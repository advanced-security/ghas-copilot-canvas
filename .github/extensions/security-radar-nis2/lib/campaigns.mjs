import { randomUUID } from "node:crypto";

export const CAMPAIGN_LIMIT = 1000;
export const CAMPAIGN_REFRESH_MS = 5 * 60 * 1000;
const TYPES = { code: "code-scanning", secrets: "secret-scanning" };

export function scheduleCampaignProgress(service, { canRefresh, onError, schedule = setInterval, cancel = clearInterval }) {
	const timer = schedule(async () => {
		if (!canRefresh() || service.busy || !service.state().receipts.some((receipt) => receipt.status === "published")) return;
		try { await service.refresh(); } catch (cause) { onError(cause); }
	}, CAMPAIGN_REFRESH_MS);
	timer.unref?.();
	return () => cancel(timer);
}

export function campaignScope(groups, kind, alerts, branch) {
	if (!TYPES[kind]) throw new Error("Choose a code or secrets campaign.");
	const selected = groups.filter((group) => group.source === TYPES[kind]);
	const selectors = new Set(selected.map((group) => group.campaignSelector ?? group.rule));
	const hits = alerts.filter((alert) => {
		if (alert.state !== "open") return false;
		if (kind === "code") return selectors.has(alert.rule?.id) &&
			alert.most_recent_instance?.ref === `refs/heads/${branch}`;
		return selectors.has(alert.secret_type);
	});
	const numbers = [...new Set(hits.map((alert) => alert.number))].sort((a, b) => a - b);
	if (!numbers.length) throw new Error("No eligible open alerts remain in this selection. Code campaigns require default-branch alerts.");
	if (numbers.length > CAMPAIGN_LIMIT) throw new Error(`A campaign can include at most ${CAMPAIGN_LIMIT} alerts. Narrow the selection.`);
	if (numbers.some((number) => !Number.isSafeInteger(number) || number < 1)) throw new Error("GitHub returned an invalid alert number.");
	return {
		numbers,
		excludedGroups: groups.filter((group) => group.source !== TYPES[kind]).map(({ title, source }) => ({ title, source })),
		excludedAlerts: Math.max(0, selected.reduce((sum, group) => sum + group.count, 0) - numbers.length),
	};
}

export function campaignFields(input, now = Date.now()) {
	if (typeof input.name !== "string" || !input.name.trim() || input.name.trim().length > 50) {
		throw new Error("Campaign name must contain 1-50 characters.");
	}
	if (typeof input.description !== "string" || !input.description.trim() || input.description.trim().length > 195) {
		throw new Error("Description must contain 1-195 characters (space is reserved for the publication receipt).");
	}
	if (typeof input.dueDate !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(input.dueDate)) {
		throw new Error("Choose a valid future due date.");
	}
	const endsAt = `${input.dueDate}T23:59:59Z`;
	if (!Number.isFinite(Date.parse(endsAt)) || new Date(endsAt).toISOString().slice(0, 10) !== input.dueDate ||
		Date.parse(endsAt) <= now) throw new Error("Choose a valid future due date.");
	if (typeof input.manager !== "string" || !/^[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?$/i.test(input.manager)) {
		throw new Error("Provide one campaign manager's GitHub login (organization owner or security manager).");
	}
	return { name: input.name.trim(), description: input.description.trim(), dueDate: input.dueDate, manager: input.manager, endsAt };
}

function campaignUrl(repo, number) {
	return `https://github.com/orgs/${repo.split("/")[0]}/security/campaigns/${number}`;
}

function summary(repo, value) {
	if (!Number.isSafeInteger(value?.number) || value.number < 1) throw new Error("GitHub did not return a valid campaign receipt.");
	return {
		number: value.number, url: campaignUrl(repo, value.number),
		name: value.name ?? "", state: value.state,
		endsAt: value.ends_at, stats: value.alert_stats ?? null,
	};
}

// api, context and persistence are injected so tests cannot publish a real campaign.
export function createCampaignService({ data, context, api, list, persist, broadcast, log, now = Date.now }) {
	let busy = false;
	let error = null;
	let refreshedAt = null;
	const protectedReceipt = () => data.receipts.find((receipt) => receipt.status === "unknown" || receipt.status === "publishing");
	async function save() {
		await persist(data);
		broadcast();
	}
	async function locked(fn) {
		if (busy) throw new Error("Wait for the current campaign operation to finish.");
		busy = true;
		error = null;
		broadcast();
		try {
			return await fn();
		} catch (cause) {
			error = cause.message;
			log(`Security campaign: ${cause.message}`);
			throw cause;
		} finally {
			busy = false;
			broadcast();
		}
	}
	async function freshScope(draft, ctx) {
		if (ctx.repo !== draft.repo || ctx.repositoryId !== draft.repositoryId || ctx.branch !== draft.branch) {
			throw new Error("Repository or default branch changed. Prepare and review the campaign again.");
		}
		const path = draft.kind === "code" ? "code-scanning" : "secret-scanning";
		const ref = draft.kind === "code" ? `&ref=${encodeURIComponent(`refs/heads/${ctx.branch}`)}` : "";
		const alerts = await list(`repos/${ctx.repo}/${path}/alerts?state=open&per_page=100${ref}`);
		return campaignScope(draft.groups, draft.kind, alerts, ctx.branch);
	}
	async function loadProgress(receipt) {
		const campaign = summary(receipt.repo, await api("GET", `orgs/${receipt.repo.split("/")[0]}/campaigns/${receipt.campaign.number}`));
		if (!campaign.stats) throw new Error("GitHub has not returned campaign progress yet. Refresh progress to check again.");
		receipt.campaign = campaign;
		delete receipt.progressError;
	}
	async function publishDraft(draft, ctx) {
		if (protectedReceipt() || data.receipts.some((receipt) => receipt.id === draft.id && receipt.status === "published")) {
			throw new Error("This campaign has already been submitted. Check publication instead of retrying.");
		}
		campaignFields(draft, now());
		const fresh = await freshScope(draft, ctx);
		if (JSON.stringify(fresh.numbers) !== JSON.stringify(draft.numbers)) {
			data.draft = { ...draft, ...fresh, status: "draft", revision: randomUUID() };
			await save();
			throw new Error("The alert selection changed. Review the updated exact alert numbers before publishing.");
		}
		const marker = `[canvas:${draft.id}]`;
		const body = {
			name: draft.name, description: `${draft.description}\n${marker}`, ends_at: draft.endsAt,
			managers: [draft.manager], generate_issues: false,
			code_scanning_alerts: [{ repository_id: draft.repositoryId, alert_numbers: draft.numbers }],
		};
		const receipt = { id: draft.id, repo: draft.repo, name: draft.name, scopeLabel: draft.scopeLabel, marker, status: "publishing", at: now() };
		data.receipts.push(receipt);
		try { await save(); } catch (cause) {
			data.receipts.splice(data.receipts.indexOf(receipt), 1);
			throw new Error(`Could not save publication intent; no request sent: ${cause.message}`);
		}
		try {
			const response = await api("POST", `orgs/${ctx.repo.split("/")[0]}/campaigns`, body);
			receipt.campaign = summary(draft.repo, response);
			receipt.status = "published";
			data.draft = null;
		} catch (cause) {
			const match = String(cause.stderr ?? cause.message).match(/HTTP (\d{3})/);
			const status = match ? Number(match[1]) : null;
			receipt.status = status && status >= 400 && status < 500 && status !== 408 ? "failed" : "unknown";
			receipt.error = receipt.status === "failed" ? `GitHub rejected publication: ${cause.message}` :
				`Publication could not be confirmed: ${cause.message}. Check publication; do not retry.`;
			await save();
			throw new Error(receipt.error);
		}
		try { await save(); } catch (cause) {
			throw new Error(`Campaign #${receipt.campaign.number} was published, but its receipt could not be saved: ${cause.message}. Check publication before doing anything else.`);
		}
		try {
			await loadProgress(receipt);
			refreshedAt = new Date(now()).toISOString();
		} catch (cause) {
			receipt.progressError = `Campaign was created, but progress could not be refreshed: ${cause.message}`;
			error = receipt.progressError;
			log(`Security campaign #${receipt.campaign.number}: ${receipt.progressError}`);
		}
		try { await save(); } catch (cause) {
			throw new Error(`Campaign #${receipt.campaign.number} was published, but its progress could not be saved: ${cause.message}. Refresh progress to check again.`);
		}
		return receipt;
	}
	return {
		get busy() { return busy; },
		state() {
			return { ...data, busy, error, refreshedAt, publicationBlocked: Boolean(protectedReceipt()) };
		},
		async prepare(groups, kind, scopeLabel) {
			return locked(async () => {
				if (protectedReceipt()) throw new Error("An earlier publication is unconfirmed. Check publication before preparing another campaign.");
				const ctx = await context();
				if (!ctx.organization) throw new Error("Security campaigns require an organization-owned repository.");
				const groupsCopy = groups.map(({ id, source, title, rule, campaignSelector, count }) =>
					({ id, source, title, rule, campaignSelector, count }));
				const draft = {
					id: randomUUID(), revision: randomUUID(), status: "draft", kind, scopeLabel,
					repo: ctx.repo, repositoryId: ctx.repositoryId, branch: ctx.branch, groups: groupsCopy,
					name: scopeLabel.slice(0, 50), description: `Remediate ${scopeLabel} in ${ctx.repo}.`.slice(0, 195),
					dueDate: new Date(now() + 30 * 86400000).toISOString().slice(0, 10), manager: ctx.manager ?? "",
				};
				Object.assign(draft, await freshScope(draft, ctx));
				const previous = data.draft;
				data.draft = draft;
				try { await save(); } catch (cause) { data.draft = previous; throw cause; }
				return draft;
			});
		},
		async review(input) {
			return locked(async () => {
				const draft = data.draft;
				if (!draft || draft.id !== input.id) throw new Error("This preparation is stale. Prepare the campaign again.");
				if (draft.kind !== "code") throw new Error("Finalize secret campaigns on GitHub; their public API request schema is incomplete.");
				if (protectedReceipt()) throw new Error("Check the unconfirmed publication first.");
				const fields = campaignFields(input, now());
				const reviewed = { ...draft, ...fields, status: "reviewed", revision: randomUUID() };
				data.draft = reviewed;
				try { await save(); } catch (cause) { data.draft = draft; throw cause; }
				return reviewed;
			});
		},
		async edit(input) {
			return locked(async () => {
				if (!data.draft || data.draft.id !== input.id || protectedReceipt()) throw new Error("No editable campaign preparation.");
				const previous = data.draft;
				data.draft = { ...previous, status: "draft", revision: randomUUID() };
				try { await save(); } catch (cause) { data.draft = previous; throw cause; }
				return data.draft;
			});
		},
		async publish(input) {
			return locked(async () => {
				const draft = data.draft;
				if (input.confirm !== true || !draft || draft.kind !== "code" || draft.status !== "reviewed" ||
					draft.id !== input.id || draft.revision !== input.revision) {
					throw new Error("Review the exact campaign and explicitly confirm publication first.");
				}
				return publishDraft(draft, await context());
			});
		},
		async create(input) {
			return locked(async () => {
				const draft = data.draft;
				if (input.confirm !== true || !draft || draft.kind !== "code" ||
					draft.id !== input.id || draft.revision !== input.revision) {
					throw new Error("Open the campaign form and explicitly confirm creation on GitHub.");
				}
				if (protectedReceipt()) throw new Error("Check the unconfirmed publication first.");
				const expectedIds = draft.groups.filter((group) => group.source === TYPES.code).map((group) => group.id).sort();
				if (!Array.isArray(input.ids) || input.ids.some((id) => typeof id !== "string") ||
					JSON.stringify([...input.ids].sort()) !== JSON.stringify(expectedIds)) {
					throw new Error("The selected groups changed. Update the prepared scope before creating the campaign.");
				}
				const ctx = await context();
				const fields = campaignFields({ ...input, manager: ctx.manager }, now());
				if (draft.manager && draft.manager !== fields.manager) {
					data.draft = { ...draft, manager: fields.manager, status: "draft", revision: randomUUID() };
					try { await save(); } catch (cause) { data.draft = draft; throw cause; }
					throw new Error(`The authenticated GitHub account changed to @${fields.manager}. Check the account before creating the campaign.`);
				}
				const reviewed = { ...draft, ...fields, status: "reviewed", revision: randomUUID() };
				data.draft = reviewed;
				try { await save(); } catch (cause) { data.draft = draft; throw cause; }
				return publishDraft(reviewed, ctx);
			});
		},
		async refresh() {
			return locked(async () => {
				const failures = [];
				for (const receipt of data.receipts) {
					try {
						if (receipt.status === "published") {
							await loadProgress(receipt);
						} else if (receipt.status === "unknown" || receipt.status === "publishing") {
							const campaigns = await list(`orgs/${receipt.repo.split("/")[0]}/campaigns?per_page=100`);
							const matches = campaigns.filter((campaign) => campaign.description?.endsWith(receipt.marker));
							if (matches.length === 1) {
								receipt.campaign = summary(receipt.repo, matches[0]);
								receipt.status = "published";
								delete receipt.error;
								if (data.draft?.id === receipt.id) data.draft = null;
								if (!receipt.campaign.stats) await loadProgress(receipt);
							} else if (matches.length > 1) throw new Error("Multiple campaigns match this publication receipt. Inspect them on GitHub.");
							else throw new Error("No matching campaign is visible yet. Publication remains unconfirmed; inspect GitHub before attempting another campaign.");
						}
					} catch (cause) {
						if (receipt.status === "published") receipt.progressError = cause.message;
						failures.push(cause.message);
					}
				}
				await save();
				if (failures.length) throw new Error(failures.join("\n"));
				refreshedAt = new Date(now()).toISOString();
				return this.state();
			});
		},
		async acknowledgeAbsent(input) {
			return locked(async () => {
				const receipt = data.receipts.find((item) => item.id === input.id);
				if (input.confirm !== true || receipt?.status !== "unknown" || receipt.id === "restore-error") {
					throw new Error("Explicitly confirm that you inspected GitHub and no campaign was created.");
				}
				const previous = { ...receipt };
				receipt.status = "abandoned";
				receipt.error = "User confirmed on GitHub that no campaign was created; automatic retry was not attempted.";
				try { await save(); } catch (cause) { Object.assign(receipt, previous); throw cause; }
				return receipt;
			});
		},
		async reset(afterSave = async () => {}, { forgetCampaigns = false } = {}) {
			return locked(async () => {
				const previous = data.draft;
				const previousReceipts = data.receipts;
				data.draft = null;
				if (forgetCampaigns) data.receipts = data.receipts.filter((receipt) => ["unknown", "publishing"].includes(receipt.status));
				try { await save(); } catch (cause) { data.draft = previous; data.receipts = previousReceipts; throw cause; }
				try { await afterSave(); } catch (cause) {
					data.draft = previous;
					data.receipts = previousReceipts;
					await save();
					throw cause;
				}
				if (forgetCampaigns) refreshedAt = null;
			});
		},
	};
}
