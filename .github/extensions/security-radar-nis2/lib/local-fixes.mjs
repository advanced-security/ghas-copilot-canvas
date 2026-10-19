export function localFixHandoff({ canvasId, instanceId, id, requestId, title, prompt }) {
	return [
		"Coordinate a canvas remediation in a NEW dedicated Copilot App session. Do not implement it in this conversation.",
		"Use create_session for the current project with workspace_type \"worktree\", execution_location \"local\", coordinate_with_creator false, and kickoff { mode: \"autopilot\", prompt: the complete task below }.",
		"Leave base_branch and model overrides unset. Name the session after the finding.",
		"Do not edit files, run implementation commands, switch branches, commit, or push in this session. Do not use task, fork_session, or a branch workspace as a substitute.",
		"Keep the user in this session with the canvas open: do not call navigate_to.",
		"Use get_session to verify the new session has its own worktree, not the parent checkout, before recording its launch.",
		"After creation, use the actual session ID and app_url returned by the tools (list_sessions_and_chats if needed). Never construct a URL.",
		`Record the launch using invoke_canvas_action with instanceId ${JSON.stringify(instanceId)}, actionName "record_fix_session", and input { id: ${JSON.stringify(id)}, requestId: ${JSON.stringify(requestId)}, sessionId: <actual session ID>, appUrl: <actual app_url> }.`,
		`Canvas: ${canvasId}. Finding: ${title}.`,
		"If creation fails, report the error; do not retry automatically and never fall back to editing here.",
		"Task for the new session (pass it verbatim as kickoff.prompt):",
		"---",
		"You own this remediation in your isolated worktree. The parent session is only a canvas coordinator.",
		"Stay on your session's branch; do not switch back to main or change the parent's checkout.",
		prompt,
		"Do not commit, push, or open a PR unless the user explicitly requested that action. A local fix button alone is not consent to publish.",
		"---",
	].join("\n");
}

export function createLocalFixLauncher({ records, parentSessionId, send, persist, broadcast, log, schedule = setTimeout, cancel = clearTimeout }) {
	const timers = new Map();
	let saving = Promise.resolve();
	async function changed() {
		const write = saving.then(persist);
		saving = write.catch(() => {});
		await write;
		broadcast();
	}
	return {
		async acknowledgeAbsent({ id, requestId, confirm }) {
			const record = records[id];
			if (confirm !== true || !record || record.requestId !== requestId || record.status !== "unknown") {
				throw new Error("Explicitly confirm that you inspected the session list and no dedicated fix session was created for this request.");
			}
			delete records[id];
			try {
				await changed();
			} catch (error) {
				records[id] = record;
				broadcast();
				throw error;
			}
			if (timers.has(id)) cancel(timers.get(id));
			timers.delete(id);
			return { id, released: true };
		},
		async reset() {
			if (Object.values(records).some((record) => record.status === "launching")) {
				throw new Error("Wait for the dedicated session launch to finish before resetting.");
			}
			const previous = { ...records };
			for (const id of Object.keys(records)) {
				if (records[id].status !== "unknown") delete records[id];
			}
			try {
				await changed();
			} catch (error) {
				Object.assign(records, previous);
				broadcast();
				throw error;
			}
			for (const timer of timers.values()) cancel(timer);
			timers.clear();
		},
		async launch(job) {
			const previous = records[job.id];
			if (previous && previous.repo?.toLowerCase() !== job.repo?.toLowerCase()) throw new Error("A fix request for this finding belongs to another repository. Preserve its receipt and review the existing session before launching another fix.");
			if (previous && previous.status !== "failed") return previous;
			const record = {
				id: job.id, canvasId: job.canvasId, requestId: job.requestId,
				title: job.title, status: "launching", at: Date.now(), ...(job.repo ? { repo: job.repo.toLowerCase() } : {}),
			};
			records[job.id] = record;
			try {
				await changed();
			} catch (error) {
				if (previous) records[job.id] = previous;
				else delete records[job.id];
				broadcast();
				throw new Error(`Could not save the launch request: ${error.message}. No request was sent; retry after restoring storage.`);
			}
			const timer = schedule(() => {
				timers.delete(job.id);
				if (records[job.id] !== record || record.status !== "launching") return;
				record.status = "unknown";
				record.error = "Session launch not confirmed. Check the session sidebar; no fix was applied in this conversation. Do not launch a duplicate.";
				changed().catch((error) => log(`Could not save local fix status: ${error.message}`));
			}, 120_000);
			timer.unref?.();
			timers.set(job.id, timer);
			try {
				await send({ prompt: localFixHandoff(job), displayPrompt: `Create dedicated fix session: ${job.title}` });
			} catch (error) {
				if (record.status === "launched" || records[job.id] !== record) return record;
				cancel(timer);
				timers.delete(job.id);
				record.status = "unknown";
				record.error = `Could not confirm delivery to the coordinator: ${error.message}. Check the session sidebar before trying again.`;
				await changed();
				throw error;
			}
			return record;
		},
		async recordSession(canvasId, { id, requestId, sessionId, appUrl }) {
			const record = records[id];
			if (!record || record.canvasId !== canvasId || record.requestId !== requestId) {
				throw new Error("No matching local fix request.");
			}
			if (typeof sessionId !== "string" || !sessionId || typeof appUrl !== "string" || !appUrl.startsWith("ghapp://sessions/")) {
				throw new Error("Provide the actual session ID and app_url returned by the session tools.");
			}
			if (sessionId === parentSessionId) throw new Error("Implementation must use a different session from the canvas.");
			const url = new URL(appUrl);
			if (url.pathname !== `/${sessionId}` || url.search || url.hash) throw new Error("The session link does not match its ID.");
			if (record.sessionId && (record.sessionId !== sessionId || record.appUrl !== appUrl)) {
				throw new Error("This fix already has a dedicated session.");
			}
			if (timers.has(id)) cancel(timers.get(id));
			timers.delete(id);
			Object.assign(record, { status: "launched", sessionId, appUrl, error: null });
			await changed();
			return record;
		},
	};
}
