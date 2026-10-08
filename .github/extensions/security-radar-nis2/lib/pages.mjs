import { remediationProjection, escapeHtml } from "./logic.mjs";

const CSS = `
:root {
  color-scheme: dark;
  --bg: #07111a;
  --panel: rgba(10, 24, 34, .92);
  --line: #1d4454;
  --text: #e8f7f4;
  --muted: #8eb4bc;
  --red: #ff5d73;
  --blue: #3ee0ff;
  --green: #3dffb0;
  --amber: #ffc14a;
  --violet: #c9a6ff;
}
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; }
body {
  background:
    radial-gradient(900px 420px at 0% -10%, rgba(62,224,255,.18), transparent 55%),
    radial-gradient(700px 420px at 100% 0%, rgba(255,93,115,.14), transparent 50%),
    var(--bg);
  background-repeat: no-repeat;
  color: var(--text);
  font-family: var(--font-sans, "Segoe UI", sans-serif);
  font-size: 14px;
  line-height: 1.4;
}
button, input { font: inherit; color: inherit; }
button {
  border: 1px solid var(--line);
  background: #102733;
  border-radius: 999px;
  padding: 8px 14px;
  cursor: pointer;
}
button.primary { background: #123f46; border-color: #1f7c86; color: var(--blue); }
button.danger { background: #3a1720; border-color: #8a3144; color: var(--red); }
button.good { background: #12382c; border-color: #1f8a62; color: var(--green); }
button:disabled { opacity: .45; cursor: default; }
#app { min-height: 100%; padding: 22px; display: flex; flex-direction: column; gap: 16px; }
header.top { display: flex; justify-content: space-between; gap: 16px; align-items: flex-end; }
.kicker { letter-spacing: .16em; text-transform: uppercase; color: var(--blue); font-size: 11px; }
h1 { margin: 4px 0 0; font-size: 32px; line-height: 1.05; font-weight: 650; }
.sub { color: var(--muted); max-width: 680px; margin: 6px 0 0; }
.row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.pill { border: 1px solid var(--line); border-radius: 999px; padding: 4px 10px; color: var(--muted); }
.pill b { color: var(--text); }
.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 18px;
  padding: 14px;
  min-height: 220px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.panel h2 { margin: 0; font-size: 16px; }
.radar-wrap {
  --scope: clamp(300px, min(42vw, calc(100vh - 330px)), 680px);
  display: grid; grid-template-columns: var(--scope) minmax(340px, 1fr); gap: clamp(24px, 3.4vw, 56px); align-items: start;
}
.scope-col { display: flex; flex-direction: column; gap: 10px; min-width: 0; align-items: center; }
.scope { position: relative; width: var(--scope); aspect-ratio: 1; border-radius: 50%; background: radial-gradient(circle, #0c2430 0%, #071018 72%); border: 1px solid #1c5360; overflow: hidden; }
.radar-svg { position: absolute; inset: 0; width: 100%; height: 100%; pointer-events: none; display: block; }
.halo {
  position: absolute; inset: 0; border-radius: 50%; pointer-events: none; z-index: 1;
  transform-origin: 50% 50%;
  /* Symmetric about the beam line so the light never leans to one side. */
  background: conic-gradient(from 0deg at 50% 50%,
    rgba(186,248,255,.48) 0deg,
    rgba(62,224,255,.3) 5deg,
    rgba(62,224,255,.15) 14deg,
    rgba(62,224,255,.06) 28deg,
    rgba(62,224,255,.015) 44deg,
    rgba(62,224,255,0) 56deg,
    rgba(62,224,255,0) 304deg,
    rgba(62,224,255,.015) 316deg,
    rgba(62,224,255,.06) 332deg,
    rgba(62,224,255,.15) 346deg,
    rgba(62,224,255,.3) 355deg,
    rgba(186,248,255,.48) 360deg);
  -webkit-mask: radial-gradient(circle at 50% 50%, transparent 0 3%, #000 10%);
  mask: radial-gradient(circle at 50% 50%, transparent 0 3%, #000 10%);
  animation: radar-spin 9s linear infinite;
}
@keyframes radar-spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .halo { animation: none; } }
.ring-stroke { fill: none; stroke: #1d5360; stroke-width: .4; stroke-dasharray: 1.15 1.05; }
.ring-stroke.hot { stroke: #3ee0ff; stroke-opacity: .7; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 12px; color: var(--muted); font-size: 12px; }
.swatch { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 5px; vertical-align: 0; }
.blip {
  position: absolute; width: 14px; height: 14px; border-radius: 50%; border: 0; padding: 0;
  transform: translate(-50%, -50%);
  transform-origin: center;
  box-shadow: 0 0 10px currentColor;
  z-index: 2;
}
.blip span {
  position: absolute; left: calc(100% + 4px); top: 50%; transform: translateY(-50%); pointer-events: none;
  font: 500 10px/1 var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace); color: rgba(214,232,240,.72); text-shadow: 0 0 4px #04121a;
}
.blip.on span { color: #fff; left: calc(100% + 17px); font-weight: 600; }
.blip.code-scanning { background: var(--red); color: var(--red); }
.blip.dependabot { background: var(--amber); color: var(--amber); }
.blip.secret-scanning { background: var(--violet); color: var(--violet); }
.blip.on { z-index: 4; box-shadow: 0 0 0 2px #04121a, 0 0 0 3.5px #fff, 0 0 16px 4px currentColor; }
.blip.on::before, .blip.on::after { content: ""; position: absolute; pointer-events: none; }
.blip.on::before {
  inset: -14px;
  background:
    linear-gradient(#fff, #fff) left top / 7px 1.5px no-repeat, linear-gradient(#fff, #fff) left top / 1.5px 7px no-repeat,
    linear-gradient(#fff, #fff) right top / 7px 1.5px no-repeat, linear-gradient(#fff, #fff) right top / 1.5px 7px no-repeat,
    linear-gradient(#fff, #fff) left bottom / 7px 1.5px no-repeat, linear-gradient(#fff, #fff) left bottom / 1.5px 7px no-repeat,
    linear-gradient(#fff, #fff) right bottom / 7px 1.5px no-repeat, linear-gradient(#fff, #fff) right bottom / 1.5px 7px no-repeat;
  filter: drop-shadow(0 0 3px rgba(0,0,0,.8));
}
.blip.on::after { inset: -4px; border-radius: 50%; border: 1.5px solid currentColor; animation: lock-pulse 1.8s ease-out infinite; }
@keyframes lock-pulse { from { transform: scale(1); opacity: .9; } to { transform: scale(2.6); opacity: 0; } }
@media (prefers-reduced-motion: reduce) { .blip.on::after { animation: none; opacity: .6; transform: scale(1.6); } }
.blip.dim, .file.dim { opacity: .28; }
.blip.contained { background: var(--green); color: var(--green); }
.top .row button { white-space: nowrap; }
.top .row { align-items: center; flex-wrap: nowrap; flex-shrink: 0; }
.refresh { display: inline-grid !important; place-items: center; }
.refresh > span { grid-area: 1 / 1; }
.refresh > span.off { visibility: hidden; }
.top .row > .src, .top .row > button { height: 38px; display: inline-flex; align-items: center; }
.src { gap: 7px; font-size: 11px; font-weight: 600; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); border: 1px solid var(--line); border-radius: 999px; padding: 0 14px; white-space: nowrap; }
.src i { width: 7px; height: 7px; border-radius: 50%; background: #5d7480; }
.src.live { color: #9ff5c8; border-color: #1f6b4a; background: rgba(28,120,80,.14); }
.src.live i { background: #3ddc97; box-shadow: 0 0 0 0 rgba(61,220,151,.6); animation: live-dot 2s infinite; }
.src.cache i { background: #ffc14a; }
.panel.empty-state { align-items: flex-start; gap: 8px; }
.panel.empty-state h2 { margin: 0; font-size: 20px; }
.panel.empty-state p { margin: 0; color: var(--muted); }
@keyframes live-dot { 0% { box-shadow: 0 0 0 0 rgba(61,220,151,.55); } 70% { box-shadow: 0 0 0 7px rgba(61,220,151,0); } 100% { box-shadow: 0 0 0 0 rgba(61,220,151,0); } }
@media (prefers-reduced-motion: reduce) { .src.live i { animation: none; } }
.scope .blip { transition: opacity .35s, filter .35s; }
.scope.syncing .blip { opacity: .28; filter: saturate(.3); }
.scope.syncing::after { content: "Syncing with GitHub…"; position: absolute; left: 50%; bottom: 7%; transform: translateX(-50%); font: 600 11px/1 var(--font-sans, sans-serif); letter-spacing: .14em; text-transform: uppercase; color: #9fe9f5; background: rgba(4,18,26,.8); border: 1px solid #1f6f7c; border-radius: 999px; padding: 7px 12px; z-index: 5; animation: sync-blink 1.2s ease-in-out infinite alternate; }
@keyframes sync-blink { from { opacity: .55; } to { opacity: 1; } }
.blip.arrive { animation: blip-in 820ms cubic-bezier(.16,.84,.24,1) both; }
@keyframes blip-in {
  0% { left: 50%; top: 50%; opacity: 0; transform: translate(-50%, -50%) scale(.2); }
  35% { opacity: 1; }
  80% { transform: translate(-50%, -50%) scale(1.35); }
  100% { transform: translate(-50%, -50%) scale(1); }
}
@media (prefers-reduced-motion: reduce) { .blip.arrive { animation: none; } .scope.syncing::after { animation: none; } }
.kpis {
  display: grid; grid-template-columns: 1.15fr 1fr 1fr 1fr 1fr 1.35fr; border: 1px solid var(--line); border-radius: 12px;
  background: rgba(9,22,31,.72); overflow: hidden;
}
@media (max-width: 1180px) { .kpis { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
@media (max-width: 560px) { .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.kpi {
  position: relative; text-align: left; padding: 14px 18px 13px; min-width: 0; display: flex; flex-direction: column; gap: 6px;
  border: 0; border-right: 1px solid var(--line); border-radius: 0; background: transparent; color: var(--text); font: inherit;
}
.kpi:last-child { border-right: 0; }
@media (max-width: 1180px) {
  .kpis .kpi { border-bottom: 1px solid var(--line); }
  .kpis .kpi:nth-child(3n) { border-right: 0; }
  .kpis .kpi:nth-last-child(-n+3) { border-bottom: 0; }
}
@media (max-width: 560px) {
  .kpis .kpi:nth-child(3n) { border-right: 1px solid var(--line); }
  .kpis .kpi:nth-child(2n) { border-right: 0; }
  .kpis .kpi:nth-last-child(-n+3) { border-bottom: 1px solid var(--line); }
  .kpis .kpi:nth-last-child(-n+2) { border-bottom: 0; }
}
.kpi-label { display: flex; align-items: baseline; gap: 8px; font-size: 11px; font-weight: 500; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); white-space: nowrap; }
.kpi-value { display: flex; align-items: baseline; gap: 6px; font-size: 26px; line-height: 1; font-weight: 600; color: #f2f7fa; font-variant-numeric: tabular-nums; letter-spacing: -.01em; }
.kpi-value em { font-style: normal; font-size: 13px; font-weight: 500; color: var(--muted); letter-spacing: 0; }
.kpi-sub { color: var(--muted); font-size: 12px; line-height: 1.35; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.kpi-sub b { color: #c9d6dd; font-weight: 500; font-variant-numeric: tabular-nums; }
button.kpi { cursor: pointer; transition: background .15s; }
button.kpi:hover { background: rgba(62,224,255,.05); }
button.kpi:hover .kpi-go { color: var(--text); }
.kpi-go { margin-left: auto; color: var(--muted); font-size: 12px; font-weight: 500; letter-spacing: 0; text-transform: none; }
.kpi-title { font-size: 15px; line-height: 26px; font-weight: 600; color: #f2f7fa; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.kpi .sev-dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; margin-right: 6px; vertical-align: 1px; }
.sevbar { display: flex; height: 4px; border-radius: 2px; overflow: hidden; background: #102733; gap: 1px; }
.sevbar i { display: block; height: 100%; opacity: .85; }
.detail {
  height: max(calc(var(--scope) + 30px), 560px); padding: 0; gap: 0; overflow: hidden;
}
.d-head { padding: 13px 18px 12px; border-bottom: 1px solid #163848; display: flex; flex-direction: column; gap: 6px; }
.d-head h2 { margin: 0; font-size: 18px; line-height: 1.2; }
.d-head .summary { font-size: 13px; line-height: 1.4; }
.chips { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
.chip { font-size: 11px; letter-spacing: .06em; text-transform: uppercase; padding: 3px 8px; border-radius: 999px; border: 1px solid var(--line); color: var(--muted); }
.chip.sev-critical { color: #fff; background: #b4233c; border-color: #ff5d73; }
.chip.sev-high { color: #ffd9a0; background: #4a2e0c; border-color: #a86c1c; }
.chip.sev-medium { color: #bff4ff; background: #0f3a47; border-color: #1f7c86; }
.loc { margin: 0; color: var(--muted); font-family: var(--font-mono, ui-monospace, monospace); font-size: 12px; word-break: break-all; }
.summary { margin: 0; color: #cfe6e3; }
.actions { margin-top: 2px; }
button.ghost { background: transparent; }
.thread { flex: 1; min-height: 0; overflow-y: auto; padding: 14px 18px; display: flex; flex-direction: column; gap: 10px; scroll-behavior: smooth; }
.thread::-webkit-scrollbar { width: 8px; }
.thread::-webkit-scrollbar-thumb { background: #1d4454; border-radius: 99px; }
.empty { margin: auto; text-align: center; color: var(--muted); max-width: 340px; }
.starter { display: flex; flex-direction: column; gap: 10px; }
.starter p { margin: 0; color: var(--muted); font-size: 13px; }
.starter-list { display: flex; flex-wrap: wrap; gap: 8px; }
button.suggest { font-size: 13px; padding: 6px 12px; border-radius: 999px; background: #0b2230; border-color: #1d4454; color: #cfe6e3; }
button.suggest:hover:not(:disabled) { border-color: #2c8fa0; color: #fff; }
.toast { position: fixed; left: 50%; bottom: 18px; transform: translateX(-50%); z-index: 50; max-width: 520px; padding: 9px 16px; border-radius: 10px; background: #3a1018; border: 1px solid #b4233c; color: #ffd6dc; font-size: 13px; box-shadow: 0 8px 24px rgba(0,0,0,.4); }
.empty p { margin: 4px 0; }
.empty strong { color: var(--text); }
.spark { color: var(--blue); }
.empty .spark { font-size: 26px; display: block; margin-bottom: 6px; }
.q { align-self: flex-end; max-width: 85%; background: #123f46; border: 1px solid #1f7c86; color: #dffaff; padding: 7px 12px; border-radius: 14px 14px 4px 14px; }
.a { align-self: stretch; background: #07141c; border: 1px solid #163848; border-radius: 4px 14px 14px 14px; padding: 10px 14px; }
.a.offline { border-style: dashed; }
.a-head { display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; color: var(--blue); margin-bottom: 4px; }
.a-tag { margin-left: auto; font-weight: 400; font-size: 11px; color: var(--muted); letter-spacing: .04em; }
.a-body p { margin: 0 0 6px; }
.pv { margin-top: 8px; padding-top: 6px; border-top: 1px dashed var(--line); }
.pv-btn { all: unset; cursor: pointer; font-size: 11px; color: var(--muted); letter-spacing: .03em; }
.pv-btn:hover, .pv-btn:focus-visible { color: var(--blue); text-decoration: underline; }
.pv-ctx { margin: 6px 0 0; font-size: 11px; color: var(--muted); }
.pv-text { margin: 6px 0 0; max-height: 220px; overflow: auto; padding: 8px 10px; border: 1px solid var(--line); border-radius: 8px; background: #071219;
  font-family: var(--font-mono, ui-monospace, monospace); font-size: 11px; line-height: 1.5; color: #c9dbe2; white-space: pre-wrap; word-break: break-word; }
.a-body p:last-child { margin-bottom: 0; }
.a-body ul, .a-body ol { margin: 2px 0 0; padding-left: 20px; display: flex; flex-direction: column; gap: 4px; }
.a-body code { font-family: var(--font-mono, ui-monospace, monospace); font-size: 12px; background: #102733; padding: 1px 5px; border-radius: 6px; }
.a-note { color: var(--muted); font-size: 13px; }
.dots { display: inline-flex; gap: 3px; margin-left: 4px; }
.dots i { width: 5px; height: 5px; border-radius: 50%; background: var(--blue); animation: blink 1.2s infinite ease-in-out; }
.dots i:nth-child(2) { animation-delay: .15s; }
.dots i:nth-child(3) { animation-delay: .3s; }
@keyframes blink { 0%, 80%, 100% { opacity: .2; } 40% { opacity: 1; } }
.composer { display: flex; flex-direction: column; gap: 10px; padding: 12px 14px; border-top: 1px solid #163848; background: rgba(6,16,24,.6); }
.quick { display: flex; flex-wrap: wrap; gap: 6px; }
.quick button.suggest { font-size: 12.5px; padding: 5px 11px; }
.quick button.suggest.key { background: #123f46; border-color: #1f7c86; color: var(--blue); }
.quick button.suggest.ghost { background: transparent; color: var(--muted); }
.quick a.suggest.assigned { display: inline-flex; align-items: center; font-size: 12.5px; padding: 5px 11px; border-radius: 999px; border: 1px solid #1f8a5c; background: #0f3a2a; color: #3dffb0; text-decoration: none; }
.a-body a { color: var(--blue); }
.d-head .chips { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; }
.d-head .gh-link { margin-left: auto; font-size: 12px; color: var(--blue); text-decoration: none; border: 1px solid var(--line, #24424a); border-radius: 999px; padding: 3px 10px; }
.d-head .gh-link:hover { text-decoration: underline; }
.ask-row { display: flex; gap: 8px; }
.composer input {
  flex: 1; min-width: 0; background: #061018; border: 1px solid var(--line); border-radius: 999px; padding: 9px 14px; outline: none;
}
.composer input:focus { border-color: #1f7c86; box-shadow: 0 0 0 3px rgba(62,224,255,.12); }
.status { margin: 0; font-size: 12px; color: var(--muted); }
.section-title { margin: 6px 0 0; font-size: 12px; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
.radar-findings > summary { padding: 12px; border: 1px solid var(--line); border-radius: 10px; background: var(--panel); }
.radar-findings-content { display: grid; gap: 10px; margin-top: 10px; }
.file.sel { border-color: #2c8fa0; box-shadow: inset 0 0 0 1px rgba(62,224,255,.35); }
.file .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; vertical-align: 1px; }
.meta { color: var(--muted); font-family: var(--font-mono, ui-monospace, monospace); font-size: 12px; word-break: break-word; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: 8px; }
.file {
  text-align: left; border-radius: 14px; padding: 10px; background: #0d2030; border: 1px solid var(--line); width: 100%;
}
.file small { display: block; color: var(--muted); }
.file.hit { border-color: var(--green); }
.c-hero { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 8px 18px; align-items: center; padding: 12px 18px; border: 1px solid var(--line); border-radius: 16px; background: rgba(9,22,31,.72); }
.gauge { width: 118px; height: 118px; border-radius: 50%; position: relative; display: grid; place-items: center;
  background: conic-gradient(var(--gc) calc(var(--p) * 1%), rgba(61,255,176,.38) 0 calc(var(--q) * 1%), #102733 0); }
.gauge::before { content: ""; position: absolute; inset: 9px; border-radius: 50%; background: #081620; box-shadow: inset 0 0 0 1px #163848; }
.gauge > div { position: relative; text-align: center; display: flex; flex-direction: column; align-items: center; gap: 2px; }
.gauge b { font-size: 34px; line-height: 1; font-weight: 650; font-variant-numeric: tabular-nums; }
.gauge small { color: var(--muted); font-size: 11px; letter-spacing: .08em; text-transform: uppercase; }
.gauge .to { color: var(--green); font-size: 13px; font-weight: 650; letter-spacing: 0; text-transform: none; margin-top: 2px; line-height: 1.2; }
.gauge .to em { display: block; font-style: normal; font-size: 10.5px; font-weight: 500; opacity: .85; }
.c-stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }
.c-stats .kpi { border-right: 1px solid var(--line); }
.c-stats .kpi:last-child { border-right: 0; }
.c-stats .kpi-title { font-size: 15px; line-height: 26px; }
.c-stats .kpi-sub, .c-stats .kpi-title { white-space: normal; overflow: visible; }
.c-stats .kpi-title { line-height: 20px; margin: 3px 0 4px; }
.c-how { grid-column: 1 / -1; padding-top: 12px; border-top: 1px dashed var(--line); color: var(--muted); font-size: 12px; }
.c-how > div { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 8px; padding-top: 8px; }
details > summary { cursor: pointer; color: var(--muted); }
details > summary:focus-visible { outline: 2px solid var(--color-focus-outline, var(--blue)); outline-offset: 3px; }
.c-scenario { grid-column: 1 / -1; display: flex; flex-wrap: wrap; gap: 6px 12px; align-items: center; color: var(--muted); font-size: 12px; }
.c-scenario strong { color: var(--green); }
.c-scenario .stripe-key { display: inline-block; width: 22px; height: 7px; margin-right: 6px; border-radius: 3px; background: repeating-linear-gradient(45deg, rgba(61,255,176,.7) 0 4px, rgba(61,255,176,.3) 4px 8px); }
.c-journey { grid-column: 1 / -1; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; color: var(--muted); font-size: 12px; }
.c-journey b { color: var(--text); }
.c-journey button { margin-left: auto; font-size: 12px; padding: 4px 10px; }
.c-how { padding-top: 8px; }
.campaign-lift.on { background: rgba(61,255,176,.08); box-shadow: inset 0 0 0 1px #1f8a62; }
.c-how strong { color: #dbe7ec; font-weight: 600; margin-right: 4px; }
.c-how span { padding: 2px 8px; border: 1px solid var(--line); border-radius: 999px; background: rgba(8,22,32,.6); white-space: nowrap; }
.c-how span b { color: var(--red); font-weight: 600; font-variant-numeric: tabular-nums; margin-left: 4px; }
.c-how em { font-style: normal; opacity: .8; }
button.kpi.lift { background: linear-gradient(160deg, rgba(61,255,176,.10), rgba(4,18,26,0) 70%); }
button.kpi.lift.on { background: linear-gradient(160deg, rgba(61,255,176,.20), rgba(4,18,26,0) 80%); box-shadow: inset 0 0 0 1px #1f8a62; }
.kpi-value .up, .ctl-score .up { color: var(--green); }
.pop { display: inline-block; animation: pop .6s cubic-bezier(.2,1.6,.4,1) both; }
@keyframes pop { from { transform: scale(.4); opacity: 0; } }
.c-main { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.3fr); gap: 14px; align-items: start; }
.c-list { display: flex; flex-direction: column; gap: 6px; }
button.ctl { text-align: left; width: 100%; border-radius: 14px; padding: 6px 12px; background: #0c1c27; display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 4px 10px; align-items: start; }
button.ctl:hover { border-color: #2c8fa0; }
button.ctl.sel { border-color: #2c8fa0; background: #0e2433; box-shadow: inset 3px 0 0 var(--blue); }
.ctl-t { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.ctl-t strong { font-size: 14px; }
.fw { color: var(--muted); font-size: 11.5px; line-height: 1.35; }
.ctl-score { font-size: 22px; line-height: 1; font-weight: 650; font-variant-numeric: tabular-nums; white-space: nowrap; }
.ctl-score em { font-style: normal; font-size: 12px; color: var(--muted); font-weight: 500; margin-left: 2px; }
.ctl-score .up { font-size: 13px; margin-left: 4px; }
.cbar { grid-column: 1 / -1; display: flex; height: 5px; background: #102733; border-radius: 99px; overflow: hidden; }
.cbar i { display: block; height: 100%; }
.cbar i.ghost { background: repeating-linear-gradient(45deg, rgba(61,255,176,.7) 0 4px, rgba(61,255,176,.3) 4px 8px); transform-origin: left; }
.cbar i.ghost.grow { animation: ghost-in .8s cubic-bezier(.16,.84,.24,1) both; }
@keyframes ghost-in { from { transform: scaleX(0); } }
.ctl-meta { grid-column: 1 / -1; display: flex; gap: 10px; flex-wrap: wrap; font-size: 11.5px; line-height: 1.3; color: var(--muted); }
.ctl-meta .gap { color: #ffb3bf; }
@media (prefers-reduced-motion: reduce) { .pop, .cbar i.ghost.grow { animation: none; } }
.c-detail { padding: 0; gap: 0; overflow: hidden; }
.c-detail .d-head { padding: 14px 18px 12px; }
.c-detail .d-score, .c-detail .d-head .note { margin: 0; }
.chip.ref { text-transform: none; letter-spacing: 0; color: #bff4ff; border-color: #1f6f7c; background: rgba(62,224,255,.06); }
.chip.ref.dora { color: #e0ccff; border-color: #5b4a86; background: rgba(201,166,255,.06); }
.d-score { color: var(--muted); font-size: 13px; }
.d-score b { font-size: 16px; color: var(--text); font-variant-numeric: tabular-nums; }
.d-score b.g { color: var(--green); }
.c-facts { display: grid; grid-template-columns: minmax(0, 1fr); gap: 14px; padding: 12px 18px 14px; border-bottom: 1px solid #163848; }
.c-evidence .ev { margin-top: 10px; }
.c-guidance { border-top: 1px solid #163848; }
.c-guidance > summary { padding: 12px 18px; font-size: 13px; }
.c-guidance .composer { border-top: 0; }
.c-guidance-tools { display: flex; gap: 6px; flex-wrap: wrap; padding: 10px 18px; border-top: 1px solid #163848; }
.c-dependency-plan, .c-response-evidence { padding: 12px 18px; border-bottom: 1px solid #163848; }
.c-dependency-plan h3, .c-response-evidence h3 { margin: 0; font-size: 14px; }
.c-plan-tools { display: flex; flex-wrap: wrap; gap: 6px; margin: 10px 0; }
.c-plan-tools button { font-size: 12px; padding: 6px 10px; }
.c-dependency-plan .flist { margin-top: 8px; }
.c-dependency-plan .note, .c-response-evidence .note { margin: 6px 0; }
.c-response-evidence .ev { margin: 12px 0; }
.c-response-evidence .score-rationale { padding: 8px 10px; border: 1px solid var(--line); border-radius: 8px; }
.c-code-scope { border-bottom: 1px solid #163848; }
.c-code-scope > summary { padding: 10px 18px; font-size: 12px; }
.c-code-scope .radar-campaign-section { margin: 0 18px 12px; }
.c-tracking > summary { padding: 10px 0; }
.c-tracking .campaign-area { margin: 0; }
.ctl-type { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
.c-facts h4, .clock h4 { margin: 0 0 6px; font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
.flist { display: flex; flex-direction: column; gap: 2px; }
a.fr { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; gap: 8px; align-items: baseline; min-width: 0; padding: 5px 0; border-radius: 8px; color: inherit; text-decoration: none; }
.fr-item:hover, .fr-item:focus-within { background: rgba(62,224,255,.06); border-color: #2c8fa0; }
.fr-item:hover .fr-t, .fr-item:focus-within .fr-t { color: #fff; }
a.fr:hover .fr-t { text-decoration: underline; text-decoration-color: #2c8fa0; }
a.fr:focus-visible { outline: 2px solid var(--color-focus-outline, var(--blue)); outline-offset: 3px; }
.fr .sev-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.fr-t { font-size: 13px; min-width: 0; }
.fr-t small { display: block; color: var(--muted); font-family: var(--font-mono, ui-monospace, monospace); font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.fr-n { font-size: 12px; color: var(--muted); font-variant-numeric: tabular-nums; }
.fr-item { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: center; padding: 8px; border: 1px solid transparent; border-radius: 10px; transition: background .15s, border-color .15s; }
.fr-item.selected { border-color: #1f8a62; background: rgba(61,255,176,.06); }
.fr-item.selected:hover, .fr-item.selected:focus-within { background: rgba(61,255,176,.12); border-color: #3dffb0; }
.fr-item .fr-actions { align-self: stretch; }
.fr-item .suggest { font-size: 12px; }
.fr-item a.assigned { display: inline-block; color: var(--green); text-decoration: none; }
.fr-actions { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.fr-actions .status { margin: 0; }
.ev { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; font-size: 13px; }
.ev li { display: flex; gap: 8px; align-items: baseline; }
.ev i { font-style: normal; font-weight: 700; width: 14px; text-align: center; flex-shrink: 0; }
.ev .ok i { color: var(--green); }
.ev .no { color: #ffd6dc; }
.ev .no i { color: var(--red); }
.ev .na { color: var(--muted); }
.ev .ev-src { display: inline-block; margin-left: 6px; padding: 0 6px; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); font-size: 10.5px; letter-spacing: .02em; vertical-align: 1px; }
.clock { grid-column: 1 / -1; }
.clock ol { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
.clock li { position: relative; padding: 9px 11px; border-radius: 10px; border: 1px solid #5a2f3a; background: linear-gradient(160deg, rgba(255,93,115,.10), rgba(4,18,26,0) 75%); display: flex; flex-direction: column; gap: 2px; }
.clock li b { color: #ff98a8; font-size: 16px; }
.clock li span { font-size: 13px; font-weight: 600; }
.clock li small { color: var(--muted); font-size: 11.5px; line-height: 1.35; }
.clock .note { margin: 6px 0 0; }
.c-detail .thread { min-height: 150px; max-height: 340px; }
.c-brief { border: 1px solid #1f6b4a; border-radius: 16px; background: linear-gradient(160deg, rgba(61,255,176,.07), rgba(4,18,26,0) 60%), rgba(9,22,31,.72); padding: 14px 16px; display: flex; flex-direction: column; gap: 12px; }
.c-brief-head { display: flex; align-items: center; gap: 10px; }
.c-brief-head h3 { margin: 0; font-size: 15px; }
.c-brief-head .note { margin-left: auto; }
.c-brief-head .stale { color: var(--amber, #f5b84a); font-weight: 600; }
.c-cards { display: grid; grid-template-columns: 1.1fr 1fr 1fr .9fr; gap: 10px; }
.c-card { border: 1px solid #163848; border-radius: 12px; padding: 11px 13px; background: #07141c; font-size: 13px; }
.c-card h4 { margin: 0 0 6px; font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
.c-card p { margin: 0; }
.c-card ul { margin: 0; padding-left: 18px; display: flex; flex-direction: column; gap: 4px; }
.c-card .big { font-size: 22px; font-weight: 650; }
.c-card .big .g { color: var(--green); }
button.small { padding: 4px 10px; font-size: 12px; }
.c-foot { display: flex; flex-direction: column; gap: 2px; }
@media (max-width: 1100px) {
  .c-cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 900px) {
  .c-main { grid-template-columns: 1fr; }
}
@media (max-width: 640px) {
  .c-hero { grid-template-columns: 1fr; justify-items: center; padding: 14px; }
  .c-stats { width: 100%; }
  .c-stats .kpi { padding: 10px; }
  .c-stats .kpi-label { white-space: normal; }
  .c-facts { grid-template-columns: 1fr; }
  .clock ol { grid-template-columns: 1fr; }
  .c-cards { grid-template-columns: 1fr; }
  .top .row > button { flex: 1; }
}
.note { color: var(--muted); font-size: 12px; }
footer.note { margin-top: auto; }
@media (max-width: 800px) {
  .radar-wrap { grid-template-columns: 1fr; }
  .radar-wrap { --scope: min(86vw, 520px); }
  .scope-col { align-items: center; }
  h1 { font-size: 26px; }
}
@media (max-width: 640px) {
  #app { padding: 16px 14px; }
  header.top { flex-direction: column; align-items: stretch; gap: 12px; }
  .top .row { flex-wrap: wrap; }
  .top .row > .refresh { flex: 1; }
  .detail { height: auto; min-height: 520px; }
}
@media (max-width: 500px) {
  .scope .blip { max-width: 22px; max-height: 22px; }
}
.a-body pre.code { margin: 4px 0 6px; padding: 8px 10px; border-radius: 8px; background: #061018; border: 1px solid #163848; overflow-x: auto; font-family: var(--font-mono, ui-monospace, monospace); font-size: 12px; line-height: 1.5; white-space: pre; }
`;

const CLIENT_HEAD = `
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[c]));
let state = JSON.parse(document.getElementById("boot").textContent);
let selectedId = null;
let fileFilter = null;
const campaignSelection = new Set(state.campaigns && state.campaigns.draft && state.findings
  ? state.campaigns.draft.groups.filter((g) => g.source === (state.campaigns.draft.kind === "code" ? "code-scanning" : "secret-scanning") &&
    state.findings.some((f) => f.id === g.id)).map((g) => g.id) : []);
const themeSelections = {};
const dependencySelections = {};
const planModes = {};
function dependencySelection(controlId) {
  return dependencySelections[controlId] ||= new Set();
}
function themeSelection(controlId) {
  if (!themeSelections[controlId]) {
    const draft = state.campaigns && state.campaigns.draft;
    const theme = (state.controls || []).find((c) => c.id === controlId);
    const groups = (state.campaignThemes && state.campaignThemes[controlId]) || [];
    themeSelections[controlId] = new Set(draft && draft.scopeLabel === theme?.title
      ? draft.groups.filter((g) => groups.some((f) => f.id === g.id)).map((g) => g.id) : []);
  }
  return themeSelections[controlId];
}
function campaignGroups(controlId) {
  return controlId ? (state.campaignThemes && state.campaignThemes[controlId]) || [] : state.findings || [];
}
const openPrompts = {};
let lastError = "";
let errorTimer = null;
const root = document.getElementById("app");
function inline(text) {
  const tick = String.fromCharCode(96);
  return esc(text).split("**").map((part, i) => {
    const coded = part.split(tick).map((bit, j) => (j % 2 ? "<code>" + bit + "</code>" : bit)).join("")
      .replace(/\\[([^\\]]+)\\]\\((https:\\/\\/github\\.com\\/[^)\\s"]+)\\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    return i % 2 ? "<strong>" + coded + "</strong>" : coded;
  }).join("");
}
function promptHtml(item) {
  if (!item.prompt) return "";
  const open = openPrompts[item.id];
  return '<div class="pv"><button class="pv-btn" data-act="toggle_prompt" data-id="' + esc(item.id) + '">' + (open ? "Hide prompt" : "View prompt") + "</button>" +
    (open ? (item.context ? '<p class="pv-ctx">' + esc(item.context) + "</p>" : "") + '<pre class="pv-text">' + esc(item.prompt) + "</pre>" : "") + "</div>";
}
function localFixHtml(record) {
  if (!record) return "";
  if (record.status === "launched") return '<p class="status"><a class="suggest key" href="' + esc(record.appUrl) + '">Open dedicated fix session ↗</a> Implementation runs in its own worktree; this checkout is unchanged.</p>';
  if (record.status === "launching") return '<p class="status">Creating a dedicated fix session… This canvas stays open.</p>';
  return '<p class="status" role="alert">' + esc(record.error || "Session launch could not be confirmed. Check the session sidebar.") + "</p>";
}
function resetButton(s) {
  return '<button class="ghost" data-act="reset_demo"' + (s.resetBlocked ? " disabled" : "") +
    ' title="Reset answers, local campaign preparation, known campaign tracking and local session links across both security canvases. Existing sessions, real GitHub assignments and campaigns on GitHub are preserved.">' +
    (s.resetting ? "Resetting…" : "Reset") + "</button>";
}
function srcClass(s) { return s.source === "github" ? "live" : s.source === "cache" ? "cache" : "none"; }
function srcLabel(s) { return s.source === "github" ? "Live" : s.source === "cache" ? "Cached" : "Not synced"; }
function srcNote(s) {
  const when = esc((s.totals && s.totals.asOf) || "");
  return s.source === "github" ? "Live from GitHub, synced " + when + "." : s.source === "cache" ? "Last GitHub sync " + when + "." : "Not synced yet.";
}
function refreshButton(s) {
  return '<button class="refresh" data-act="refresh"' + (s.refreshing ? " disabled" : "") + '><span' + (s.refreshing ? ' class="off"' : "") +
    '>' + (s.source === "none" ? "Sync from GitHub" : "Refresh from GitHub") + '</span><span' + (s.refreshing ? "" : ' class="off" aria-hidden="true"') + ">Syncing…</span></button>";
}
function emptyState(s, kicker, title) {
  const problem = s.repoError || s.refreshError;
  return '<header class="top"><div><div class="kicker">' + esc(kicker) + "</div><h1>" + esc(title) + '</h1><p class="sub">' + (s.repo ? esc(s.repo) + " · " : "") +
    'Not synced yet.</p></div><div class="row"><span class="src none"><i></i>Not synced</span>' + (s.repoError ? "" : refreshButton(s)) + resetButton(s) + "</div></header>" +
    '<section class="panel empty-state"><h2>' + (s.refreshing ? "Syncing from GitHub…" : "No data yet — Sync from GitHub") + "</h2>" +
    "<p>" + (s.repo ? "Open code scanning, Dependabot and secret scanning alerts for " + esc(s.repo) + " load here." : "Open code scanning, Dependabot and secret scanning alerts for the repository of this session load here.") +
    " Secret values are never loaded.</p>" + (problem && !s.refreshing ? '<p class="status" role="alert">' + esc(problem) + "</p>" : "") +
    "</section>" + (s.disclaimer ? '<footer class="note">' + esc(s.disclaimer) + "</footer>" : "");
}
function campaignHtml(s, direct = false) {
  const c = s.campaigns;
  if (!c) return "";
  const disabled = c.busy || s.refreshing ? " disabled" : "";
  const d = c.draft;
  let draft = "";
  if (d) {
    const prefix = "campaign-" + d.id + "-";
    const field = (key, label, max, type) => '<label>' + label + '<input id="' + esc(prefix + key) + '" type="' + (type || "text") +
      '"' + (max ? ' maxlength="' + max + '"' : "") + ' value="' + esc(d[key] || "") + '"' + disabled + " /></label>";
    const numbers = d.numbers.map((number) => '<a href="https://github.com/' + esc(d.repo) + '/security/' +
      (d.kind === "code" ? "code-scanning" : "secret-scanning") + '/' + number + '" target="_blank" rel="noopener">#' + number + "</a>").join(" ");
    const excluded = d.excludedGroups.length ? d.excludedGroups.map((g) => g.title + " (" + g.source + ")").join(", ") : "none";
    let actions;
    if (d.kind === "secrets") {
      actions = '<p class="status">Secrets campaigns are in public preview. The documented REST creation schema is incomplete; finalize this preparation in GitHub. No campaign has been created here, and secret values are never loaded.</p>' +
        '<a class="suggest key" href="https://github.com/orgs/' + esc(d.repo.split("/")[0]) + '/security/campaigns" target="_blank" rel="noopener">Open GitHub campaigns ↗</a>';
    } else if (direct) {
      actions = '<div class="campaign-fields">' + field("name", "Campaign name", 50) +
        (s.controls ? field("dueDate", "Due date (UTC)", null, "date") + field("description", "Description", 195) :
          field("description", "Description", 195) + field("dueDate", "Due date (UTC)", null, "date")) +
        '</div><div class="campaign-context" aria-label="Included alerts">' +
        '<span>' + d.numbers.length + ' alert' + (d.numbers.length === 1 ? '' : 's') + ' included:</span> ' + numbers + '</div>' +
        (d.excludedAlerts || d.excludedGroups.length ? '<p class="note">' + d.excludedAlerts +
          ' alerts excluded by eligibility checks. Excluded groups: ' + esc(excluded) + '.</p>' : '');
    } else if (d.status === "reviewed") {
      actions = '<p><b>' + esc(d.name) + '</b> · due ' + esc(d.dueDate) + ' · manager @' + esc(d.manager) +
        '</p><p>' + esc(d.description) + '</p><p class="status">Publishing creates a real organization campaign, not a draft. GitHub notifies developers and queues Autofix suggestions. No repository issues will be generated. The posture score does not change.</p>' +
        '<label class="campaign-confirm"><input type="checkbox" data-campaign-confirm /> I approve publishing this exact campaign on GitHub.</label>' +
        '<div class="quick"><button class="primary" data-act="publish_campaign" data-id="' + esc(d.id) + '" data-revision="' + esc(d.revision) +
        '" disabled>Publish on GitHub</button><button class="ghost" data-act="edit_campaign" data-id="' + esc(d.id) + '"' + disabled +
        '>Edit details</button></div>';
    } else {
      actions = '<div class="campaign-fields">' + field("name", "Campaign name", 50) + field("description", "Description", 195) +
        field("dueDate", "Due date (UTC)", null, "date") + field("manager", "Manager GitHub login", 39) +
        '</div><p class="note">Manager must be an organization owner or security manager. Preparation is local, not a GitHub draft.</p>' +
        '<button class="primary" data-act="review_campaign" data-id="' + esc(d.id) + '" data-prefix="' + esc(prefix) + '"' + disabled + ">Review publication</button>";
    }
    draft = direct ? '<section class="radar-campaign-form" aria-label="Campaign details">' +
      (d.kind === "secrets" ? '<details><summary>' + d.numbers.length + ' secret alerts included</summary><div class="campaign-numbers">' +
        numbers + '</div></details>' : '') + actions + '</section>' :
      '<section class="panel campaign-review"><div class="row"><h3>' + (d.status === "reviewed" ? "Review before publication" : "Local campaign preparation") +
      '</h3><button class="ghost" data-act="discard_campaign"' + disabled + '>Discard preparation</button></div><p>' + esc(d.scopeLabel) +
      ' · <b>' + d.numbers.length + '</b> exact ' + (d.kind === "code" ? "default-branch code" : "secret") + ' alerts · ' + esc(d.repo) +
      '</p><p class="note">Selected groups: ' + esc(d.groups.filter((g) => g.source === (d.kind === "code" ? "code-scanning" : "secret-scanning")).map((g) => g.title).join(", ")) +
      '</p><details><summary>Review exact alert numbers (' + d.numbers.length + ')</summary><div class="campaign-numbers">' + numbers +
      '</div></details><p class="note">Excluded groups: ' + esc(excluded) + ". " + d.excludedAlerts + " alerts excluded by current eligibility/default-branch checks.</p>" + actions + "</section>";
  }
  const refreshed = c.refreshedAt ? '<time class="campaign-last-refresh" datetime="' + esc(c.refreshedAt) +
    '" title="' + esc(c.refreshedAt) + '">Last refresh: ' + esc(new Date(c.refreshedAt).toLocaleString(undefined, {
      day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit",
    })) + '</time>' : "";
  const firstPublished = c.receipts.find((r) => r.status === "published");
  const receipts = c.receipts.filter((r) => !["failed", "abandoned"].includes(r.status)).map((r) => {
    if (r.status !== "published") return '<div class="campaign-receipt"><b>' + esc(r.name || "Unconfirmed publication") +
      '</b><p class="status" role="alert">' + esc(r.error || "Publishing…") + '</p><p class="note">No automatic retry. ' +
      (direct ? 'Use Refresh from GitHub to check publication against the saved receipt.' : 'Check publication to reconcile the saved receipt.') +
      ' Reset preserves it.</p>' +
      '<a href="https://github.com/orgs/' + esc(r.repo.split("/")[0]) + '/security/campaigns" target="_blank" rel="noopener">Inspect on GitHub ↗</a>' +
      (r.status === "unknown" && r.id !== "restore-error" ? '<label class="campaign-confirm"><input type="checkbox" data-campaign-absent="' + esc(r.id) +
        '" /> I checked GitHub: no campaign was created.</label><button class="ghost" data-act="acknowledge_campaign_absent" data-id="' + esc(r.id) +
        '" disabled>Release unconfirmed receipt</button>' : "") + '</div>';
    const x = r.campaign;
    const stats = x.stats;
    return '<div class="campaign-receipt"><div class="campaign-receipt-head"><a href="' + esc(x.url) + '" target="_blank" rel="noopener"><b>' + esc(x.name || r.name) +
      ' · #' + x.number + '</b> ↗</a>' + (direct && r.id === firstPublished?.id ? refreshed : '') +
      '</div><p>' + (s.controls && r.scopeLabel ? esc(r.scopeLabel) + ' · ' : '') + esc(x.state || "published") + " · due " + esc(x.endsAt || "") + '</p><p>' +
      (stats ? stats.closed_count + " alerts closed · " + stats.open_count + " open · " + stats.in_progress_count + " in progress" :
        c.busy ? "Fetching progress…" : "Progress pending from GitHub") + "</p>" +
      (r.progressError ? '<p class="status" role="alert">' + esc(r.progressError) + '</p>' : '') + "</div>";
  }).join("");
  if (!draft && !c.error && !receipts) return "";
  return '<section class="campaign-area">' + draft + (c.error ? '<p class="status" role="alert">' + esc(c.error) + "</p>" : "") +
    (receipts ? '<section class="' + (direct ? "" : "panel ") + 'campaign-tracking" aria-label="Created campaigns">' +
      (direct ? '' : '<div class="campaign-tracking-head"><h3>Campaigns submitted from this session</h3>' +
      '<div class="campaign-tracking-actions">' + refreshed + '<button class="ghost" data-act="refresh_campaigns"' +
      disabled + '>' + (c.publicationBlocked ? "Check publication" : "Refresh progress") + '</button></div></div>') +
      receipts + "</section>" : "") + "</section>";
}
function md(text) {
  const out = [];
  let list = [];
  let tag = "ul";
  let code = null;
  const fence = String.fromCharCode(96).repeat(3);
  const flush = () => { if (list.length) { out.push("<" + tag + ">" + list.join("") + "</" + tag + ">"); list = []; } };
  const close = () => { out.push('<pre class="code"><code>' + esc(code.join("\\n")) + "</code></pre>"); code = null; };
  String(text || "").split("\\n").forEach((raw) => {
    const line = raw.trim();
    if (line.startsWith(fence)) {
      if (code) close();
      else { flush(); code = []; }
      return;
    }
    if (code) { code.push(raw.replace(/\\s+$/, "")); return; }
    if (!line) { flush(); return; }
    const bullet = line.match(/^([-*•]|\\d+[.)])\\s+(.*)$/);
    if (bullet) {
      const kind = /\\d/.test(bullet[1]) ? "ol" : "ul";
      if (list.length && kind !== tag) flush();
      tag = kind;
      list.push("<li>" + inline(bullet[2]) + "</li>");
      return;
    }
    flush();
    out.push("<p>" + inline(line.replace(/^#+\\s*/, "")) + "</p>");
  });
  if (code) close();
  flush();
  return out.join("");
}
function showError(message) {
  lastError = message;
  clearTimeout(errorTimer);
  errorTimer = setTimeout(() => { lastError = ""; draw(); }, 5000);
  draw();
}
function draw() {
  const active = document.activeElement;
  const focusId = active && active.id && root.contains && root.contains(active) ? active.id : null;
  const kept = {};
  root.querySelectorAll("input[id]").forEach((el) => {
    kept[el.id] = { value: el.value, start: el.selectionStart, end: el.selectionEnd };
  });
  const scrolls = {};
  const disclosures = {};
  root.querySelectorAll("details[data-disclosure]").forEach((el) => { disclosures[el.dataset.disclosure] = el.open; });
  root.querySelectorAll("[data-scroll]").forEach((el) => {
    scrolls[el.dataset.scroll] = { top: el.scrollTop, sig: el.dataset.sig };
  });
  root.innerHTML = view(state) + (lastError ? '<div class="toast" role="alert">' + esc(lastError) + "</div>" : "");
  root.querySelectorAll("details[data-disclosure]").forEach((el) => {
    if (Object.hasOwn(disclosures, el.dataset.disclosure)) el.open = disclosures[el.dataset.disclosure];
  });
  Object.keys(kept).forEach((id) => {
    const el = document.getElementById(id);
    if (el && "value" in el) el.value = kept[id].value;
  });
  if (focusId) {
    const el = document.getElementById(focusId);
    if (el && el.focus) {
      el.focus();
      if (kept[focusId] && kept[focusId].start != null && el.setSelectionRange) el.setSelectionRange(kept[focusId].start, kept[focusId].end);
    }
  }
  root.querySelectorAll("[data-scroll]").forEach((el) => {
    const prev = scrolls[el.dataset.scroll];
    el.style.scrollBehavior = "auto";
    el.scrollTop = prev && prev.sig === el.dataset.sig ? prev.top : el.scrollHeight;
    el.style.scrollBehavior = "";
  });
  root.querySelectorAll("input[data-enter]").forEach((el) => {
    el.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" || event.isComposing) return;
      event.preventDefault();
      const target = document.getElementById(el.dataset.enter);
      if (target && !target.disabled) target.click();
    });
  });
  root.querySelectorAll("[data-act]").forEach((el) => {
    el.addEventListener("click", async () => {
      if (el.dataset.act === "select") {
        selectedId = el.dataset.id;
        draw();
        const detail = el.classList.contains("ctl") || el.classList.contains("kpi") ? root.querySelector(".c-detail") : null;
        if (detail && typeof window !== "undefined" && window.innerWidth <= 900) detail.scrollIntoView({ behavior: "smooth", block: "start" });
        return;
      }
      if (el.dataset.act === "toggle_prompt") {
        openPrompts[el.dataset.id] = !openPrompts[el.dataset.id];
        draw();
        return;
      }
      if (el.dataset.act === "same_file") {
        fileFilter = fileFilter === el.dataset.id ? null : el.dataset.id;
        draw();
        return;
      }
      if (el.dataset.act === "toggle_campaign_selection") {
        const selection = el.dataset.control ? themeSelection(el.dataset.control) : campaignSelection;
        const finding = campaignGroups(el.dataset.control).find((f) => f.id === el.dataset.id);
        if (!state.campaigns || state.campaigns.busy || state.refreshing || !finding ||
            !["code-scanning", "secret-scanning"].includes(finding.source)) return;
        if (selection.has(finding.id)) selection.delete(finding.id);
        else selection.add(finding.id);
        if (el.dataset.control) planModes[el.dataset.control] = "campaign";
        draw();
        return;
      }
      if (el.dataset.act === "select_campaign_theme") {
        if (state.campaigns.busy || state.refreshing) return;
        const selection = themeSelection(el.dataset.control);
        campaignGroups(el.dataset.control).filter((f) => ["code-scanning", "secret-scanning"].includes(f.source)).forEach((f) => selection.add(f.id));
        planModes[el.dataset.control] = "campaign";
        draw();
        return;
      }
      if (["toggle_dependency_selection", "select_dependency_theme", "clear_dependency_selection", "show_dependency_preview", "show_campaign_preview"].includes(el.dataset.act)) {
        if (state.refreshing) return;
        const controlId = el.dataset.control;
        const selection = dependencySelection(controlId);
        const dependencies = campaignGroups(controlId).filter((f) => f.source === "dependabot");
        if (el.dataset.act === "toggle_dependency_selection") {
          if (!dependencies.some((f) => f.id === el.dataset.id)) return;
          if (selection.has(el.dataset.id)) selection.delete(el.dataset.id);
          else selection.add(el.dataset.id);
        } else if (el.dataset.act === "select_dependency_theme") {
          dependencies.forEach((f) => selection.add(f.id));
        } else if (el.dataset.act === "clear_dependency_selection") selection.clear();
        planModes[controlId] = el.dataset.act === "show_campaign_preview" ? "campaign" : "dependencies";
        draw();
        return;
      }
      if (el.dataset.act === "clear_campaign_selection") {
        if (state.campaigns.busy || state.refreshing) return;
        if (!state.campaigns.draft) {
          (el.dataset.control ? themeSelection(el.dataset.control) : campaignSelection).clear();
          draw();
          return;
        }
      }
      const input = el.dataset.id ? { id: el.dataset.id } : {};
      if (el.dataset.control) input.controlId = el.dataset.control;
      if (el.dataset.act === "draft_dependency_plan") {
        input.ids = [...dependencySelection(input.controlId)].filter((id) =>
          campaignGroups(input.controlId).some((f) => f.id === id && f.source === "dependabot"));
        if (!input.ids.length || state.pending || state.refreshing) return;
      }
      if (["draft_dependency_plan", "draft_evidence", "draft_plan", "draft_board", "ask_auditor"].includes(el.dataset.act)) {
        const guidance = root.querySelector('[data-disclosure="guidance-' + (input.controlId || input.id) + '"]');
        if (guidance) guidance.open = true;
      }
      if (el.dataset.act === "prepare_campaign") {
        input.kind = el.dataset.kind;
        input.ids = [...(input.controlId ? themeSelection(input.controlId) : campaignSelection)].filter((id) =>
          campaignGroups(input.controlId).some((f) => f.id === id && f.source === (input.kind === "code" ? "code-scanning" : "secret-scanning")));
      }
      if (el.dataset.act === "review_campaign" || el.dataset.act === "create_campaign") {
        (el.dataset.act === "create_campaign" ? ["name", "description", "dueDate"] : ["name", "description", "dueDate", "manager"]).forEach((key) => {
          const field = document.getElementById(el.dataset.prefix + key);
          input[key] = field ? field.value : "";
        });
        if (el.dataset.act === "create_campaign") {
          if (state.campaigns.busy || state.refreshing || state.campaigns.publicationBlocked) return;
          input.revision = el.dataset.revision;
          input.confirm = true;
          input.ids = [...(input.controlId ? themeSelection(input.controlId) : campaignSelection)].filter((id) =>
            campaignGroups(input.controlId).some((f) => f.id === id && f.source === "code-scanning"));
          el.disabled = true;
        }
      }
      if (el.dataset.act === "publish_campaign") {
        const check = root.querySelector("[data-campaign-confirm]");
        if (!check || !check.checked) return;
        input.confirm = true;
        input.revision = el.dataset.revision;
        el.disabled = true;
      }
      if (el.dataset.act === "acknowledge_campaign_absent") {
        const check = root.querySelector('[data-campaign-absent="' + el.dataset.id + '"]');
        if (!check || !check.checked) return;
        input.confirm = true;
        el.disabled = true;
      }
      let field = null;
      let typed = "";
      if (el.dataset.q) input.question = el.dataset.q;
      if (el.dataset.input) {
        field = document.getElementById(el.dataset.input);
        typed = field ? String(field.value || "") : "";
        const question = typed.trim();
        if (!question) {
          if (field && field.focus) field.focus();
          return;
        }
        input.question = question;
        field.value = "";
      }
      try {
        const res = await fetch("/api/action", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: el.dataset.act === "clear_campaign_selection" ? "discard_campaign" : el.dataset.act, input }),
        });
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body.error || "The canvas could not run that action.");
        }
        if (el.dataset.act === "clear_campaign_selection") {
          (el.dataset.control ? themeSelection(el.dataset.control) : campaignSelection).clear();
          state = { ...state, campaigns: { ...state.campaigns, draft: null } };
          draw();
        }
      } catch (error) {
        const restore = field && document.getElementById(field.id);
        if (restore && !restore.value) restore.value = typed;
        showError(error && error.message ? error.message : "The canvas could not run that action.");
      }
    });
  });
  root.querySelectorAll("[data-campaign-confirm]").forEach((el) => {
    el.addEventListener("change", () => {
      const publish = root.querySelector('[data-act="publish_campaign"]');
      if (publish) publish.disabled = !el.checked || state.campaigns.busy || state.refreshing || state.campaigns.publicationBlocked;
    });
  });
  root.querySelectorAll("[data-campaign-absent]").forEach((el) => {
    el.addEventListener("change", () => {
      const release = root.querySelector('[data-act="acknowledge_campaign_absent"][data-id="' + el.dataset.campaignAbsent + '"]');
      if (release) release.disabled = !el.checked || state.campaigns.busy || state.refreshing;
    });
  });
  if (typeof bindRadarTooltips === "function") bindRadarTooltips(root);
}
`;

const CLIENT_TAIL = `
draw();
const events = new EventSource("/events");
events.onmessage = (event) => {
  const next = JSON.parse(event.data);
  if (next.resetEpoch !== state.resetEpoch) {
    selectedId = null;
    fileFilter = null;
    campaignSelection.clear();
    Object.keys(themeSelections).forEach((id) => { delete themeSelections[id]; });
    Object.keys(dependencySelections).forEach((id) => { delete dependencySelections[id]; });
    Object.keys(planModes).forEach((id) => { delete planModes[id]; });
    Object.keys(openPrompts).forEach((id) => { delete openPrompts[id]; });
    root.querySelectorAll("input[id]").forEach((el) => { el.value = ""; });
    lastError = "";
    clearTimeout(errorTimer);
  }
  if (next.findings) {
    const ids = new Set(next.findings.filter((f) => ["code-scanning", "secret-scanning"].includes(f.source)).map((f) => f.id));
    for (const id of campaignSelection) if (!ids.has(id)) campaignSelection.delete(id);
  }
  Object.keys(themeSelections).forEach((controlId) => {
    const ids = new Set(((next.campaignThemes && next.campaignThemes[controlId]) || []).map((f) => f.id));
    for (const id of themeSelections[controlId]) if (!ids.has(id)) themeSelections[controlId].delete(id);
  });
  Object.keys(dependencySelections).forEach((controlId) => {
    const ids = new Set(((next.campaignThemes && next.campaignThemes[controlId]) || []).filter((f) => f.source === "dependabot").map((f) => f.id));
    for (const id of dependencySelections[controlId]) if (!ids.has(id)) dependencySelections[controlId].delete(id);
  });
  state = next;
  draw();
};
`;

function shell(title, viewSource, state) {
	const boot = JSON.stringify(state).replace(/</g, "\\u003c");
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>${CSS}
  .campaign-area { margin: 18px 0; }
  .c-detail > .radar-campaign-section { margin: 14px 18px; }
  .c-detail .campaign-scope { margin: 0; padding: 0 12px 8px; }
  .c-detail .radar-campaign-bar { grid-template-columns: minmax(0, 1fr); gap: 8px; }
  .c-detail .radar-campaign-coverage { justify-self: start; }
  .c-detail .campaign-actions { justify-content: flex-start; flex-wrap: wrap; }
  .c-detail .radar-campaign-form .campaign-fields { grid-template-columns: minmax(0, 1fr); }
  @media (min-width: 600px) {
    .c-detail .radar-campaign-form .campaign-fields { grid-template-columns: minmax(0, 1fr) minmax(130px, .6fr); }
    .c-detail .campaign-fields label:nth-child(3) { grid-column: 1 / -1; }
  }
  .fr-actions .radar-campaign-toggle.compact { position: static; flex: none; }
  .campaign-review, .campaign-tracking { padding: 18px; margin: 14px 0; }
  .campaign-fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; margin: 14px 0; }
  .campaign-fields label { display: grid; gap: 6px; }
  .campaign-fields input { width: 100%; }
  .campaign-confirm { display: flex; align-items: center; gap: 8px; padding: 10px 0; }
  .campaign-confirm input { width: auto; flex: none; }
  .campaign-numbers { display: flex; flex-wrap: wrap; gap: 8px; max-height: 180px; overflow: auto; padding: 10px 0; }
  .campaign-receipt { padding: 12px 0; border-top: 1px solid var(--border-color-default, #284653); }
  .campaign-tracking-head { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 16px; }
  .campaign-tracking-head h3 { margin: 0; font-size: 15px; }
  .campaign-tracking-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; margin-left: auto; }
  .campaign-last-refresh { color: var(--muted); font-size: 12px; }
  .campaign-receipt-head { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 12px; }
  .campaign-receipt-head a { min-width: 0; overflow-wrap: anywhere; }
  .campaign-receipt-head .campaign-last-refresh { margin-left: auto; }
  .radar-finding { position: relative; min-width: 0; }
  .radar-finding .file { width: 100%; height: 100%; }
  .radar-finding.eligible .file { padding-right: 48px; }
  .radar-campaign-toggle.compact { position: absolute; top: 10px; right: 8px; width: 34px; height: 34px; padding: 0; font-size: 20px; border-radius: 8px; background: transparent; }
  .radar-campaign-toggle[aria-pressed="true"] { color: var(--blue); border-color: #398d9e; background: #14323e; }
  .panel.detail.empty-thread { height: max(calc(var(--scope) + 30px), 440px); min-height: 0; }
  .radar-discussion-placeholder { margin: auto; max-width: 44ch; text-align: center; color: var(--muted); font-size: 13px; }
  .radar-wrap .quick .radar-conversation-clear { margin-left: auto; }
  #app.radar-app { height: 100dvh; }
  #app.radar-app > .top, #app.radar-app > .kpis, #app.radar-app > .radar-findings { flex-shrink: 0; }
  #app.radar-app > .radar-wrap {
    --scope: clamp(300px, 45vw, 760px);
    flex: 1; min-height: 440px; align-items: stretch;
  }
  #app.radar-app .scope-col { justify-content: center; container-type: size; }
  #app.radar-app .scope { width: min(100%, calc(100cqh - 40px)); flex-shrink: 0; }
  #app.radar-app .panel.detail { height: auto; min-height: 0; }
  #app.radar-app > .radar-findings { position: relative; }
  /* Expanded findings extend the page without resizing the radar and chat. */
  #app.radar-app .radar-findings-content { position: absolute; top: 100%; left: 0; right: 0; padding-bottom: 22px; }
  .radar-tooltip { position: fixed; z-index: 100; max-width: min(360px, calc(100vw - 20px)); padding: 8px 12px; border: 1px solid #398d9e; border-radius: 8px; background: #14323e; color: var(--text); font-size: 12px; line-height: 1.5; box-shadow: 0 6px 18px rgba(0,0,0,.3); }
  .radar-kpis .kpi:focus-visible { outline: 2px solid var(--blue); outline-offset: -3px; }
  .radar-kpis .kpi-label { overflow: hidden; text-overflow: ellipsis; }
  .radar-campaign-toggle:focus-visible, .radar-finding .file:focus-visible { outline: 2px solid var(--blue); outline-offset: 3px; }
  .radar-finding .file.campaign-marked { border-color: #398d9e; }
  .blip.campaign-marked { outline: 2px dashed var(--blue); outline-offset: 6px; }
  .radar-campaign-section { border: 1px solid var(--line); border-radius: 10px; background: var(--panel); }
  .radar-campaign-bar { display: grid; grid-template-columns: minmax(230px, 1fr) auto auto; align-items: center; gap: 8px 14px; padding: 9px 12px; }
  .radar-campaign-bar .campaign-count { display: grid; align-content: center; min-height: 40px; font-variant-numeric: tabular-nums; }
  .radar-campaign-bar button { height: 34px; padding: 6px 11px; }
  .radar-campaign-bar .campaign-actions { display: flex; gap: 8px; align-items: center; min-height: 40px; }
  .radar-campaign-coverage { display: grid; align-content: center; min-height: 40px; font-size: 12px; color: var(--muted); }
  .radar-campaign-coverage b { color: var(--text); font-size: 16px; font-variant-numeric: tabular-nums; }
  .radar-campaign-coverage:focus-visible { outline: 2px solid var(--blue); outline-offset: 3px; }
  .radar-campaign-bar .campaign-submit { background: #17663c; border-color: #43b975; color: #f0fff5; font-weight: 600; }
  .radar-campaign-bar .campaign-submit:hover:not(:disabled) { background: #1c7a49; border-color: #75dfa0; }
  .radar-campaign-section .campaign-area { margin: 0; padding: 0 12px 12px; }
  .radar-campaign-form { padding: 8px 0 0; }
  .radar-campaign-form .campaign-fields { grid-template-columns: minmax(0, 1.1fr) minmax(0, 1.8fr) minmax(160px, .75fr); margin: 0; }
  .radar-campaign-form .campaign-fields label { min-width: 0; font-size: 12px; }
  .radar-campaign-form input { min-height: 36px; padding: 7px 10px; border: 1px solid var(--line); border-radius: 6px; background: #061018; color: var(--text); font: inherit; font-size: 13px; }
  .radar-campaign-form input:focus-visible { outline: 2px solid var(--blue); outline-offset: 2px; }
  .campaign-context { display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px 8px; max-height: 96px; overflow: auto; margin-top: 8px; font-size: 12px; color: var(--muted); }
  .campaign-context a { white-space: nowrap; }
  .radar-campaign-section .campaign-tracking { margin: 12px 0 0; padding: 12px 0 0; border-top: 1px solid var(--line); }
  .radar-campaign-section .campaign-tracking:first-child { margin-top: 0; }
  .radar-campaign-section .campaign-tracking > .campaign-receipt:first-child { margin-top: 0; padding-top: 0; border-top: 0; }
  .radar-campaign-section .campaign-receipt { margin-top: 10px; padding: 10px 0 0; }
  .radar-campaign-section .campaign-receipt p { margin: 4px 0 0; font-size: 13px; line-height: 1.4; }
  @media (max-width: 1100px) {
    .radar-campaign-bar { grid-template-columns: minmax(0, 1fr) auto; }
    .radar-campaign-bar .campaign-count { grid-column: 1; grid-row: 1; }
    .radar-campaign-coverage { grid-column: 2; grid-row: 1; }
    .radar-campaign-bar .campaign-actions { grid-column: 1 / -1; grid-row: 2; }
  }
  @media (max-width: 640px) {
    .radar-campaign-form .campaign-fields { grid-template-columns: minmax(0, 1fr); gap: 10px; }
    .radar-campaign-bar .campaign-count { grid-column: 1 / -1; }
    .radar-campaign-coverage { grid-column: 1 / -1; grid-row: 2; }
    .radar-campaign-bar .campaign-actions { grid-column: 1 / -1; grid-row: 3; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); min-height: 48px; }
    .radar-campaign-bar .campaign-actions button { height: 48px; padding: 6px 8px; font-size: 12px; }
  }
  @media (max-width: 800px) {
    #app.radar-app { height: auto; min-height: 100dvh; }
    #app.radar-app > .radar-wrap { --scope: min(86vw, 520px); flex: none; min-height: 0; }
    #app.radar-app .scope-col { container-type: normal; }
    #app.radar-app .scope { width: var(--scope); }
    #app.radar-app .panel.detail { min-height: 400px; }
    #app.radar-app .radar-findings-content { position: static; padding-bottom: 0; }
    .radar-wrap .panel.detail { height: auto; min-height: 400px; }
    .radar-kpis .kpi-sub, .radar-kpis .kpi-title, .radar-kpis .kpi-label { white-space: normal; overflow: visible; overflow-wrap: anywhere; }
  }
  @media (max-width: 500px) { .radar-wrap .quick button.suggest { font-size: 12px; padding: 6px 8px; } }
  @media (pointer: coarse) { .radar-campaign-toggle.compact { width: 44px; height: 44px; top: 4px; right: 4px; } .radar-finding.eligible .file { padding-right: 54px; } }
  </style>
</head>
<body>
  <div id="app"${title === "attack-surface-radar" ? ' class="radar-app"' : ""}></div>
  ${title === "attack-surface-radar" ? '<div id="radar-tooltip" class="radar-tooltip" role="tooltip" hidden></div>' : ""}
  <script id="boot" type="application/json">${boot}</script>
  <script>${CLIENT_HEAD}\n${viewSource}\n${CLIENT_TAIL}</script>
</body>
</html>`;
}

const VIEWS = {};

const RADAR_START = `
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const SEV_COLOR = { critical: "#ff5d73", high: "#ffc14a", medium: "#3ee0ff", low: "#8eb4bc" };
const SRC_LABEL = { "code-scanning": "Code scanning", dependabot: "Dependabot", "secret-scanning": "Secret scanning" };
const SRC_COLOR = { "code-scanning": "#ff5d73", dependabot: "#ffc14a", "secret-scanning": "#c9a6ff" };
const SWEEP_MS = 9000;
const radarMotion = { seed: undefined, arrive: null };
const radarTooltipState = { owner: null, timer: null };
function bindRadarTooltips(root) {
  const tip = document.getElementById("radar-tooltip");
  if (!tip || !tip.style) return;
  const hide = () => {
    clearTimeout(radarTooltipState.timer);
    tip.hidden = true;
    if (radarTooltipState.owner) radarTooltipState.owner.removeAttribute("aria-describedby");
    radarTooltipState.owner = null;
  };
  hide();
  const delayHide = () => {
    if (document.activeElement !== radarTooltipState.owner) radarTooltipState.timer = setTimeout(hide, 120);
  };
  tip.onmouseenter = () => clearTimeout(radarTooltipState.timer);
  tip.onmouseleave = delayHide;
  root.querySelectorAll("[data-tooltip]").forEach((el) => {
    const show = () => {
      hide();
      radarTooltipState.owner = el;
      tip.textContent = el.dataset.tooltip;
      tip.hidden = false;
      tip.style.left = "10px";
      tip.style.top = "10px";
      el.setAttribute("aria-describedby", "radar-tooltip");
      const anchor = el.getBoundingClientRect();
      const box = tip.getBoundingClientRect();
      tip.style.left = Math.max(10, Math.min(anchor.left, window.innerWidth - box.width - 10)) + "px";
      tip.style.top = Math.max(10, anchor.bottom + box.height + 16 <= window.innerHeight
        ? anchor.bottom + 6 : anchor.top - box.height - 6) + "px";
    };
    el.addEventListener("mouseenter", show);
    el.addEventListener("mouseleave", delayHide);
    el.addEventListener("focus", show);
    el.addEventListener("blur", hide);
    el.addEventListener("keydown", (event) => { if (event.key === "Escape") hide(); });
  });
}
`;

const CAMPAIGN_CLIENT = `
function plural(count, word) { return count + " " + word + (count === 1 ? "" : "s"); }
function campaignEligible(finding) { return ["code-scanning", "secret-scanning"].includes(finding.source); }
function radarCampaignToggle(finding, s, controlId) {
  if (!s.campaigns || !campaignEligible(finding)) return "";
  const included = (controlId ? themeSelection(controlId) : campaignSelection).has(finding.id);
  const action = included ? "Remove from campaign" : "Add to campaign";
  const label = action + ": " + finding.title + " (" + plural(finding.count, "alert") + ")";
  return '<button class="radar-campaign-toggle compact" id="campaign-card-' +
    esc(finding.id) + '" data-act="toggle_campaign_selection" data-id="' +
    esc(finding.id) + '"' + (controlId ? ' data-control="' + esc(controlId) + '"' : '') + ' aria-pressed="' + included + '" aria-label="' + esc(label) + '"' +
    (controlId ? ' title="' + esc(label) + '"' : '') + (s.campaigns.busy || s.refreshing ? " disabled" : "") + '><span aria-hidden="true">' + (included ? "✓" : "+") + '</span>' +
    "</button>";
}
function radarCampaignBar(s, controlId) {
  if (!s.campaigns) return "";
  const selection = controlId ? themeSelection(controlId) : campaignSelection;
  const attrs = controlId ? ' data-control="' + esc(controlId) + '"' : '';
  const chosen = s.findings.filter((f) => campaignEligible(f) && selection.has(f.id));
  const count = chosen.reduce((sum, f) => sum + f.count, 0);
  const eligible = s.findings.filter(campaignEligible).reduce((sum, f) => sum + f.count, 0);
  const coverage = eligible ? Math.round(count / eligible * 1000) / 10 : 0;
  const scopeHint = plural(count, "alert") + " selected out of " + eligible +
    " campaign-eligible alerts (code scanning and secret scanning).";
  const disabled = s.campaigns.busy || s.refreshing || s.campaigns.publicationBlocked || s.source !== "github";
  const kinds = [["code", "code-scanning"], ["secrets", "secret-scanning"]].filter((pair) => chosen.some((f) => f.source === pair[1]));
  const draft = s.campaigns.draft;
  const codeSelection = chosen.filter((f) => f.source === "code-scanning").map((f) => f.id).sort();
  const ready = draft && draft.kind === "code" && (!controlId || draft.scopeLabel === s.controls.find((c) => c.id === controlId)?.title) &&
    JSON.stringify(draft.groups.filter((f) => f.source === "code-scanning").map((f) => f.id).sort()) === JSON.stringify(codeSelection);
  const prepare = kinds.map((pair) => {
    if (pair[0] === "code" && ready) return '<button class="primary campaign-submit" data-act="create_campaign" data-id="' + esc(draft.id) +
      '" data-revision="' + esc(draft.revision) + '" data-prefix="' + esc("campaign-" + draft.id + "-") +
      '"' + attrs + ' aria-description="Creates a real GitHub campaign for the included alerts, notifies developers and queues Autofix."' +
      (disabled ? " disabled" : "") + '>Create on GitHub</button>';
    return '<button class="primary" data-act="prepare_campaign" data-kind="' + pair[0] + '"' + attrs +
      (disabled ? " disabled" : "") + '>' + (pair[0] === "secrets" ? "Set up secrets" : draft?.kind === "code" ?
        "Update scope" : kinds.length > 1 ? "Prepare code" : "Prepare campaign") + '</button>';
  }).join("");
  return '<section class="radar-campaign-section" aria-label="Security campaigns"><div class="radar-campaign-bar"><span class="campaign-count" role="status"><b>Security campaigns</b>' + (chosen.length
    ? '<span>' + esc(plural(chosen.length, "group")) + ' · ' + esc(plural(count, "alert")) + ' selected</span>'
    : '<span class="note">' + (eligible ? 'Add alerts to prepare a campaign.' : 'No campaign-eligible alerts.') + '</span>') + '</span>' + (chosen.length
    ? '<div class="radar-campaign-coverage" role="status" tabindex="0" data-tooltip="' + esc(scopeHint) + '"' +
      (controlId ? ' title="' + esc(scopeHint) + '"' : '') + ' aria-label="' +
      esc(coverage + "% selected. " + scopeHint) + '"><span><b>' + coverage + '%</b> selected</span></div>'
    : '<span class="radar-campaign-coverage" aria-hidden="true"></span>') + '<div class="campaign-actions">' +
    (controlId && eligible ? '<button class="ghost" data-act="select_campaign_theme"' + attrs + (s.campaigns.busy || s.refreshing ? " disabled" : "") + '>Select theme</button>' : '') +
    (chosen.length || draft ? '<button class="ghost" data-act="clear_campaign_selection"' + attrs + (s.campaigns.busy || s.refreshing ? " disabled" : "") + '>Clear selection</button>' + prepare : "") +
    '</div></div>' + (controlId && draft ? '<p class="campaign-scope note">Prepared scope: ' + esc(draft.scopeLabel) + '</p>' : '') +
    campaignHtml(controlId ? { ...s, campaigns: { ...s.campaigns, receipts: [] } } : s, true) + '</section>';
}
`;

const RADAR_REST = `
function ringName(severity) {
  if (severity === "critical") return "inner ring";
  if (severity === "high") return "middle ring";
  if (severity === "low") return "outer edge";
  return "outer ring";
}
function kpiHtml(s, critical) {
  const k = s.kpis;
  if (!k) return "";
  const bar = ["critical", "high", "medium", "low"].filter((sev) => k.bySeverity[sev]).map((sev) =>
    '<i style="width:' + ((k.bySeverity[sev] / k.mapped) * 100).toFixed(2) + "%;background:" + SEV_COLOR[sev] + '" title="' + esc(SEV_LABEL[sev] + " " + k.bySeverity[sev]) + '"></i>'
  ).join("");
  const cell = (label, value, sub, extra) =>
    '<div class="kpi"' + (["Open alerts", "Critical & high"].includes(label) ? "" : ' tabindex="0" data-tooltip="' +
      esc(label + ": " + value.replace(/<[^>]*>/g, " ") + " · " + sub) + '"') +
    '><span class="kpi-label">' + esc(label) + '</span><div class="kpi-value">' + value + "</div>" + (extra || "") + '<div class="kpi-sub">' + esc(sub) + "</div></div>";
  const priority = critical
    ? '<button class="kpi" data-act="select" data-id="' + esc(critical.id) + '" data-tooltip="' +
      esc("Top priority: " + critical.title + " · " + SEV_LABEL[critical.severity] + " · " + critical.path + (critical.line ? ":" + critical.line : "")) +
      '"><span class="kpi-label">Top priority<span class="kpi-go">View →</span></span><div class="kpi-title">' +
      esc(critical.title) + '</div><div class="kpi-sub"><i class="sev-dot" style="background:' + SEV_COLOR[critical.severity] + '"></i>' +
      esc(SEV_LABEL[critical.severity]) + " · " + esc(critical.path.split("/").pop() + (critical.line ? ":" + critical.line : "")) + "</div></button>"
    : "";
  return '<div class="kpis radar-kpis">' +
    cell("Open alerts", String(k.open), s.totals.codeScanning + " code · " + s.totals.dependabot + " deps · " + s.totals.secretScanning + " secrets", '<div class="sevbar">' + bar + "</div>") +
    cell("Critical & high", k.criticalHigh + "<em>" + k.criticalHighPct + "%</em>", "of mapped alerts") +
    cell("Open secret alerts", String(k.secrets), "Rotate · values never loaded") +
    cell("Supply chain", k.supplyChainPct + "%", "of alerts from dependencies") +
    cell("Quick wins", String(k.quickWinAlerts), k.quickWinBumps + " upgrades may fix these") +
    priority + "</div>";
}
function threadHtml(selected, s) {
  const items = (s.threads && s.threads[selected.id]) || [];
  if (!items.length) {
    return '<p class="radar-discussion-placeholder">' +
      (selected.source === "secret-scanning" ? "Ask Copilot about this alert or how to respond." : "Ask Copilot about this alert or request a fix.") + '</p>';
  }
  return items.map((item) => {
    const q = '<div class="q">' + esc(item.question) + "</div>";
    if (item.status === "pending") {
      return q + '<div class="a pending"><div class="a-head"><span class="spark">✦</span> Copilot' + (item.kind === "change" ? '<span class="a-tag">editing in a branch</span>' : "") +
        '<span class="dots"><i></i><i></i><i></i></span></div><div class="a-note">' + esc(item.note || "Thinking…") + "</div>" + promptHtml(item) + "</div>";
    }
    return q + '<div class="a' + (item.offline ? " offline" : "") + '"><div class="a-head"><span class="spark">✦</span> Copilot<span class="a-tag">' +
      (item.offline ? (item.kind === "assign" ? "GitHub API error" : item.kind === "assess" ? "assessment unavailable" : "offline brief") : item.kind === "assign" ? "GitHub API · Copilot Autofix" : item.kind === "assess" ? "AI priority · advisory" : item.kind === "change" ? "changed code in a branch" : "grounded in this repo") + '</span></div><div class="a-body">' + md(item.answer) + "</div>" + promptHtml(item) + "</div>";
  }).join("");
}
function view(s) {
  if (s.source === "none") return emptyState(s, "GitHub Advanced Security", "Attack surface radar");
  const selected = s.findings.find((finding) => finding.id === selectedId) || s.findings[0];
  const critical = s.findings.find((finding) => finding.severity === "critical");
  const alertCount = s.findings.reduce((sum, finding) => sum + (finding.count || 0), 0);
  const busy = Boolean(s.pending);
  const off = busy ? " disabled" : "";
  // Replay the arrival from the center on first paint and whenever a sync produced a new layout.
  const now = typeof performance !== "undefined" ? performance.now() : 0;
  if (!s.refreshing && s.layoutSeed !== radarMotion.seed) {
    radarMotion.seed = s.layoutSeed;
    radarMotion.arrive = now;
  }
  const since = radarMotion.arrive == null ? Infinity : now - radarMotion.arrive;
  const blips = s.findings.map((finding) => {
    const size = Math.min(28, Math.round(10 + 3.2 * Math.sqrt(finding.count || 1)));
    const bearing = ((((finding.angle || 0) + Math.PI / 2) / (Math.PI * 2)) % 1 + 1) % 1;
    const delay = Math.round(bearing * 900 - since);
    const arrive = !s.refreshing && delay > -820;
    return '<button class="blip ' + esc(finding.source) + (finding.contained ? " contained" : "") + (arrive ? " arrive" : "") +
      (campaignSelection.has(finding.id) ? " campaign-marked" : "") +
      (selected && selected.id === finding.id ? " on" : "") + '" style="left:' + finding.x + "%;top:" +
      finding.y + "%;width:" + size + "px;height:" + size + "px" + (arrive ? ";animation-delay:" + delay + "ms" : "") + '" data-act="select" data-id="' + esc(finding.id) +
      '" aria-label="' + esc("Inspect " + finding.title + (campaignSelection.has(finding.id) ? " · selected for campaign" : "")) +
      '" title="' + esc(SEV_LABEL[finding.severity] + " · " + finding.title + " · " + plural(finding.count, "alert") +
        (campaignSelection.has(finding.id) ? " · selected for campaign" : "")) + '">' +
      (finding.count > 1 ? "<span>" + finding.count + "</span>" : "") + "</button>";
  }).join("");
  const tray = s.findings.map((finding) =>
    '<div class="radar-finding' + (s.campaigns && campaignEligible(finding) ? " eligible" : "") + '"><button class="file' +
      (campaignSelection.has(finding.id) ? " campaign-marked" : "") + (finding.contained ? " hit" : "") + (selected && selected.id === finding.id ? " sel" : "") +
      '" data-act="select" data-id="' + esc(finding.id) + '"><strong><i class="dot" style="background:' + SRC_COLOR[finding.source] + '"></i>' +
      esc(finding.title) + "</strong><small>" + esc(SEV_LABEL[finding.severity]) + " · " + esc(plural(finding.count, "alert")) + "</small></button>" +
      radarCampaignToggle(finding, s) + "</div>"
  ).join("");
  let detail = "";
  if (selected) {
    const items = (s.threads && s.threads[selected.id]) || [];
    const last = items[items.length - 1];
    const sig = items.length + ":" + (last ? last.status + ":" + String(last.answer || "").length : "0");
    const where = selected.path + (selected.line ? ":" + selected.line : "") + " · " + selected.rule;
    detail = '<section class="panel detail' + (!items.length ? " empty-thread" : "") + '"><div class="d-head"><div class="chips"><span class="chip sev-' + esc(selected.severity) + '">' +
      esc(SEV_LABEL[selected.severity]) + '</span><span class="chip">' + esc(SRC_LABEL[selected.source] || selected.source) + '</span><span class="chip">' +
      esc(plural(selected.count, "open alert")) + "</span>" +
      (selected.url ? '<a class="gh-link" href="' + esc(selected.url) + '" target="_blank" rel="noopener">View on GitHub ↗</a>' : "") +
      "</div><h2>" + esc(selected.title) + '</h2><p class="loc">' + esc(where) +
      '</p><p class="summary">' + esc(selected.what || selected.remediation) + "</p>" +
      (s.refreshError ? '<p class="status">' + esc(s.refreshError) + "</p>" : "") +
      '</div><div class="thread" data-scroll="thread-' + esc(selected.id) + '" data-sig="' + esc(sig) + '">' + threadHtml(selected, s) +
      '</div><div class="composer"><div class="quick"><button class="suggest key" data-act="explain_finding" data-id="' + esc(selected.id) + '"' + off +
      '>Explain</button>' +
      '<button class="suggest key" data-act="assess_priority" data-id="' + esc(selected.id) + '"' + off + '>Assess priority</button>' +
      (selected.source !== "secret-scanning" && !(s.localFixes && s.localFixes[selected.id])
        ? '<button class="suggest key" data-act="request_copilot" data-id="' + esc(selected.id) + '"' + off + '>Fix locally</button>' : "") +
      (selected.source === "code-scanning"
        ? ((s.assigned && s.assigned[selected.id]) || selected.copilot
          ? (function (a) { return '<a class="suggest key assigned" href="' + esc(a.url) + '" target="_blank" rel="noopener" title="Open the alert on GitHub">✓ Assigned to Copilot · #' + esc(a.number) + "</a>"; })((s.assigned && s.assigned[selected.id]) || selected.copilot)
          : '<button class="suggest key" data-act="assign_copilot" data-id="' + esc(selected.id) + '"' + off + '>Fix in the cloud</button>')
        : "") +
      (items.length && !busy ? '<button class="suggest key radar-conversation-clear" data-act="clear_thread" data-id="' + esc(selected.id) + '">Clear</button>' : "") + '</div>' +
      localFixHtml(s.localFixes && s.localFixes[selected.id]) + '<div class="ask-row"><input id="ask-input" autocomplete="off" maxlength="500" placeholder="' +
      esc(busy ? "Copilot is answering…" : selected.source === "secret-scanning" ? "Ask Copilot about this alert…" : "Ask about this alert, or request a fix in a dedicated session…") + '" data-enter="ask-send" /><button id="ask-send" class="primary" data-act="ask_copilot" data-id="' +
      esc(selected.id) + '" data-input="ask-input"' + off + ">Ask</button></div></div></section>";
  }
  const phase = (typeof performance !== "undefined" ? performance.now() : 0) % SWEEP_MS;
  const scope = '<div class="scope' + (s.refreshing ? " syncing" : "") + '"><div class="halo" aria-hidden="true" style="animation-delay:-' + Math.round(phase) + 'ms"></div><svg class="radar-svg" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">' +
    '<circle class="ring-stroke" cx="50" cy="50" r="44"/>' +
    '<circle class="ring-stroke" cx="50" cy="50" r="32"/>' +
    '<circle class="ring-stroke hot" cx="50" cy="50" r="18"/>' +
    '<circle cx="50" cy="50" r="1.15" fill="#3ee0ff"/>' +
    '<circle cx="50" cy="50" r="2.5" fill="none" stroke="#3ee0ff" stroke-width=".28"/></svg>' + blips + "</div>";
  return '<header class="top"><div><h1>Attack surface radar</h1><p class="sub">' + s.findings.length + " groups · " + alertCount + " alerts. " +
    srcNote(s) + '</p></div><div class="row"><span class="src ' + srcClass(s) + '"><i></i>' + srcLabel(s) + "</span>" + refreshButton(s) + resetButton(s) + "</div></header>" +
    kpiHtml(s, critical) + '<div class="radar-wrap"><div class="scope-col">' +
    scope + '<div class="legend"><span><i class="swatch" style="background:#ff5d73"></i>Code scanning</span><span><i class="swatch" style="background:#ffc14a"></i>Dependabot</span><span><i class="swatch" style="background:#c9a6ff"></i>Secret scanning</span></div>' +
    '</div>' + detail + '</div><details class="radar-findings" data-disclosure="radar-findings"><summary class="section-title">All findings' +
    (s.campaigns ? " &amp; Security campaigns" : "") + ' · ' + s.findings.length + " groups · " + alertCount + " alerts</summary>" +
    '<div class="radar-findings-content">' + radarCampaignBar(s) + '<div class="grid">' + tray + '</div></div></details>';
}
`;

const COMPLIANCE_VIEW = `
const remediationProjection = ${remediationProjection.toString()};
const C_SEV = { critical: "#ff5d73", high: "#ffc14a", medium: "#3ee0ff", low: "#8eb4bc" };
const cMotion = { scenario: undefined, at: -1e9 };
function tone(score20) { return score20 >= 15 ? "#3dffb0" : score20 >= 9 ? "#ffc14a" : "#ff5d73"; }
function cPlural(n, word) { return n + " " + word + (n === 1 ? "" : "s"); }
function cThread(sel, s) {
  const items = (s.threads && s.threads[sel.id]) || [];
  if (!items.length) {
    return '<div class="starter"><p><span class="spark">✦</span> Turn this theme into a plan, a board line, or an audit checklist. Advice uses the shared alert metadata and checked evidence; implementation stays in the radar.</p></div>';
  }
  return items.map((item) => {
    const q = '<div class="q">' + esc(item.question) + "</div>";
    if (item.status === "pending") {
      return q + '<div class="a pending"><div class="a-head"><span class="spark">✦</span> Copilot<span class="dots"><i></i><i></i><i></i></span></div><div class="a-note">' +
        esc(item.note || "Thinking…") + "</div></div>";
    }
    return q + '<div class="a' + (item.offline ? " offline" : "") + '"><div class="a-head"><span class="spark">✦</span> Copilot<span class="a-tag">' +
      (item.kind === "assign" ? (item.offline ? "GitHub API error" : "GitHub API · Copilot Autofix") : item.kind === "assess" ? (item.offline ? "assessment unavailable" : "AI priority · advisory") : item.offline ? "offline checklist" : "planning advice · no changes") + '</span></div><div class="a-body">' + md(item.answer) + "</div>" + promptHtml(item) + "</div>";
  }).join("");
}
const EV_SRC = { checkout: "repo file", live: "live setting", cached: "cached setting", unknown: "setting not readable · not scored" };
function gaps(control) { return (control.evidence || []).filter((item) => item.status === false); }
function cEvidence(control) {
  return '<ul class="ev">' + control.evidence.map((e) => '<li class="' + (e.status === true ? "ok" : e.status === false ? "no" : "na") + '"><i>' +
    (e.status === true ? "✓" : e.status === false ? "✕" : "?") + "</i><span>" + esc(e.label) + ' · <b>' +
    (e.status === true ? e.source === "checkout" ? "found" : "found / enabled" :
      e.status === false ? e.source === "checkout" ? "not found" : "not found / disabled" : "unknown · not scored") + '</b>' +
    (EV_SRC[e.source] ? '<small class="ev-src">' + esc(EV_SRC[e.source]) + "</small>" : "") + "</span></li>").join("") + "</ul>";
}
function cFinding(f, s, controlId, dependency = false) {
  const included = (dependency ? dependencySelection(controlId) : themeSelection(controlId)).has(f.id);
  const label = (included ? "Remove from" : "Add to") + " upgrade plan: " + f.title;
  const toggle = dependency ? '<button class="radar-campaign-toggle compact" id="dependency-card-' + esc(f.id) +
    '" data-act="toggle_dependency_selection" data-id="' + esc(f.id) + '" data-control="' + esc(controlId) +
    '" aria-pressed="' + included + '" aria-label="' + esc(label) + '" title="' + esc(label) + '"' +
    (s.refreshing ? " disabled" : "") + '><span aria-hidden="true">' + (included ? "✓" : "+") + '</span></button>' : radarCampaignToggle(f, s, controlId);
  return '<div class="fr-item' + (included ? " selected" : "") + '"><a class="fr" href="' + esc(f.url) +
    '" target="_blank" rel="noopener" title="Open ' + (dependency ? "Dependabot alerts" : "on GitHub") + '"><i class="sev-dot" style="background:' +
    (C_SEV[f.severity] || "#8eb4bc") + '"></i><span class="fr-t">' + esc(f.title) + '<small>' +
    esc(f.where || f.path) + '</small></span><span class="fr-n">' + f.count + '</span></a><div class="fr-actions">' + toggle + "</div></div>";
}
function cDependencyPlan(s, control, dependencies, mode) {
  if (!dependencies.length) return "";
  const selection = dependencySelection(control.id);
  const count = dependencies.filter((f) => selection.has(f.id)).reduce((sum, f) => sum + f.count, 0);
  const attrs = ' data-control="' + esc(control.id) + '"';
  const disabled = s.pending || s.refreshing ? " disabled" : "";
  return '<section class="c-dependency-plan"><h3>Dependabot upgrade plan</h3><p class="note">Select updates to preview their posture impact. Review and merge the actual Dependabot PRs in GitHub; this is not a Security Campaign.</p>' +
    '<div class="c-plan-tools"><button class="primary" data-act="select_dependency_theme"' + attrs + (s.refreshing ? " disabled" : "") + '>Preview all updates</button>' +
    (selection.size ? '<button class="good" data-act="draft_dependency_plan"' + attrs + disabled + '>Draft upgrade plan</button>' +
      '<button class="ghost" data-act="clear_dependency_selection"' + attrs + '>Clear updates</button>' +
      (mode !== "dependencies" ? '<button class="ghost" data-act="show_dependency_preview"' + attrs + '>Preview these updates</button>' : "") : "") +
    '</div><p class="note">' + (selection.size ? cPlural(selection.size, "group") + " · " + cPlural(count, "alert") + " selected" :
      cPlural(dependencies.length, "dependency group") + " · " + cPlural(dependencies.reduce((sum, f) => sum + f.count, 0), "open alert")) +
    '</p><div class="flist">' + dependencies.slice(0, 5).map((f) => cFinding(f, s, control.id, true)).join("") + "</div>" +
    (dependencies.length > 5 ? '<details data-disclosure="dependency-groups"><summary>Show ' + (dependencies.length - 5) +
      ' more groups · Preview all includes these too</summary><div class="flist">' + dependencies.slice(5).map((f) => cFinding(f, s, control.id, true)).join("") + "</div></details>" : "") +
    "</section>";
}
function briefHtml(s) {
  if (!s.brief || !s.brief.open) return "";
  const m = s.brief.model || s;
  const stale = m.score !== s.score;
  const ranked = m.controls.slice().sort((a, b) => a.score - b.score);
  const risks = ranked.slice(0, 3).map((c) => {
    const why = c.findings[0] ? c.findings[0].title + " · " + c.findings[0].severity : (gaps(c)[0] ? "No " + gaps(c)[0].label : "");
    return "<li><b>" + esc(c.title) + "</b> " + c.score + "/20" + (why ? '<br><span class="note">' + esc(why) + "</span>" : "") + "</li>";
  }).join("");
  const actions = [];
  ranked.forEach((c) => {
    const f = c.findings[0];
    if (f && (f.severity === "critical" || f.severity === "high") && actions.length < 3) actions.push(f.source === "secret-scanning" ? "Revoke and rotate the " + f.title.replace(/ alert$/, "") : f.source === "dependabot" ? "Merge the Dependabot update for " + f.title.replace(/ dependency alerts$/, "") : "Fix " + f.title + " with Copilot Autofix");
  });
  const missing = [];
  m.controls.forEach((c) => gaps(c).forEach((g) => { if (missing.indexOf(g.label) < 0) missing.push(g.label); }));
  missing.slice(0, 2).forEach((label) => actions.push("Add " + label));
  const t = m.totals || {};
  return '<section class="c-brief"><div class="c-brief-head"><span class="spark">✦</span><h3>Posture brief</h3><span class="note">Built ' + esc(s.brief.at || "") +
    " from " + (m.source === "github" ? "live GitHub data" : "the last sync") + " · saved as audit-brief.md" +
    (stale ? ' · <b class="stale">score is now ' + s.score + ", rebuild to update</b>" : "") + '</span><button class="small ghost" data-act="close_brief">Close</button></div><div class="c-cards">' +
    '<div class="c-card"><h4>Headline</h4><p class="big">' + m.score + '<span class="note">/100</span> → <span class="g">' + m.projected + '</span></p><p>Illustrative posture today, and once critical and high findings are fixed. ' +
    esc((t.codeScanning || 0) + " code, " + (t.dependabot || 0) + " dependency and " + (t.secretScanning || 0) + " secret alerts open.") + "</p></div>" +
    '<div class="c-card"><h4>Top risks</h4><ul>' + risks + "</ul></div>" +
    '<div class="c-card"><h4>Next 30 days</h4><ul>' + actions.map((a) => "<li>" + esc(a) + "</li>").join("") + "</ul></div>" +
    '<div class="c-card"><h4>Reporting clock</h4><p>NIS2: <b>24 h</b> early warning, <b>72 h</b> notification, <b>1 month</b> final report.</p><p class="note">DORA: major ICT incidents reported under Art. 19.</p></div>' +
    "</div></section>";
}
function view(s) {
  if (s.source === "none") return emptyState(s, "GitHub Advanced Security", "NIS2 / DORA posture");
  const now = typeof performance !== "undefined" ? performance.now() : 0;
  const ranked = s.controls.slice().sort((a, b) => a.score - b.score);
  const sel = s.controls.find((c) => c.id === selectedId) || ranked[0];
  const mappedFindings = (s.campaignThemes && s.campaignThemes[sel.id]) || sel.findings;
  const dependencies = mappedFindings.filter((f) => f.source === "dependabot");
  const campaignFindings = mappedFindings.filter(campaignEligible);
  const preparedCode = s.campaigns?.draft?.kind === "code" && s.campaigns.draft.scopeLabel === sel.title;
  const mode = planModes[sel.id] || (dependencies.length && !preparedCode ? "dependencies" : "campaign");
  const selection = mode === "dependencies" ? dependencySelection(sel.id) : themeSelection(sel.id);
  const campaign = remediationProjection(s.controls, [...selection], mode);
  const campaignActive = campaign.groups > 0;
  const preview = campaignActive || s.preview;
  const target = campaignActive ? campaign.score : s.projected;
  const scenarioKey = (campaignActive ? mode + ":" + sel.id + ":" + [...selection].sort().join(",") : "copilot:" + s.preview) + ":" + target;
  if (cMotion.scenario === undefined) cMotion.scenario = scenarioKey;
  else if (cMotion.scenario !== scenarioKey) { cMotion.scenario = scenarioKey; cMotion.at = now; }
  const grow = preview && now - cMotion.at < 900;
  const t = s.totals || {};
  const allGaps = [];
  s.controls.forEach((c) => gaps(c).forEach((g) => { const name = g.short || g.label; if (allGaps.indexOf(name) < 0) allGaps.push(name); }));
  const gauge = '<div class="gauge" style="--p:' + s.score + ";--q:" + (preview ? target : s.score) + ";--gc:" + tone(s.score / 5) + '"><div><small>Today</small><b>' + s.score +
    "</b><small>/ 100</small>" + (preview ? '<span class="to' + (grow ? " pop" : "") + '">→ ' + target + "<em>" + (campaignActive ? mode === "dependencies" ? "selected updates" : "selected campaign" : "with Copilot") + "</em></span>" : "") + "</div></div>";
  const how = s.scoring ? '<details class="c-how" data-disclosure="scoring"><summary>How is this scored?</summary><div><em>5 themes × 20 points. Each theme starts at 20 and loses, per open finding group:</em>' +
    s.scoring.map((r) => "<span>" + esc(r.label) + "<b>" + esc(typeof r.points === "number" ? "−" + Math.abs(r.points) : r.points) + "</b></span>").join("") +
    "<em>Floor at 0. One finding can affect multiple themes. Illustrative, not a legal score.</em></div></details>" : "";
  const cell = (label, value, sub) => '<div class="kpi"><span class="kpi-label">' + label + '</span><div class="kpi-value">' + value + '</div><div class="kpi-sub">' + sub + "</div></div>";
  const receipts = (s.campaigns?.receipts || []).filter((r) => !["failed", "abandoned"].includes(r.status));
  const published = receipts.filter((r) => r.status === "published").length;
  const unconfirmed = receipts.length - published;
  const stats = '<div class="c-stats">' +
    '<div class="kpi campaign-lift' + (campaignActive ? " on" : "") + '"><span class="kpi-label">' + (campaignActive ? mode === "dependencies" ? "Upgrade plan lift" : "Campaign lift" : s.preview ? "Critical / High lift" : "Projected gain") +
    '</span><div class="kpi-value"><span class="up">' + (campaignActive ? "+" + campaign.lift : s.preview ? "+" + s.lift : "—") +
    '</span><em>points</em></div><div class="kpi-sub">' + (campaignActive ? esc(cPlural(campaign.groups, "group")) + " · " +
      esc(cPlural(campaign.alerts, mode === "dependencies" ? "dependency alert" : "eligible alert")) : s.preview ? "All Critical / High groups resolved" : "Select a work scope below") + "</div></div>" +
    cell("Evidence gaps", String(allGaps.length), esc(allGaps.length ? allGaps.join(" · ") : "None found in the repo")) +
    cell("Campaigns tracked", String(published), unconfirmed ? unconfirmed + " publication(s) unconfirmed · check progress" : published ? "Actual GitHub progress below" : "None submitted from this session") + "</div>";
  const scenario = '<div class="c-scenario" role="status"><span><i class="stripe-key" aria-hidden="true"></i><strong>' +
    (campaignActive ? (mode === "dependencies" ? "Dependency plan scenario · " : "Campaign scenario · ") + esc(sel.title) : s.preview ? "Copilot scenario · Critical / High" : "Illustrative posture · not a legal score") + '</strong></span><span>' +
    (campaignActive ? (mode === "dependencies" ? "If every alert in the selected dependency groups is resolved. No upgrades or campaigns are executed." :
      campaign.upperBound ? "Upper bound: branch coverage is unknown; assumes every alert in the selected groups closes." :
      "If selected default-branch code / secret alerts are resolved.") +
      (campaign.excluded ? " " + cPlural(campaign.excluded, "alert") + " outside the campaign scope " + (campaign.excluded === 1 ? "remains." : "remain.") : "") +
      (campaign.lift === 0 ? " No point gain yet: remaining findings keep the score at its floor, or the selected scope is not eligible." : "") +
      " This replaces, never adds to, the Copilot scenario." : s.preview ? "If all Critical / High groups close, including dependencies and secrets." :
      "Radar explains exposure; here, choose work and show proof.") +
    (preview ? ' Hatching is projected; today’s score and evidence gaps are unchanged.' : "") + '</span></div>';
  const journey = '<div class="c-journey"><span><b>1 Prioritize</b> a theme</span><span>→</span><span><b>2 Plan</b> the work</span><span>→</span><span><b>3 Prove</b> with GitHub evidence</span>' +
    '<button class="ghost" data-act="toggle_preview"' + (campaignActive ? ' disabled title="Clear the selected work scope to compare the independent Copilot scenario."' : "") + '>' +
    (s.preview ? "Hide broad scenario" : "Compare Copilot lift (+" + s.lift + ")") + "</button></div>";
  const list = s.controls.map((c) => {
    const lift = campaignActive ? campaign.controls.find((item) => item.id === c.id).lift : s.preview ? c.projectedScore - c.score : 0;
    const g = gaps(c).length;
    const mapped = (s.campaignThemes && s.campaignThemes[c.id]) || c.findings;
    const route = c.id === "incident" ? "Evidence checklist · not an alert campaign" : mapped.some((f) => f.source === "dependabot")
      ? "Dependency updates" + (mapped.some(campaignEligible) ? " + workflow campaigns" : "") :
      mapped.some((f) => f.source === "secret-scanning") ? "Credential rotation · secrets preparation" : "Security campaign";
    return '<button class="ctl' + (sel && sel.id === c.id ? " sel" : "") + '" data-act="select" data-id="' + esc(c.id) + '" title="' + esc(route) + '"><span class="ctl-t"><strong>' + esc(c.title) + '</strong><span class="ctl-type">' +
      esc(route) + '</span></span><span class="ctl-score" style="color:' + tone(c.score) + '">' + c.score + (lift ? '<span class="up' + (grow ? " pop" : "") + '">+' + lift + "</span>" : "") +
      '<em>/20</em></span><span class="cbar"><i style="width:' + c.score * 5 + "%;background:" + tone(c.score) + '"></i>' + (lift ? '<i class="ghost' + (grow ? " grow" : "") + '" style="width:' + lift * 5 + '%"></i>' : "") +
      '</span><span class="ctl-meta"><span>' + (c.id === "incident" ? cPlural(c.evidence.filter((e) => e.status === true).length, "artifact") + " found" :
        c.alerts ? esc(cPlural(c.alerts, "open alert")) : "No open alerts") + "</span>" + (g ? '<span class="gap">' + esc(cPlural(g, "evidence gap")) + "</span>" : "") + "</span></button>";
  }).join("");
  const busy = Boolean(s.pending);
  const off = busy ? " disabled" : "";
  const items = (s.threads && s.threads[sel.id]) || [];
  const last = items[items.length - 1];
  const sig = items.length + ":" + (last ? last.status + ":" + String(last.answer || "").length : "0");
  const refs = sel.nis2.map((r) => '<span class="chip ref">NIS2 ' + esc(r) + "</span>").join("") + sel.dora.map((r) => '<span class="chip ref dora">DORA ' + esc(r) + "</span>").join("");
  const evidence = cEvidence(sel);
  const clock = sel.clock && s.clock ? '<details class="clock" data-disclosure="incident-clock"><summary>Reporting reference · not triggered by repository alerts</summary><ol>' + s.clock.nis2.map((step) =>
    "<li><b>" + esc(step.at) + "</b><span>" + esc(step.label) + "</span><small>" + esc(step.note) + "</small></li>").join("") + '</ol><p class="note">NIS2 Art. 23. DORA: ' + esc(s.clock.dora.join(" → ")) + ".</p></details>" : "";
  const outsidePreview = (sel.bySeverity.medium || 0) + (sel.bySeverity.low || 0);
  const projectionNote = !campaignActive && s.preview && sel.alerts > 0 && outsidePreview === sel.alerts
    ? '<p class="note">No Copilot lift in this scenario: all ' + sel.alerts + ' open alerts are Medium or Low. This preview only closes Critical and High alerts; these findings can still be fixed. Evidence gaps are unchanged.</p>' : "";
  const quick = [["draft_plan", "plan", " key"], ["draft_board", "board", " key"], ["ask_auditor", "auditor", ""]].map((q) =>
    '<button class="suggest' + q[2] + '" data-act="' + q[0] + '" data-id="' + esc(sel.id) + '"' + off + ">" + (q[2] ? "✦ " : "") + esc((s.labels && s.labels[q[1]]) || q[1]) + "</button>").join("") +
    (items.length && !busy ? '<button class="suggest ghost" data-act="clear_thread" data-id="' + esc(sel.id) + '">Clear</button>' : "");
  const rationale = sel.scoreDetails && sel.id !== "incident" ? '<p class="note">Illustrative scoring: 20 − ' + sel.scoreDetails.alertPenalty + ' alert-group points − ' +
    sel.scoreDetails.evidencePenalty + ' missing-evidence points; floor at 0.</p>' : "";
  const guidanceTools = '<div class="c-guidance-tools">' +
    (sel.id === "incident" ? '<button class="good" data-act="draft_evidence" data-id="incident"' + off + '>Draft response checklist</button>' :
      '<button class="suggest key" data-act="draft_plan" data-id="' + esc(sel.id) + '"' + off + '>Draft 30-day priorities</button>') +
    '<button class="suggest" data-act="ask_auditor" data-id="' + esc(sel.id) + '"' + off + '>Audit questions</button></div>';
  const responseEvidence = '<section class="c-response-evidence"><h3>Contact, response process, and reporting evidence</h3>' +
    '<p class="note">No alert campaign here. Checks look for files/settings in this repository; “not found” does not mean the organization has no process.</p>' +
    evidence + '<p class="score-rationale">' + sel.score + '/20 = 20 − ' + cPlural(gaps(sel).length, "missing artifact") + ' × 4 points.</p>' +
    '<p class="note">A file’s presence is not proof of a tested response capability. Validate contacts, escalation, ownership, and reporting in a tabletop exercise.</p>' + clock + "</section>";
  const codeScope = (campaignFindings.length ? radarCampaignBar({ ...s, findings: campaignFindings }, sel.id) +
    '<div class="c-facts"><div><h4>Campaign scope · ' + esc(cPlural(campaignFindings.reduce((sum, f) => sum + f.count, 0), "open alert")) +
    '</h4><div class="flist">' + campaignFindings.map((f) => cFinding(f, s, sel.id)).join("") + '</div></div></div>' : "");
  const work = sel.id === "incident" ? responseEvidence : cDependencyPlan(s, sel, dependencies, mode) +
    (dependencies.length && codeScope ? '<details class="c-code-scope" data-disclosure="workflow-campaign"' +
      (mode === "campaign" || s.campaigns?.draft?.scopeLabel === sel.title ? " open" : "") + '><summary>Workflow alerts · separate code campaign</summary>' +
      (themeSelection(sel.id).size && mode !== "campaign" ? '<div class="c-plan-tools"><button class="ghost" data-act="show_campaign_preview" data-control="' + esc(sel.id) + '">Preview workflow campaign</button></div>' : "") +
      codeScope + "</details>" : codeScope) +
    (!dependencies.length && !codeScope ? '<div class="c-facts"><p class="note">No open alerts mapped here. Review the evidence below.</p></div>' : "") +
    '<div class="c-facts"><details class="c-evidence" data-disclosure="evidence-' + esc(sel.id) + '"><summary>Repository evidence · ' +
      esc(cPlural(gaps(sel).length, "gap")) + '</summary>' + evidence + "</details></div>";
  const detail = '<section class="panel c-detail"><div class="d-head"><h2>' + esc(sel.title) + '</h2><p class="d-score"><b style="color:' + tone(sel.score) + '">' + sel.score +
    '</b>/20 today' + (preview ? ' → <b class="g">' + (campaignActive ? campaign.controls.find((c) => c.id === sel.id).score : sel.projectedScore) + '</b>/20 ' +
      (campaignActive ? mode === "dependencies" ? "if the selected updates resolve" : "in the selected campaign scenario" : "once critical &amp; high are fixed") : "") + '</p>' +
    projectionNote + '<p class="summary">' + esc(sel.summary) + '</p>' + rationale +
    '<details data-disclosure="regulatory-mapping"><summary>Illustrative NIS2 / DORA mapping</summary><div class="chips">' + refs + "</div></details></div>" +
    (sel.id === "incident" ? guidanceTools + work : work + guidanceTools) +
    '<details class="c-guidance" data-disclosure="guidance-' + esc(sel.id) + '"' + (items.length ? " open" : "") + '><summary>Copilot guidance · plan, board summary &amp; audit evidence</summary><div class="thread" data-scroll="c-thread-' + esc(sel.id) + '" data-sig="' + esc(sig) + '">' + cThread(sel, s) + '</div><div class="composer"><div class="quick">' + quick +
    '</div><div class="ask-row"><input id="c-ask" autocomplete="off" maxlength="500" placeholder="' + esc(busy ? "Copilot is answering…" : "Ask Copilot about " + sel.title.toLowerCase() + "…") +
    '" data-enter="c-send" /><button id="c-send" class="primary" data-act="ask_copilot" data-id="' + esc(sel.id) + '" data-input="c-ask"' + off + ">Ask</button></div></div></details></section>";
  const live = srcClass(s);
  const tracking = receipts.length && s.campaigns ? '<details class="c-tracking" data-disclosure="campaign-tracking"' +
    (unconfirmed || s.campaigns.error ? " open" : "") + '><summary>Actual GitHub campaign progress · ' + published + ' published' +
    (unconfirmed ? " · " + unconfirmed + " unconfirmed" : "") + '</summary>' +
    campaignHtml({ ...s, campaigns: { ...s.campaigns, draft: null } }, true) + "</details>" : "";
  return '<header class="top"><div><div class="kicker">GitHub Advanced Security</div><h1>NIS2 / DORA posture</h1><p class="sub">Prioritize the work. Preview the improvement. Show the evidence. Use the radar to investigate and implement fixes. ' +
    srcNote(s) + '</p></div><div class="row"><span class="src ' + live + '"><i></i>' + srcLabel(s) + "</span>" + refreshButton(s) +
    '<button class="good" data-act="generate_brief">Posture brief</button>' + resetButton(s) + "</div></header>" +
    '<section class="c-hero">' + gauge + stats + scenario + journey + how + "</section>" + tracking + briefHtml(s) + (s.refreshError ? '<p class="status">' + esc(s.refreshError) + "</p>" : "") +
    '<div class="c-main"><div class="c-list">' + list + "</div>" + detail + "</div>" +
    '<footer class="note c-foot"><span>' + esc(s.disclaimer) + "</span><span>" + esc(s.applicability || "") + "</span></footer>";
}
`;
VIEWS["attack-surface-radar"] = RADAR_START + CAMPAIGN_CLIENT + RADAR_REST;
VIEWS["compliance-scoreboard"] = CAMPAIGN_CLIENT + COMPLIANCE_VIEW;

export function renderPage(canvasId, state) {
	const viewSource = VIEWS[canvasId];
	if (!viewSource) {
		return shell("Unknown canvas", "function view(){ return '<p>Unknown canvas</p>'; }", state);
	}
	return shell(canvasId, viewSource, state);
}

export const CANVAS_IDS = Object.keys(VIEWS);
