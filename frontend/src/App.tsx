import { useState } from "react";

type View = "dashboard" | "execute" | "variations" | "reevaluate" | "matrix";

// ── mock data ─────────────────────────────────────────────────────────────────

const TECHNIQUES = [
  { id: "T1059.001", name: "PowerShell", tactic: "Execution", severity: "high" as const },
  { id: "T1003.001", name: "LSASS Memory", tactic: "Credential Access", severity: "critical" as const },
  { id: "T1055.012", name: "Process Hollowing", tactic: "Defense Evasion", severity: "critical" as const },
  { id: "T1078",     name: "Valid Accounts", tactic: "Initial Access", severity: "high" as const },
  { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "Lateral Movement", severity: "medium" as const },
  { id: "T1027.002", name: "Software Packing", tactic: "Defense Evasion", severity: "high" as const },
  { id: "T1082",     name: "System Info Discovery", tactic: "Discovery", severity: "low" as const },
  { id: "T1105",     name: "Ingress Tool Transfer", tactic: "C&C", severity: "high" as const },
  { id: "T1569.002", name: "Service Execution", tactic: "Execution", severity: "medium" as const },
  { id: "T1136.001", name: "Local Account Creation", tactic: "Persistence", severity: "medium" as const },
];

type ExecResult = "ALERT" | "NO_ALERT" | "ERROR" | "RUNNING" | "QUEUED";

const EXEC_LOG: {
  runId: string; techniqueId: string; variant: string; result: ExecResult;
  execMs: number | null; sysmonEvents: number | null; ts: string; error?: string;
}[] = [
  { runId: "RUN-041", techniqueId: "T1059.001", variant: "Base",            result: "ALERT",    execMs: 1240, sysmonEvents: 14, ts: "2026-09-04 14:33:11" },
  { runId: "RUN-040", techniqueId: "T1059.001", variant: "VAR-3 (Encoded)", result: "NO_ALERT", execMs: 980,  sysmonEvents: 7,  ts: "2026-09-04 14:32:58" },
  { runId: "RUN-039", techniqueId: "T1003.001", variant: "VAR-2 (Minidump)",result: "NO_ALERT", execMs: 2310, sysmonEvents: 22, ts: "2026-09-04 14:30:22" },
  { runId: "RUN-038", techniqueId: "T1078",     variant: "Base",            result: "ALERT",    execMs: 830,  sysmonEvents: 9,  ts: "2026-09-04 14:28:05" },
  { runId: "RUN-037", techniqueId: "T1082",     variant: "Base",            result: "ALERT",    execMs: 420,  sysmonEvents: 5,  ts: "2026-09-04 14:25:44" },
  { runId: "RUN-036", techniqueId: "T1055.012", variant: "VAR-1",           result: "NO_ALERT", execMs: 1870, sysmonEvents: 18, ts: "2026-09-04 14:22:01" },
];

const VARIATIONS: {
  id: string; techniqueId: string; method: string; description: string;
  status: "pending_review" | "approved" | "rejected"; source: "manual" | "llm";
  llmPrompt?: string;
}[] = [
  { id: "VAR-AI-003", techniqueId: "T1059.001", method: "LLM",    description: "IEX with split string concat to avoid keyword matching",        status: "pending_review", source: "llm",    llmPrompt: "Generate a PowerShell execution variant that avoids AMSI detection using string concatenation only. No external downloads." },
  { id: "VAR-AI-002", techniqueId: "T1003.001", method: "LLM",    description: "NanoDump via reflective load — alternate syscall chain",          status: "approved",       source: "llm",    llmPrompt: "Produce an LSASS dump variant using a reflective loader that avoids direct OpenProcess calls." },
  { id: "VAR-MAN-007",techniqueId: "T1059.001", method: "Manual", description: "EncodedCommand flag with Base64 payload",                         status: "approved",       source: "manual" },
  { id: "VAR-MAN-006",techniqueId: "T1003.001", method: "Manual", description: "comsvcs.dll MiniDump via rundll32",                               status: "approved",       source: "manual" },
  { id: "VAR-AI-001", techniqueId: "T1078",     method: "LLM",    description: "RDP auth with renamed built-in account — rule only checks 'Admin'",status: "rejected",       source: "llm",    llmPrompt: "Vary the account name used in a valid-accounts RDP login to evade name-based rules." },
];

const BLINDSPOTS: {
  id: string; techniqueId: string; variantId: string; status: "open" | "patched";
  cause: string; sigmaRule: string; recommendation: string;
}[] = [
  { id: "BS-004", techniqueId: "T1003.001", variantId: "VAR-MAN-006", status: "open",   cause: "Rule matches direct sekurlsa::logonpasswords. comsvcs.dll MiniDump uses different call path.", sigmaRule: "sigma/cred_dump_lsass_direct.yml",      recommendation: "Add parent-process rule matching rundll32 → comsvcs.dll with MiniDump export." },
  { id: "BS-003", techniqueId: "T1059.001", variantId: "VAR-MAN-007", status: "patched",cause: "Rule requires raw invocation pattern; -EncodedCommand bypasses string match.",               sigmaRule: "sigma/powershell_exec.yml",             recommendation: "Match on EncodedCommand flag regardless of payload content. Rule updated." },
  { id: "BS-002", techniqueId: "T1055.012", variantId: "VAR-1",       status: "open",   cause: "No detection rule exists. Sysmon Event ID 10 fires but no sigma rule consumes it.",           sigmaRule: "—",                                    recommendation: "Author new rule on Sysmon EID 10 with hollow process memory-write heuristic." },
  { id: "BS-001", techniqueId: "T1027.002", variantId: "VAR-1",       status: "open",   cause: "Signature-based rule misses packed binaries with modified UPX headers.",                      sigmaRule: "sigma/suspicious_packed_binary.yml",   recommendation: "Supplement signature rule with entropy-based heuristic detection." },
];

const MATRIX: Record<string, (boolean | null)[]> = {
  "T1059.001": [true,  true,  false, false, null ],
  "T1003.001": [true,  true,  false, null,  null ],
  "T1055.012": [false, false, false, null,  null ],
  "T1078":     [true,  false, null,  null,  null ],
  "T1021.001": [true,  true,  true,  null,  null ],
  "T1027.002": [false, false, false, false, null ],
  "T1082":     [true,  true,  null,  null,  null ],
  "T1105":     [true,  true,  false, null,  null ],
  "T1569.002": [false, false, null,  null,  null ],
  "T1136.001": [true,  false, null,  null,  null ],
};
const MATRIX_COLS = ["Base", "VAR-1", "VAR-2", "VAR-3", "VAR-4"];

const totalCells  = Object.values(MATRIX).flatMap(r => r).filter(v => v !== null).length;
const hitCells    = Object.values(MATRIX).flatMap(r => r).filter(v => v === true).length;
const coveragePct = Math.round((hitCells / totalCells) * 100);

// ── shared primitives ─────────────────────────────────────────────────────────

type BadgeColor = "green" | "red" | "amber" | "blue" | "zinc" | "teal";
function Badge({ label, color }: { label: string; color: BadgeColor }) {
  const cls: Record<BadgeColor, string> = {
    green: "bg-emerald-950 text-emerald-400 border-emerald-800",
    red:   "bg-red-950 text-red-400 border-red-800",
    amber: "bg-amber-950 text-amber-400 border-amber-800",
    blue:  "bg-blue-950 text-blue-400 border-blue-800",
    zinc:  "bg-zinc-900 text-zinc-400 border-zinc-700",
    teal:  "bg-[#00d4aa]/10 text-[#00d4aa] border-[#00d4aa]/30",
  };
  return (
    <span className={`inline-flex items-center border px-1.5 py-px font-mono text-[10px] uppercase tracking-wider whitespace-nowrap ${cls[color]}`}>
      {label}
    </span>
  );
}

function SectionHeader({ label, right }: { label: string; right?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between mb-4">
      <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">{label}</span>
      {right}
    </div>
  );
}

function TableShell({ cols, children }: { cols: string[]; children: React.ReactNode }) {
  return (
    <div className="border border-zinc-800 overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-zinc-800">
            {cols.map(c => (
              <th key={c} className="px-4 py-2.5 text-left text-[10px] font-mono uppercase tracking-widest text-zinc-600 whitespace-nowrap">{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

function resultBadge(r: ExecResult) {
  if (r === "ALERT")    return <Badge label="ALERT"    color="green" />;
  if (r === "NO_ALERT") return <Badge label="NO ALERT" color="red" />;
  if (r === "ERROR")    return <Badge label="ERROR"    color="amber" />;
  if (r === "RUNNING")  return <Badge label="RUNNING"  color="teal" />;
  return                       <Badge label="QUEUED"   color="zinc" />;
}

// ── views ─────────────────────────────────────────────────────────────────────

function Dashboard() {
  return (
    <div className="space-y-6">
      {/* stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-px bg-zinc-800">
        {[
          { label: "Detection Coverage",  value: `${coveragePct}%`, sub: `${hitCells}/${totalCells} test cells detected`, accent: true },
          { label: "ATT&CK Techniques",   value: "10",   sub: "8–12 target range" },
          { label: "Open Blind Spots",    value: "3",    sub: "1 patched this sprint" },
          { label: "AI Variants Generated", value: "3", sub: "1 novel blind spot found" },
        ].map(s => (
          <div key={s.label} className="bg-zinc-950 px-5 py-4">
            <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600 mb-1">{s.label}</div>
            <div className={`text-3xl font-bold font-mono tabular-nums ${s.accent ? "text-[#00d4aa]" : "text-zinc-100"}`}>{s.value}</div>
            <div className="text-[11px] text-zinc-600 mt-1">{s.sub}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* recent runs */}
        <div className="lg:col-span-2 border border-zinc-800">
          <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">Recent Executions</span>
            <span className="text-[10px] font-mono text-zinc-700">FastAPI · /runs</span>
          </div>
          <TableShell cols={["Run ID", "Technique", "Variant", "Sysmon Evts", "Exec Time", "Result"]}>
            {EXEC_LOG.map(r => (
              <tr key={r.runId} className="border-b border-zinc-800/40 hover:bg-zinc-800/20 transition-colors">
                <td className="px-4 py-2.5 font-mono text-[11px] text-zinc-500">{r.runId}</td>
                <td className="px-4 py-2.5 font-mono text-[12px] text-[#00d4aa]">{r.techniqueId}</td>
                <td className="px-4 py-2.5 text-[12px] text-zinc-300">{r.variant}</td>
                <td className="px-4 py-2.5 font-mono text-[12px] text-zinc-400 tabular-nums">{r.sysmonEvents ?? "—"}</td>
                <td className="px-4 py-2.5 font-mono text-[12px] text-zinc-500 tabular-nums">{r.execMs ? `${r.execMs} ms` : "—"}</td>
                <td className="px-4 py-2.5">{resultBadge(r.result)}</td>
              </tr>
            ))}
          </TableShell>
        </div>

        {/* tech stack */}
        <div className="border border-zinc-800">
          <div className="px-4 py-3 border-b border-zinc-800">
            <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">System Architecture</span>
          </div>
          <div className="p-4 space-y-3">
            {[
              { layer: "Frontend",   components: ["React", "Vite", "Tailwind CSS"] },
              { layer: "Backend",    components: ["FastAPI", "Python"] },
              { layer: "Storage",    components: ["PostgreSQL"] },
              { layer: "Telemetry",  components: ["Sysmon", "Windows Event Log"] },
              { layer: "Detection",  components: ["Sigma Rules", "Wazuh SIEM"] },
              { layer: "AI Engine",  components: ["LLM API", "Prompt Templates"] },
              { layer: "Env",        components: ["VMware", "Windows 10/Server 2022"] },
            ].map(l => (
              <div key={l.layer} className="flex items-start gap-3">
                <span className="text-[10px] font-mono text-zinc-600 w-20 flex-shrink-0 pt-0.5 uppercase tracking-wide">{l.layer}</span>
                <div className="flex flex-wrap gap-1">
                  {l.components.map(c => (
                    <span key={c} className="bg-zinc-900 border border-zinc-800 text-zinc-400 font-mono text-[10px] px-1.5 py-0.5">{c}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* milestones */}
      <div className="border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800">
          <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">Delivery Milestones</span>
        </div>
        <div className="p-4 grid grid-cols-2 lg:grid-cols-4 gap-2">
          {[
            { d: "D1", label: "Architecture",          date: "09/04/26", done: true  },
            { d: "D2", label: "Test Environment",       date: "10/02/26", done: false },
            { d: "D3", label: "Test Framework",         date: "10/16/26", done: false },
            { d: "D4", label: "Initial Coverage Eval",  date: "10/30/26", done: false },
            { d: "D5", label: "Blind-Spot Analysis",    date: "11/13/26", done: false },
            { d: "D6", label: "Improvement Validation", date: "11/20/26", done: false },
            { d: "D7", label: "AI Variation Prototype", date: "11/27/26", done: false },
            { d: "D8", label: "Final Framework",        date: "12/04/26", done: false },
          ].map(m => (
            <div key={m.d} className={`border p-3 ${m.done ? "border-[#00d4aa]/30 bg-[#00d4aa]/5" : "border-zinc-800"}`}>
              <div className="flex items-center gap-1.5 mb-1">
                <div className={`w-1.5 h-1.5 rounded-full ${m.done ? "bg-[#00d4aa]" : "bg-zinc-700"}`} />
                <span className={`font-mono text-[10px] ${m.done ? "text-[#00d4aa]" : "text-zinc-600"}`}>{m.done ? "DONE" : "PENDING"}</span>
              </div>
              <div className="text-[11px] font-mono text-zinc-500 mb-0.5">{m.d}</div>
              <div className="text-[12px] text-zinc-300 leading-tight">{m.label}</div>
              <div className="text-[10px] font-mono text-zinc-700 mt-1">{m.date}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ExecuteView() {
  const [selected, setSelected] = useState<string[]>([]);
  const [running, setRunning] = useState(false);

  const toggle = (id: string) =>
    setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]);

  const handleRun = () => {
    if (!selected.length) return;
    setRunning(true);
    setTimeout(() => setRunning(false), 2200);
  };

  return (
    <div className="space-y-5">
      <SectionHeader
        label="Automated Test Execution — Use Case 1"
        right={
          <div className="flex items-center gap-2 text-[10px] font-mono text-zinc-600">
            <span>POST</span>
            <code className="bg-zinc-900 border border-zinc-800 px-2 py-0.5 text-[#00d4aa]">/api/runs/execute</code>
          </div>
        }
      />

      {/* inputs panel */}
      <div className="border border-zinc-800 p-5">
        <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600 mb-3">Inputs — Select Test Cases</div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-px bg-zinc-800 mb-4">
          {TECHNIQUES.map(t => {
            const active = selected.includes(t.id);
            return (
              <button
                key={t.id}
                onClick={() => toggle(t.id)}
                className={`flex items-center gap-3 px-4 py-3 text-left transition-colors ${active ? "bg-[#00d4aa]/8 border-l-2 border-[#00d4aa]" : "bg-zinc-950 hover:bg-zinc-900 border-l-2 border-transparent"}`}
              >
                <div className={`w-3 h-3 border ${active ? "bg-[#00d4aa] border-[#00d4aa]" : "border-zinc-700"} flex items-center justify-center`}>
                  {active && <span className="text-zinc-950 text-[9px] font-bold">✓</span>}
                </div>
                <div>
                  <span className="font-mono text-[12px] text-[#00d4aa]">{t.id}</span>
                  <span className="text-[12px] text-zinc-300 ml-2">{t.name}</span>
                </div>
                <Badge
                  label={t.severity}
                  color={t.severity === "critical" ? "red" : t.severity === "high" ? "amber" : t.severity === "medium" ? "blue" : "zinc"}
                />
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-4">
          <button
            onClick={handleRun}
            disabled={!selected.length || running}
            className="border border-[#00d4aa] text-[#00d4aa] font-mono text-[11px] px-4 py-2 uppercase tracking-wide hover:bg-[#00d4aa]/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {running ? "Executing..." : `Run ${selected.length || 0} Test${selected.length !== 1 ? "s" : ""}`}
          </button>
          <span className="text-[11px] font-mono text-zinc-600">
            Target: <span className="text-zinc-400">lab-dc01 · lab-workstation01</span>
          </span>
        </div>
      </div>

      {/* outputs */}
      <div className="border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">Outputs — Execution Log</span>
          <span className="text-[10px] font-mono text-zinc-700">PostgreSQL · runs_log</span>
        </div>
        <TableShell cols={["Run ID", "Technique", "Variant", "Exec Time", "Sysmon Events", "SIEM Status", "Timestamp"]}>
          {EXEC_LOG.map(r => (
            <tr key={r.runId} className="border-b border-zinc-800/40 hover:bg-zinc-800/20 transition-colors">
              <td className="px-4 py-3 font-mono text-[11px] text-zinc-500">{r.runId}</td>
              <td className="px-4 py-3 font-mono text-[12px] text-[#00d4aa]">{r.techniqueId}</td>
              <td className="px-4 py-3 text-[12px] text-zinc-300">{r.variant}</td>
              <td className="px-4 py-3 font-mono text-[12px] text-zinc-400 tabular-nums">{r.execMs ? `${r.execMs} ms` : "—"}</td>
              <td className="px-4 py-3 font-mono text-[12px] text-zinc-400 tabular-nums">{r.sysmonEvents ?? "—"}</td>
              <td className="px-4 py-3">{resultBadge(r.result)}</td>
              <td className="px-4 py-3 font-mono text-[11px] text-zinc-700">{r.ts}</td>
            </tr>
          ))}
        </TableShell>
      </div>

      {/* sysmon telemetry detail */}
      <div className="border border-zinc-800 p-5">
        <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600 mb-3">Sysmon Telemetry — RUN-041 (T1059.001 Base)</div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-px bg-zinc-800">
          {[
            { eid: "EID 1",  label: "Process Create",   count: 4 },
            { eid: "EID 3",  label: "Network Connect",  count: 0 },
            { eid: "EID 11", label: "File Create",       count: 2 },
            { eid: "EID 13", label: "Registry Set",      count: 8 },
          ].map(e => (
            <div key={e.eid} className="bg-zinc-950 px-4 py-3">
              <div className="font-mono text-[10px] text-zinc-600 mb-1">{e.eid}</div>
              <div className="text-xl font-bold font-mono text-zinc-200 tabular-nums">{e.count}</div>
              <div className="text-[11px] text-zinc-500 mt-0.5">{e.label}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function VariationsView() {
  const [prompt, setPrompt] = useState("");
  const [techId, setTechId] = useState("T1059.001");
  const [generating, setGenerating] = useState(false);
  const [statuses, setStatuses] = useState<Record<string, "pending_review" | "approved" | "rejected">>(
    Object.fromEntries(VARIATIONS.map(v => [v.id, v.status]))
  );

  const handleGen = () => { setGenerating(true); setTimeout(() => setGenerating(false), 2000); };
  const approve = (id: string) => setStatuses(s => ({ ...s, [id]: "approved" }));
  const reject  = (id: string) => setStatuses(s => ({ ...s, [id]: "rejected" }));

  return (
    <div className="space-y-5">
      <SectionHeader
        label="Generate Detection Variations — Use Case 2"
        right={
          <div className="flex items-center gap-2 text-[10px] font-mono text-zinc-600">
            <span>POST</span>
            <code className="bg-zinc-900 border border-zinc-800 px-2 py-0.5 text-[#00d4aa]">/api/variations/generate</code>
          </div>
        }
      />

      {/* input panel */}
      <div className="border border-zinc-800 p-5">
        <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600 mb-3">Inputs</div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="text-[10px] font-mono text-zinc-600 uppercase tracking-wide block mb-1.5">Base Technique</label>
            <select
              value={techId}
              onChange={e => setTechId(e.target.value)}
              className="w-full bg-zinc-900 border border-zinc-700 text-zinc-300 font-mono text-[12px] px-3 py-2 focus:outline-none focus:border-[#00d4aa]"
            >
              {TECHNIQUES.map(t => <option key={t.id} value={t.id}>{t.id} — {t.name}</option>)}
            </select>
          </div>
          <div>
            <label className="text-[10px] font-mono text-zinc-600 uppercase tracking-wide block mb-1.5">Method</label>
            <select className="w-full bg-zinc-900 border border-zinc-700 text-zinc-300 font-mono text-[12px] px-3 py-2 focus:outline-none focus:border-[#00d4aa]">
              <option>LLM Prompt</option>
              <option>Manual</option>
            </select>
          </div>
          <div>
            <label className="text-[10px] font-mono text-zinc-600 uppercase tracking-wide block mb-1.5">LLM Prompt / Constraints</label>
            <input
              value={prompt}
              onChange={e => setPrompt(e.target.value)}
              placeholder="e.g. avoid direct syscalls, use only LOLBins..."
              className="w-full bg-zinc-900 border border-zinc-700 text-zinc-300 font-mono text-[12px] px-3 py-2 placeholder-zinc-700 focus:outline-none focus:border-[#00d4aa]"
            />
          </div>
        </div>
        <button
          onClick={handleGen}
          disabled={generating}
          className="border border-[#00d4aa] text-[#00d4aa] font-mono text-[11px] px-4 py-2 uppercase tracking-wide hover:bg-[#00d4aa]/10 transition-colors disabled:opacity-40"
        >
          {generating ? "Generating..." : "Generate via LLM"}
        </button>
        <p className="text-[10px] font-mono text-zinc-700 mt-2">
          Req 7: All AI-generated variants require manual validation before execution.
        </p>
      </div>

      {/* outputs */}
      <div className="border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">Outputs — Variation Repository</span>
          <span className="text-[10px] font-mono text-zinc-700">PostgreSQL · variations</span>
        </div>
        <table className="w-full">
          <thead>
            <tr className="border-b border-zinc-800">
              {["ID", "Technique", "Source", "Description", "Status", "Actions"].map(h => (
                <th key={h} className="px-4 py-2.5 text-left text-[10px] font-mono uppercase tracking-widest text-zinc-600">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {VARIATIONS.map(v => {
              const st = statuses[v.id];
              return (
                <tr key={v.id} className="border-b border-zinc-800/40 hover:bg-zinc-800/20 transition-colors">
                  <td className="px-4 py-3 font-mono text-[11px] text-zinc-500">{v.id}</td>
                  <td className="px-4 py-3 font-mono text-[12px] text-[#00d4aa]">{v.techniqueId}</td>
                  <td className="px-4 py-3">
                    <Badge label={v.source === "llm" ? "LLM" : "Manual"} color={v.source === "llm" ? "blue" : "zinc"} />
                  </td>
                  <td className="px-4 py-3 text-[12px] text-zinc-300 max-w-xs">{v.description}</td>
                  <td className="px-4 py-3">
                    <Badge
                      label={st.replace("_", " ")}
                      color={st === "approved" ? "green" : st === "rejected" ? "red" : "amber"}
                    />
                  </td>
                  <td className="px-4 py-3">
                    {st === "pending_review" ? (
                      <div className="flex gap-2">
                        <button onClick={() => approve(v.id)} className="text-[10px] font-mono text-emerald-400 border border-emerald-900 px-2 py-0.5 hover:border-emerald-700 transition-colors">Approve</button>
                        <button onClick={() => reject(v.id)}  className="text-[10px] font-mono text-red-400 border border-red-900 px-2 py-0.5 hover:border-red-700 transition-colors">Reject</button>
                      </div>
                    ) : st === "approved" ? (
                      <button className="text-[10px] font-mono text-[#00d4aa] border border-[#00d4aa]/30 px-2 py-0.5 hover:border-[#00d4aa]/60 transition-colors">Run Test</button>
                    ) : (
                      <span className="text-[11px] text-zinc-700 font-mono">—</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ReEvaluateView() {
  return (
    <div className="space-y-5">
      <SectionHeader
        label="Detection Re-Evaluation — Use Case 3"
        right={
          <div className="flex items-center gap-2 text-[10px] font-mono text-zinc-600">
            <span>POST</span>
            <code className="bg-zinc-900 border border-zinc-800 px-2 py-0.5 text-[#00d4aa]">/api/detections/reevaluate</code>
          </div>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* inputs */}
        <div className="border border-zinc-800 p-5 space-y-4">
          <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600">Inputs</div>

          <div>
            <div className="text-[10px] font-mono text-zinc-600 uppercase tracking-wide mb-2">Modified Detection Rules</div>
            <div className="space-y-2">
              {[
                { file: "sigma/powershell_exec.yml",          modified: true,  change: "Added EncodedCommand pattern" },
                { file: "sigma/cred_dump_lsass_direct.yml",   modified: false, change: "Pending — add comsvcs parent rule" },
                { file: "sigma/suspicious_packed_binary.yml", modified: false, change: "Pending — add entropy heuristic" },
                { file: "sigma/process_hollowing.yml",        modified: false, change: "New — in development" },
              ].map(r => (
                <div key={r.file} className={`flex items-start gap-3 p-3 border ${r.modified ? "border-[#00d4aa]/30 bg-[#00d4aa]/5" : "border-zinc-800"}`}>
                  <div className={`w-1.5 h-1.5 rounded-full mt-1 flex-shrink-0 ${r.modified ? "bg-[#00d4aa]" : "bg-zinc-700"}`} />
                  <div className="min-w-0">
                    <code className="font-mono text-[11px] text-zinc-300 block truncate">{r.file}</code>
                    <span className="text-[11px] text-zinc-600">{r.change}</span>
                  </div>
                  {r.modified && <Badge label="updated" color="teal" />}
                </div>
              ))}
            </div>
          </div>

          <div>
            <div className="text-[10px] font-mono text-zinc-600 uppercase tracking-wide mb-2">Benign Baseline Activities</div>
            <div className="space-y-1.5">
              {["Normal user login / logout cycle", "Windows Update process", "Browser HTTP/S traffic", "File open / save in Office apps"].map(b => (
                <div key={b} className="flex items-center gap-2">
                  <div className="w-1 h-1 bg-zinc-700 rounded-full" />
                  <span className="text-[12px] text-zinc-500">{b}</span>
                </div>
              ))}
            </div>
          </div>

          <button className="border border-[#00d4aa] text-[#00d4aa] font-mono text-[11px] px-4 py-2 uppercase tracking-wide hover:bg-[#00d4aa]/10 transition-colors w-full">
            Run Re-Evaluation
          </button>
        </div>

        {/* outputs */}
        <div className="space-y-4">
          <div className="border border-zinc-800 p-5">
            <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600 mb-3">Outputs — Blind Spots</div>
            <div className="space-y-3">
              {BLINDSPOTS.map(b => (
                <div key={b.id} className={`border p-4 ${b.status === "open" ? "border-red-900/50 bg-red-950/10" : "border-zinc-800"}`}>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-mono text-[11px] text-zinc-600">{b.id}</span>
                    <span className="font-mono text-[12px] text-[#00d4aa]">{b.techniqueId}</span>
                    <Badge label={b.status} color={b.status === "open" ? "red" : "green"} />
                  </div>
                  <p className="text-[11px] text-zinc-400 leading-relaxed mb-2">{b.cause}</p>
                  <div className="text-[11px] text-zinc-500 border-l-2 border-zinc-800 pl-2">{b.recommendation}</div>
                </div>
              ))}
            </div>
          </div>

          {/* false positive check */}
          <div className="border border-zinc-800 p-5">
            <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600 mb-3">False Positive Evaluation</div>
            <div className="space-y-2">
              {[
                { rule: "sigma/powershell_exec.yml",        benign: "Normal PS scripts", fp: false },
                { rule: "sigma/cred_dump_lsass_direct.yml", benign: "Windows Update",    fp: false },
                { rule: "sigma/process_hollowing.yml",      benign: "Browser launch",    fp: true  },
              ].map(row => (
                <div key={row.rule} className="flex items-center gap-3">
                  <Badge label={row.fp ? "FP" : "clean"} color={row.fp ? "amber" : "green"} />
                  <code className="font-mono text-[11px] text-zinc-500 truncate flex-1">{row.rule}</code>
                  <span className="text-[11px] text-zinc-600 whitespace-nowrap">{row.benign}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function MatrixView() {
  return (
    <div className="space-y-4">
      <SectionHeader
        label="Coverage Matrix — Use Case 4"
        right={
          <div className="flex items-center gap-2 text-[10px] font-mono text-zinc-600">
            <span>GET</span>
            <code className="bg-zinc-900 border border-zinc-800 px-2 py-0.5 text-[#00d4aa]">/api/coverage/matrix</code>
          </div>
        }
      />

      <div className="grid grid-cols-3 gap-px bg-zinc-800 mb-4">
        <div className="bg-zinc-950 px-4 py-3">
          <div className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest mb-1">Overall Coverage</div>
          <div className="text-2xl font-bold font-mono text-[#00d4aa] tabular-nums">{coveragePct}%</div>
          <div className="text-[11px] text-zinc-600">{hitCells}/{totalCells} test cells</div>
        </div>
        <div className="bg-zinc-950 px-4 py-3">
          <div className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest mb-1">Techniques Fully Covered</div>
          <div className="text-2xl font-bold font-mono text-zinc-100 tabular-nums">
            {TECHNIQUES.filter(t => {
              const row = MATRIX[t.id].filter(v => v !== null);
              return row.length > 0 && row.every(v => v === true);
            }).length}
          </div>
          <div className="text-[11px] text-zinc-600">of 10 techniques</div>
        </div>
        <div className="bg-zinc-950 px-4 py-3">
          <div className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest mb-1">Techniques with Gaps</div>
          <div className="text-2xl font-bold font-mono text-red-400 tabular-nums">
            {TECHNIQUES.filter(t => MATRIX[t.id].some(v => v === false)).length}
          </div>
          <div className="text-[11px] text-zinc-600">have at least one evasion</div>
        </div>
      </div>

      <div className="border border-zinc-800 overflow-x-auto">
        <table className="w-full min-w-[640px]">
          <thead>
            <tr className="border-b border-zinc-800">
              <th className="px-4 py-3 text-left text-[10px] font-mono uppercase tracking-widest text-zinc-600 w-36">Technique</th>
              <th className="px-4 py-3 text-left text-[10px] font-mono uppercase tracking-widest text-zinc-600">Name</th>
              <th className="px-4 py-3 text-left text-[10px] font-mono uppercase tracking-widest text-zinc-600">Tactic</th>
              {MATRIX_COLS.map(c => (
                <th key={c} className="px-3 py-3 text-center text-[10px] font-mono uppercase tracking-widest text-zinc-600">{c}</th>
              ))}
              <th className="px-4 py-3 text-center text-[10px] font-mono uppercase tracking-widest text-zinc-600">Score</th>
            </tr>
          </thead>
          <tbody>
            {TECHNIQUES.map(t => {
              const row = MATRIX[t.id];
              const tested = row.filter(v => v !== null);
              const hits   = tested.filter(v => v === true).length;
              const pct    = tested.length ? Math.round((hits / tested.length) * 100) : 0;
              return (
                <tr key={t.id} className="border-b border-zinc-800/40 hover:bg-zinc-800/20 transition-colors">
                  <td className="px-4 py-3 font-mono text-[12px] text-[#00d4aa]">{t.id}</td>
                  <td className="px-4 py-3 text-[12px] text-zinc-300">{t.name}</td>
                  <td className="px-4 py-3 text-[11px] text-zinc-500">{t.tactic}</td>
                  {row.map((cell, i) => (
                    <td key={i} className="px-3 py-3 text-center">
                      {cell === null
                        ? <span className="text-zinc-800 font-mono text-xs">—</span>
                        : cell
                          ? <span className="inline-flex w-5 h-5 items-center justify-center bg-[#00d4aa]/15 border border-[#00d4aa]/40 text-[#00d4aa] text-[10px] font-bold">✓</span>
                          : <span className="inline-flex w-5 h-5 items-center justify-center bg-red-900/25 border border-red-800/40 text-red-400 text-[10px] font-bold">✗</span>
                      }
                    </td>
                  ))}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2 justify-end">
                      <div className="w-16 h-1 bg-zinc-800 flex-shrink-0">
                        <div className="h-full bg-[#00d4aa]" style={{ width: `${pct}%` }} />
                      </div>
                      <span className="font-mono text-[11px] text-zinc-500 tabular-nums w-8 text-right">{hits}/{tested.length}</span>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="flex items-center gap-6 text-[11px] font-mono text-zinc-600">
        <div className="flex items-center gap-2">
          <span className="inline-flex w-4 h-4 items-center justify-center bg-[#00d4aa]/15 border border-[#00d4aa]/40 text-[#00d4aa] text-[9px]">✓</span>
          SIEM alert fired
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex w-4 h-4 items-center justify-center bg-red-900/25 border border-red-800/40 text-red-400 text-[9px]">✗</span>
          Evaded / no alert
        </div>
        <div className="flex items-center gap-2">
          <span className="text-zinc-700">—</span>
          Not yet tested
        </div>
      </div>
    </div>
  );
}

// ── nav ───────────────────────────────────────────────────────────────────────

const NAV: { id: View; label: string; useCase?: string }[] = [
  { id: "dashboard",   label: "Dashboard" },
  { id: "execute",     label: "Test Execution",  useCase: "UC-1" },
  { id: "variations",  label: "Variations",       useCase: "UC-2" },
  { id: "reevaluate",  label: "Re-Evaluation",    useCase: "UC-3" },
  { id: "matrix",      label: "Coverage Matrix",  useCase: "UC-4" },
];

export default function App() {
  const [view, setView] = useState<View>("dashboard");

  return (
    <div className="flex h-full bg-[#09090b] text-zinc-200" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>
      {/* sidebar */}
      <aside className="w-56 flex-shrink-0 border-r border-zinc-800 flex flex-col">
        <div className="px-5 py-5 border-b border-zinc-800">
          <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600 mb-1">Capstone · RAD v1</div>
          <div className="text-[14px] font-semibold text-zinc-100">DetectIQ</div>
          <div className="text-[10px] font-mono text-zinc-700 mt-0.5">Detection Robustness Framework</div>
        </div>

        <nav className="flex-1 py-3">
          {NAV.map(n => (
            <button
              key={n.id}
              onClick={() => setView(n.id)}
              className={`w-full flex items-center justify-between px-5 py-2.5 text-left transition-colors ${
                view === n.id
                  ? "text-[#00d4aa] bg-[#00d4aa]/8 border-r-2 border-[#00d4aa]"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40 border-r-2 border-transparent"
              }`}
            >
              <span className="text-[12px]">{n.label}</span>
              {n.useCase && (
                <span className={`font-mono text-[9px] ${view === n.id ? "text-[#00d4aa]/50" : "text-zinc-700"}`}>{n.useCase}</span>
              )}
            </button>
          ))}
        </nav>

        {/* actors */}
        <div className="px-5 py-4 border-t border-zinc-800 space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-700">Actors</div>
          {[
            { role: "Security Analyst", dot: "bg-[#00d4aa]" },
            { role: "Dev Team",          dot: "bg-blue-500" },
            { role: "AI System",         dot: "bg-amber-500" },
          ].map(a => (
            <div key={a.role} className="flex items-center gap-2">
              <div className={`w-1.5 h-1.5 rounded-full ${a.dot}`} />
              <span className="text-[11px] text-zinc-600">{a.role}</span>
            </div>
          ))}
          <div className="pt-2 text-[10px] font-mono text-zinc-700">Nathan Amend · Alex Lap</div>
        </div>
      </aside>

      {/* main */}
      <main className="flex-1 overflow-y-auto">
        <header className="border-b border-zinc-800 px-8 py-4 flex items-center justify-between sticky top-0 bg-[#09090b]/95 backdrop-blur z-10">
          <div>
            <h1 className="text-sm font-semibold text-zinc-100">{NAV.find(n => n.id === view)?.label}</h1>
            <p className="text-[10px] font-mono text-zinc-600">MITRE ATT&CK · Sysmon · FastAPI · PostgreSQL · React</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-[#00d4aa] animate-pulse" />
              <span className="text-[11px] font-mono text-zinc-600">lab-dc01 online</span>
            </div>
            <span className="text-[11px] font-mono text-zinc-700">2026-09-04</span>
          </div>
        </header>

        <div className="px-8 py-6">
          {view === "dashboard"  && <Dashboard />}
          {view === "execute"    && <ExecuteView />}
          {view === "variations" && <VariationsView />}
          {view === "reevaluate" && <ReEvaluateView />}
          {view === "matrix"     && <MatrixView />}
        </div>
      </main>
    </div>
  );
}
