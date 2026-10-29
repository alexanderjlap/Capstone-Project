import { useState, useEffect, useCallback } from "react";
import * as api from "./api";
import type {
  Technique,
  RunLog,
  Variation,
  BlindSpot,
  DetectionRule,
  MatrixResponse,
  ExecResult
} from "./api";

type View = "dashboard" | "execute" | "variations" | "reevaluate" | "matrix";
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

// ── Default fallback data ───────────────────────────────────────────────────

const DEFAULT_TECHNIQUES: Technique[] = [
  { id: "T1059.001", name: "PowerShell", tactic: "Execution", severity: "high" },
  { id: "T1003.001", name: "LSASS Memory", tactic: "Credential Access", severity: "critical" },
  { id: "T1055.012", name: "Process Hollowing", tactic: "Defense Evasion", severity: "critical" },
  { id: "T1078",     name: "Valid Accounts", tactic: "Initial Access", severity: "high" },
  { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "Lateral Movement", severity: "medium" },
  { id: "T1027.002", name: "Software Packing", tactic: "Defense Evasion", severity: "high" },
  { id: "T1082",     name: "System Info Discovery", tactic: "Discovery", severity: "low" },
  { id: "T1105",     name: "Ingress Tool Transfer", tactic: "C&C", severity: "high" },
  { id: "T1569.002", name: "Service Execution", tactic: "Execution", severity: "medium" },
  { id: "T1136.001", name: "Local Account Creation", tactic: "Persistence", severity: "medium" },
];

const DEFAULT_RUNS: RunLog[] = [
  { runId: "RUN-041", techniqueId: "T1059.001", variant: "Base",            result: "ALERT",    execMs: 1240, sysmonEvents: 14, telemetry: { eid1: 4, eid3: 0, eid11: 2, eid13: 8 }, ts: "2026-09-04 14:33:11", commandLine: "powershell.exe -NoProfile -Command 'Get-Process'" },
  { runId: "RUN-040", techniqueId: "T1059.001", variant: "VAR-3 (Encoded)", result: "NO_ALERT", execMs: 980,  sysmonEvents: 7,  telemetry: { eid1: 2, eid3: 0, eid11: 1, eid13: 4 }, ts: "2026-09-04 14:32:58", commandLine: "powershell.exe -EncodedCommand V3JpdGU..." },
  { runId: "RUN-039", techniqueId: "T1003.001", variant: "VAR-2 (Minidump)",result: "NO_ALERT", execMs: 2310, sysmonEvents: 22, telemetry: { eid1: 3, eid3: 0, eid11: 12, eid13: 7 }, ts: "2026-09-04 14:30:22", commandLine: "rundll32.exe comsvcs.dll #24" },
  { runId: "RUN-038", techniqueId: "T1078",     variant: "Base",            result: "ALERT",    execMs: 830,  sysmonEvents: 9,  telemetry: { eid1: 2, eid3: 3, eid11: 0, eid13: 4 }, ts: "2026-09-04 14:28:05", commandLine: "net use \\\\lab-dc01 /user:Administrator" },
  { runId: "RUN-037", techniqueId: "T1082",     variant: "Base",            result: "ALERT",    execMs: 420,  sysmonEvents: 5,  telemetry: { eid1: 2, eid3: 0, eid11: 1, eid13: 2 }, ts: "2026-09-04 14:25:44", commandLine: "systeminfo.exe & whoami" },
  { runId: "RUN-036", techniqueId: "T1055.012", variant: "VAR-1",           result: "NO_ALERT", execMs: 1870, sysmonEvents: 18, telemetry: { eid1: 5, eid3: 1, eid11: 0, eid13: 12 }, ts: "2026-09-04 14:22:01", commandLine: "inject_hollowing.ps1 -Target notepad.exe" },
];

const DEFAULT_VARIATIONS: Variation[] = [
  { id: "VAR-003", techniqueId: "T1059.001", method: "Rule-Based", description: "IEX with split string concat to avoid keyword matching",        status: "pending_review", source: "rule_based", strategy: "String Concatenation & Env Expansion" },
  { id: "VAR-002", techniqueId: "T1003.001", method: "Rule-Based", description: "NanoDump via reflective load — alternate syscall chain",          status: "approved",       source: "rule_based", strategy: "Reflective Loader / Forked Handle" },
  { id: "VAR-MAN-007",techniqueId: "T1059.001", method: "Manual",     description: "EncodedCommand flag with Base64 payload",                         status: "approved",       source: "manual" },
  { id: "VAR-MAN-006",techniqueId: "T1003.001", method: "Manual",     description: "comsvcs.dll MiniDump via rundll32",                               status: "approved",       source: "manual" },
  { id: "VAR-001", techniqueId: "T1078",     method: "Rule-Based", description: "RDP auth with renamed built-in account — rule only checks 'Admin'",status: "rejected",       source: "rule_based", strategy: "Account Parameter Substitution" },
];

const DEFAULT_BLINDSPOTS: BlindSpot[] = [
  { id: "BS-004", techniqueId: "T1003.001", variantId: "VAR-MAN-006", status: "open",   cause: "Rule matches direct sekurlsa::logonpasswords. comsvcs.dll MiniDump uses different call path.", sigmaRule: "sigma/cred_dump_lsass_direct.yml",      recommendation: "Add parent-process rule matching rundll32 → comsvcs.dll with MiniDump export." },
  { id: "BS-003", techniqueId: "T1059.001", variantId: "VAR-MAN-007", status: "patched",cause: "Rule requires raw invocation pattern; -EncodedCommand bypasses string match.",               sigmaRule: "sigma/powershell_exec.yml",             recommendation: "Match on EncodedCommand flag regardless of payload content. Rule updated." },
  { id: "BS-002", techniqueId: "T1055.012", variantId: "VAR-1",       status: "open",   cause: "No detection rule exists. Sysmon Event ID 10 fires but no sigma rule consumes it.",           sigmaRule: "—",                                    recommendation: "Author new rule on Sysmon EID 10 with hollow process memory-write heuristic." },
  { id: "BS-001", techniqueId: "T1027.002", variantId: "VAR-1",       status: "open",   cause: "Signature-based rule misses packed binaries with modified UPX headers.",                      sigmaRule: "sigma/suspicious_packed_binary.yml",   recommendation: "Supplement signature rule with entropy-based heuristic detection." },
];

const DEFAULT_MATRIX: Record<string, (boolean | null)[]> = {
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

// ── App Component ───────────────────────────────────────────────────────────

export default function App() {
  const [view, setView] = useState<View>("dashboard");
  const [backendOnline, setBackendOnline] = useState<boolean>(false);
  const [agentActive, setAgentActive] = useState<boolean>(false);
  const [agentMode, setAgentMode] = useState<string>("Initializing...");

  // Data states
  const [techniques, setTechniques] = useState<Technique[]>(DEFAULT_TECHNIQUES);
  const [runs, setRuns] = useState<RunLog[]>(DEFAULT_RUNS);
  const [variations, setVariations] = useState<Variation[]>(DEFAULT_VARIATIONS);
  const [blindspots, setBlindspots] = useState<BlindSpot[]>(DEFAULT_BLINDSPOTS);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [matrixData, setMatrixData] = useState<{
    matrix: Record<string, (boolean | null)[]>;
    columns: string[];
    coveragePct: number;
    totalCells: number;
    hitCells: number;
    fullyCovered: number;
    withGaps: number;
  }>({
    matrix: DEFAULT_MATRIX,
    columns: ["Base", "VAR-1", "VAR-2", "VAR-3", "VAR-4"],
    coveragePct: 46,
    totalCells: 28,
    hitCells: 13,
    fullyCovered: 2,
    withGaps: 8
  });

  const [selectedRun, setSelectedRun] = useState<RunLog | null>(DEFAULT_RUNS[0]);
  const [notification, setNotification] = useState<{ msg: string; type: "success" | "error" | "info" } | null>(null);

  // Poll backend health & refresh core data
  const refreshAllData = useCallback(async () => {
    try {
      const health = await api.fetchHealth();
      setBackendOnline(true);
      setAgentActive(health.agentConnected);
      setAgentMode(health.agentMode);

      // Fetch dynamic records
      const [techList, runList, varList, bsList, matrixRes, rulesList] = await Promise.allSettled([
        api.fetchTechniques(),
        api.fetchRuns(),
        api.fetchVariations(),
        api.fetchBlindSpots(),
        api.fetchCoverageMatrix(),
        api.fetchDetectionRules()
      ]);

      if (techList.status === "fulfilled" && techList.value.length) setTechniques(techList.value);
      if (runList.status === "fulfilled" && runList.value.length) {
        setRuns(runList.value);
        if (!selectedRun && runList.value.length) {
          setSelectedRun(runList.value[0]);
        }
      }
      if (varList.status === "fulfilled") setVariations(varList.value);
      if (bsList.status === "fulfilled") setBlindspots(bsList.value);
      if (matrixRes.status === "fulfilled") setMatrixData(matrixRes.value);
      if (rulesList.status === "fulfilled") setRules(rulesList.value);
    } catch {
      setBackendOnline(false);
      setAgentMode("Offline (Local Fallback)");
    }
  }, [selectedRun]);

  useEffect(() => {
    refreshAllData();
    const timer = setInterval(refreshAllData, 5000);
    return () => clearInterval(timer);
  }, [refreshAllData]);

  const showToast = (msg: string, type: "success" | "error" | "info" = "success") => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 4000);
  };

  // ── Sub-Views ─────────────────────────────────────────────────────────────

  // 1. Dashboard View
  function Dashboard() {
    return (
      <div className="space-y-6">
        {/* Stats row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-px bg-zinc-800">
          {[
            { label: "Detection Coverage", value: `${matrixData.coveragePct}%`, sub: `${matrixData.hitCells}/${matrixData.totalCells} test cells detected`, accent: true },
            { label: "ATT&CK Techniques", value: `${techniques.length}`, sub: "8–12 target scope" },
            { label: "Open Blind Spots", value: `${blindspots.filter(b => b.status === "open").length}`, sub: `${blindspots.filter(b => b.status === "patched").length} patched this cycle` },
            { label: "Evasion Variations", value: `${variations.length}`, sub: "Evasion variants active" },
          ].map(s => (
            <div key={s.label} className="bg-zinc-950 px-5 py-4">
              <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600 mb-1">{s.label}</div>
              <div className={`text-3xl font-bold font-mono tabular-nums ${s.accent ? "text-[#00d4aa]" : "text-zinc-100"}`}>{s.value}</div>
              <div className="text-[11px] text-zinc-600 mt-1">{s.sub}</div>
            </div>
          ))}
        </div>

        {/* Live System Status Banner */}
        <div className="border border-zinc-800 bg-zinc-950 px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className={`w-2 h-2 rounded-full ${backendOnline ? "bg-[#00d4aa] animate-pulse" : "bg-red-500"}`} />
            <div>
              <span className="text-[11px] font-mono text-zinc-300">
                DetectIQ Engine: <strong className={backendOnline ? "text-[#00d4aa]" : "text-red-400"}>{backendOnline ? "ONLINE" : "DISCONNECTED"}</strong>
              </span>
              <span className="text-[11px] font-mono text-zinc-600 ml-3">
                Agent: <span className="text-zinc-400">{agentMode}</span>
              </span>
            </div>
          </div>
          <button
            onClick={() => { refreshAllData(); showToast("Refreshed live data from API"); }}
            className="text-[10px] font-mono text-zinc-400 hover:text-[#00d4aa] border border-zinc-800 px-2.5 py-1 transition-colors"
          >
            ↻ Sync Now
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Recent Runs */}
          <div className="lg:col-span-2 border border-zinc-800">
            <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">Recent Executions</span>
              <span className="text-[10px] font-mono text-zinc-700">FastAPI · /api/runs</span>
            </div>
            <TableShell cols={["Run ID", "Technique", "Variant", "Sysmon Evts", "Exec Time", "Result"]}>
              {runs.slice(0, 7).map(r => (
                <tr
                  key={r.runId}
                  onClick={() => setSelectedRun(r)}
                  className={`border-b border-zinc-800/40 cursor-pointer transition-colors ${selectedRun?.runId === r.runId ? "bg-[#00d4aa]/10" : "hover:bg-zinc-800/20"}`}
                >
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

          {/* Architecture Stack */}
          <div className="border border-zinc-800">
            <div className="px-4 py-3 border-b border-zinc-800">
              <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">System Architecture</span>
            </div>
            <div className="p-4 space-y-3">
              {[
                { layer: "Frontend",   components: ["React 19", "Vite", "Tailwind CSS"] },
                { layer: "Backend",    components: ["FastAPI", "Python 3.14", "Uvicorn"] },
                { layer: "Storage",    components: ["SQLite / PostgreSQL Relational DB"] },
                { layer: "Telemetry",  components: ["Sysmon EID 1/3/11/13", "WinEvent"] },
                { layer: "Detection",  components: ["Sigma Rules", "Wazuh SIEM"] },
                { layer: "Variations", components: ["Heuristic Engine", "Obfuscation Rules"] },
                { layer: "Agent",      components: ["ExecutionAgent", "Sandbox"] },
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

        {/* Selected Run Telemetry Inspector */}
        {selectedRun && (
          <div className="border border-zinc-800 p-5 bg-zinc-950">
            <div className="flex items-center justify-between mb-3">
              <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">
                Telemetry Breakdown — {selectedRun.runId} ({selectedRun.techniqueId} · {selectedRun.variant})
              </div>
              <div className="flex items-center gap-3">
                <span className="text-[11px] font-mono text-zinc-500">Timestamp: {selectedRun.ts}</span>
                {resultBadge(selectedRun.result)}
              </div>
            </div>

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-px bg-zinc-800 mb-3">
              <div className="bg-zinc-900 px-4 py-3">
                <div className="font-mono text-[10px] text-zinc-500">EID 1</div>
                <div className="text-xl font-bold font-mono text-zinc-200">{selectedRun.telemetry?.eid1 ?? 4}</div>
                <div className="text-[11px] text-zinc-500">Process Create</div>
              </div>
              <div className="bg-zinc-900 px-4 py-3">
                <div className="font-mono text-[10px] text-zinc-500">EID 3</div>
                <div className="text-xl font-bold font-mono text-zinc-200">{selectedRun.telemetry?.eid3 ?? 0}</div>
                <div className="text-[11px] text-zinc-500">Network Connect</div>
              </div>
              <div className="bg-zinc-900 px-4 py-3">
                <div className="font-mono text-[10px] text-zinc-500">EID 11</div>
                <div className="text-xl font-bold font-mono text-zinc-200">{selectedRun.telemetry?.eid11 ?? 2}</div>
                <div className="text-[11px] text-zinc-500">File Create</div>
              </div>
              <div className="bg-zinc-900 px-4 py-3">
                <div className="font-mono text-[10px] text-zinc-500">EID 13</div>
                <div className="text-xl font-bold font-mono text-zinc-200">{selectedRun.telemetry?.eid13 ?? 8}</div>
                <div className="text-[11px] text-zinc-500">Registry Set</div>
              </div>
            </div>

            <div className="p-3 bg-zinc-900 border border-zinc-800 text-[11px] font-mono space-y-1">
              <div className="text-zinc-500">Executed Command String:</div>
              <div className="text-[#00d4aa] break-all">{selectedRun.commandLine || `Payload executed for ${selectedRun.techniqueId}`}</div>
            </div>
          </div>
        )}

        {/* Milestones */}
        <div className="border border-zinc-800">
          <div className="px-4 py-3 border-b border-zinc-800">
            <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">Delivery Milestones</span>
          </div>
          <div className="p-4 grid grid-cols-2 lg:grid-cols-4 gap-2">
            {[
              { d: "D1", label: "Architecture",          date: "09/04/26", done: true  },
              { d: "D2", label: "Test Environment",       date: "10/02/26", done: true  },
              { d: "D3", label: "Test Framework",         date: "10/16/26", done: true  },
              { d: "D4", label: "Initial Coverage Eval",  date: "10/30/26", done: true  },
              { d: "D5", label: "Blind-Spot Analysis",    date: "11/13/26", done: false },
              { d: "D6", label: "Improvement Validation", date: "11/20/26", done: false },
              { d: "D7", label: "Variation Prototype", date: "11/27/26", done: true  },
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

  // 2. Execute View
  function ExecuteView() {
    const [selected, setSelected] = useState<string[]>(["T1059.001"]);
    const [variantType, setVariantType] = useState<string>("Base");
    const [running, setRunning] = useState(false);

    const toggle = (id: string) =>
      setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]);

    const selectAll = () => setSelected(techniques.map(t => t.id));
    const clearAll = () => setSelected([]);

    const handleRun = async () => {
      if (!selected.length) return;
      setRunning(true);
      try {
        const res = await api.executeTests(selected, variantType);
        showToast(`Successfully executed ${selected.length} test(s)! Mode: ${res.mode}`);
        await refreshAllData();
      } catch (err: any) {
        showToast(err.message || "Execution failed", "error");
      } finally {
        setRunning(false);
      }
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

        {/* Inputs panel */}
        <div className="border border-zinc-800 p-5 bg-zinc-950">
          <div className="flex items-center justify-between mb-3">
            <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600">Select Test Cases</div>
            <div className="flex gap-2">
              <button onClick={selectAll} className="text-[10px] font-mono text-zinc-400 hover:text-[#00d4aa]">Select All</button>
              <span className="text-zinc-700">·</span>
              <button onClick={clearAll} className="text-[10px] font-mono text-zinc-400 hover:text-red-400">Clear</button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-px bg-zinc-800 mb-4">
            {techniques.map(t => {
              const active = selected.includes(t.id);
              return (
                <button
                  key={t.id}
                  onClick={() => toggle(t.id)}
                  className={`flex items-center gap-3 px-4 py-3 text-left transition-colors ${
                    active ? "bg-[#00d4aa]/8 border-l-2 border-[#00d4aa]" : "bg-zinc-950 hover:bg-zinc-900 border-l-2 border-transparent"
                  }`}
                >
                  <div className={`w-3 h-3 border ${active ? "bg-[#00d4aa] border-[#00d4aa]" : "border-zinc-700"} flex items-center justify-center`}>
                    {active && <span className="text-zinc-950 text-[9px] font-bold">✓</span>}
                  </div>
                  <div className="flex-1 min-w-0">
                    <span className="font-mono text-[12px] text-[#00d4aa]">{t.id}</span>
                    <span className="text-[12px] text-zinc-300 ml-2">{t.name}</span>
                    <div className="text-[10px] text-zinc-600 truncate">{t.tactic}</div>
                  </div>
                  <Badge
                    label={t.severity}
                    color={t.severity === "critical" ? "red" : t.severity === "high" ? "amber" : t.severity === "medium" ? "blue" : "zinc"}
                  />
                </button>
              );
            })}
          </div>

          {/* Execution Configuration */}
          <div className="flex flex-wrap items-center gap-4 pt-2 border-t border-zinc-800/60">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-zinc-500 uppercase">Variant:</span>
              <select
                value={variantType}
                onChange={e => setVariantType(e.target.value)}
                className="bg-zinc-900 border border-zinc-700 text-zinc-200 font-mono text-[11px] px-2.5 py-1.5 focus:border-[#00d4aa] focus:outline-none"
              >
                <option value="Base">Base Standard Payload</option>
                <option value="VAR-1">VAR-1 (Evasion Heuristic)</option>
                <option value="VAR-2">VAR-2 (Reflective / Minidump)</option>
                <option value="VAR-3">VAR-3 (Encoded / Obfuscated)</option>
                <option value="VAR-4">VAR-4 (LOLBin Native)</option>
              </select>
            </div>

            <button
              onClick={handleRun}
              disabled={!selected.length || running}
              className="border border-[#00d4aa] text-[#00d4aa] font-mono text-[11px] px-4 py-2 uppercase tracking-wide hover:bg-[#00d4aa]/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {running && <span className="w-2 h-2 rounded-full bg-[#00d4aa] animate-ping" />}
              {running ? "Detonating & Polling SIEM..." : `Run ${selected.length || 0} Test${selected.length !== 1 ? "s" : ""}`}
            </button>

            <span className="text-[11px] font-mono text-zinc-600">
              Host Target: <span className="text-zinc-400">lab-dc01 (Windows 10/Server 2022)</span>
            </span>
          </div>
        </div>

        {/* Execution Output Table */}
        <div className="border border-zinc-800">
          <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">Outputs — Execution Log</span>
            <span className="text-[10px] font-mono text-zinc-700">Live Database · {runs.length} runs</span>
          </div>
          <TableShell cols={["Run ID", "Technique", "Variant", "Exec Time", "Sysmon Events", "SIEM Status", "Timestamp"]}>
            {runs.map(r => (
              <tr
                key={r.runId}
                onClick={() => setSelectedRun(r)}
                className={`border-b border-zinc-800/40 cursor-pointer transition-colors ${selectedRun?.runId === r.runId ? "bg-[#00d4aa]/10" : "hover:bg-zinc-800/20"}`}
              >
                <td className="px-4 py-3 font-mono text-[11px] text-zinc-500">{r.runId}</td>
                <td className="px-4 py-3 font-mono text-[12px] text-[#00d4aa]">{r.techniqueId}</td>
                <td className="px-4 py-3 text-[12px] text-zinc-300">{r.variant}</td>
                <td className="px-4 py-3 font-mono text-[12px] text-zinc-400 tabular-nums">{r.execMs ? `${r.execMs} ms` : "—"}</td>
                <td className="px-4 py-3 font-mono text-[12px] text-zinc-400 tabular-nums">{r.sysmonEvents ?? "—"}</td>
                <td className="px-4 py-3">{resultBadge(r.result)}</td>
                <td className="px-4 py-3 font-mono text-[11px] text-zinc-600">{r.ts}</td>
              </tr>
            ))}
          </TableShell>
        </div>

        {/* Live Sysmon Telemetry Details */}
        {selectedRun && (
          <div className="border border-zinc-800 p-5 bg-zinc-950">
            <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-500 mb-3">
              Sysmon Telemetry — {selectedRun.runId} ({selectedRun.techniqueId} · {selectedRun.variant})
            </div>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-px bg-zinc-800 mb-3">
              {[
                { eid: "EID 1",  label: "Process Create",   count: selectedRun.telemetry?.eid1 ?? 4 },
                { eid: "EID 3",  label: "Network Connect",  count: selectedRun.telemetry?.eid3 ?? 0 },
                { eid: "EID 11", label: "File Create",       count: selectedRun.telemetry?.eid11 ?? 2 },
                { eid: "EID 13", label: "Registry Set",      count: selectedRun.telemetry?.eid13 ?? 8 },
              ].map(e => (
                <div key={e.eid} className="bg-zinc-900 px-4 py-3">
                  <div className="font-mono text-[10px] text-zinc-500 mb-1">{e.eid}</div>
                  <div className="text-xl font-bold font-mono text-zinc-200 tabular-nums">{e.count}</div>
                  <div className="text-[11px] text-zinc-500 mt-0.5">{e.label}</div>
                </div>
              ))}
            </div>
            <div className="text-[11px] font-mono text-zinc-400">
              Command line: <code className="text-[#00d4aa]">{selectedRun.commandLine || `Execution of ${selectedRun.techniqueId}`}</code>
            </div>
          </div>
        )}
      </div>
    );
  }

  // 3. Variations View
  function VariationsView() {
    const [strategy, setStrategy] = useState("");
    const [method, setMethod] = useState("Rule-Based Obfuscation");
    const [techId, setTechId] = useState("T1059.001");
    const [generating, setGenerating] = useState(false);

    const PRESET_STRATEGIES: Record<string, string[]> = {
      "T1059.001": [
        "String Concatenation & Env Expansion",
        "Base64 Obfuscation & Flag Formatting",
        "Unmanaged Runspace Execution"
      ],
      "T1003.001": [
        "Reflective Loader / Forked Handle",
        "LOLBin Ordinal Invocation (#24)",
        "Direct NT Syscall Invocations"
      ],
      "T1055.012": [
        "Early Bird APC Injection",
        "Section Unmapping & Injection"
      ],
      "T1078": [
        "Account Parameter Substitution",
        "WinRM Kerberos Ticket Passthrough"
      ],
      "T1021.001": [
        "Encrypted Port-Forward Tunneling"
      ],
      "T1027.002": [
        "Header Scrambling & Strip Overlays"
      ],
      "T1082": [
        "CIM/WMI API Invocation"
      ],
      "T1105": [
        "RFC 2397 Data URI Encoding"
      ],
      "T1569.002": [
        "Service Masquerading"
      ],
      "T1136.001": [
        "ADSI COM Object Invocation"
      ]
    };

    const handleGen = async () => {
      setGenerating(true);
      try {
        const variant = await api.generateVariation(techId, strategy, method);
        showToast(`Generated variant ${variant.id}! Added to repository for review.`);
        setStrategy("");
        await refreshAllData();
      } catch (err: any) {
        showToast(err.message || "Failed to generate variation", "error");
      } finally {
        setGenerating(false);
      }
    };

    const handleStatus = async (id: string, status: "approved" | "rejected") => {
      try {
        await api.updateVariationStatus(id, status);
        showToast(`Variant ${id} marked as ${status}`);
        await refreshAllData();
      } catch (err: any) {
        showToast(err.message || "Failed to update status", "error");
      }
    };

    const handleRunVariation = async (v: Variation) => {
      try {
        showToast(`Scheduling execution for ${v.id} (${v.techniqueId})...`, "info");
        await api.executeTests([v.techniqueId], v.id, v.id, v.payload);
        showToast(`Variation ${v.id} executed successfully! Matrix updated.`);
        await refreshAllData();
      } catch (err: any) {
        showToast(err.message || "Failed to execute variant", "error");
      }
    };

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

        {/* Input panel */}
        <div className="border border-zinc-800 p-5 bg-zinc-950">
          <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600 mb-3">Adversarial Variation Generator</div>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="text-[10px] font-mono text-zinc-600 uppercase tracking-wide block mb-1.5">Base Technique</label>
              <select
                value={techId}
                onChange={e => setTechId(e.target.value)}
                className="w-full bg-zinc-900 border border-zinc-700 text-zinc-300 font-mono text-[12px] px-3 py-2 focus:outline-none focus:border-[#00d4aa]"
              >
                {techniques.map(t => (
                  <option key={t.id} value={t.id}>{t.id} — {t.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[10px] font-mono text-zinc-600 uppercase tracking-wide block mb-1.5">Evasion Method</label>
              <select
                value={method}
                onChange={e => setMethod(e.target.value)}
                className="w-full bg-zinc-900 border border-zinc-700 text-zinc-300 font-mono text-[12px] px-3 py-2 focus:outline-none focus:border-[#00d4aa]"
              >
                <option value="Rule-Based Obfuscation">Rule-Based Obfuscation</option>
                <option value="LOLBin Substitution">LOLBin Substitution</option>
                <option value="Reflective / Memory Injection">Reflective / Memory Injection</option>
                <option value="Protocol / Parameter Alternate">Protocol / Parameter Alternate</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] font-mono text-zinc-600 uppercase tracking-wide block mb-1.5">Strategy / Parameters</label>
              <input
                value={strategy}
                onChange={e => setStrategy(e.target.value)}
                placeholder="e.g. split string concat, ordinal #24, forked handle..."
                className="w-full bg-zinc-900 border border-zinc-700 text-zinc-300 font-mono text-[12px] px-3 py-2 placeholder-zinc-700 focus:outline-none focus:border-[#00d4aa]"
              />
            </div>
          </div>

          {/* Quick Preset Strategies */}
          {PRESET_STRATEGIES[techId] && (
            <div className="mb-4">
              <span className="text-[10px] font-mono text-zinc-600 mr-2 uppercase">Presets:</span>
              <div className="flex flex-wrap gap-2 mt-1.5">
                {PRESET_STRATEGIES[techId].map((s, i) => (
                  <button
                    key={i}
                    onClick={() => setStrategy(s)}
                    className="text-[10px] font-mono bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-[#00d4aa] hover:border-[#00d4aa]/40 px-2 py-1 text-left transition-colors"
                  >
                    "{s}"
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className="flex items-center gap-4">
            <button
              onClick={handleGen}
              disabled={generating}
              className="border border-[#00d4aa] text-[#00d4aa] font-mono text-[11px] px-4 py-2 uppercase tracking-wide hover:bg-[#00d4aa]/10 transition-colors disabled:opacity-40 flex items-center gap-2"
            >
              {generating && <span className="w-2 h-2 rounded-full bg-[#00d4aa] animate-ping" />}
              {generating ? "Generating Variant..." : "Generate Evasion Variant"}
            </button>
            <span className="text-[10px] font-mono text-zinc-600">
              Req 7: All generated evasion variants require manual validation before execution.
            </span>
          </div>
        </div>

        {/* Variations Repository Table */}
        <div className="border border-zinc-800">
          <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">Outputs — Variation Repository</span>
            <span className="text-[10px] font-mono text-zinc-700">PostgreSQL / SQLite · {variations.length} records</span>
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
              {variations.map(v => (
                <tr key={v.id} className="border-b border-zinc-800/40 hover:bg-zinc-800/20 transition-colors">
                  <td className="px-4 py-3 font-mono text-[11px] text-zinc-500">{v.id}</td>
                  <td className="px-4 py-3 font-mono text-[12px] text-[#00d4aa]">{v.techniqueId}</td>
                  <td className="px-4 py-3">
                    <Badge
                      label={v.source === "manual" ? "Manual" : "Rule-Based"}
                      color={v.source === "manual" ? "zinc" : "blue"}
                    />
                  </td>
                  <td className="px-4 py-3 text-[12px] text-zinc-300 max-w-md">
                    <div>{v.description}</div>
                    {v.payload && (
                      <code className="text-[10px] font-mono text-zinc-500 block truncate mt-0.5">{v.payload}</code>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <Badge
                      label={v.status.replace("_", " ")}
                      color={v.status === "approved" ? "green" : v.status === "rejected" ? "red" : "amber"}
                    />
                  </td>
                  <td className="px-4 py-3">
                    {v.status === "pending_review" ? (
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleStatus(v.id, "approved")}
                          className="text-[10px] font-mono text-emerald-400 border border-emerald-900 px-2 py-0.5 hover:border-emerald-700 transition-colors"
                        >
                          Approve
                        </button>
                        <button
                          onClick={() => handleStatus(v.id, "rejected")}
                          className="text-[10px] font-mono text-red-400 border border-red-900 px-2 py-0.5 hover:border-red-700 transition-colors"
                        >
                          Reject
                        </button>
                      </div>
                    ) : v.status === "approved" ? (
                      <button
                        onClick={() => handleRunVariation(v)}
                        className="text-[10px] font-mono text-[#00d4aa] border border-[#00d4aa]/30 px-2 py-0.5 hover:border-[#00d4aa]/60 hover:bg-[#00d4aa]/10 transition-colors"
                      >
                        Run Test
                      </button>
                    ) : (
                      <span className="text-[11px] text-zinc-700 font-mono">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  // 4. Re-Evaluation View
  function ReEvaluateView() {
    const [evaluating, setEvaluating] = useState(false);

    const handleReEvaluate = async () => {
      setEvaluating(true);
      try {
        const res = await api.runReEvaluation();
        showToast(`Re-evaluation complete! ${res.blindSpotsPatched} blind spots patched.`);
        await refreshAllData();
      } catch (err: any) {
        showToast(err.message || "Re-evaluation failed", "error");
      } finally {
        setEvaluating(false);
      }
    };

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
          {/* Inputs */}
          <div className="border border-zinc-800 p-5 space-y-4 bg-zinc-950">
            <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600">Inputs — Rules & Baselines</div>

            <div>
              <div className="text-[10px] font-mono text-zinc-600 uppercase tracking-wide mb-2">Modified Detection Rules</div>
              <div className="space-y-2">
                {(rules.length ? rules : [
                  { ruleFile: "sigma/powershell_exec.yml",          modified: true,  change: "Added EncodedCommand pattern", benign: "Normal PS scripts", falsePositive: false, ruleName: "PowerShell Suspicious", techniqueId: "T1059.001" },
                  { ruleFile: "sigma/cred_dump_lsass_direct.yml",   modified: false, change: "Pending — add comsvcs parent rule", benign: "Windows Update", falsePositive: false, ruleName: "LSASS Access", techniqueId: "T1003.001" },
                  { ruleFile: "sigma/suspicious_packed_binary.yml", modified: false, change: "Pending — add entropy heuristic", benign: "AV engine scan", falsePositive: false, ruleName: "Packed Binary", techniqueId: "T1027.002" },
                  { ruleFile: "sigma/process_hollowing.yml",        modified: false, change: "New — in development", benign: "Browser launch", falsePositive: true, ruleName: "Process Hollowing", techniqueId: "T1055.012" },
                ]).map(r => (
                  <div key={r.ruleFile} className={`flex items-start gap-3 p-3 border ${r.modified ? "border-[#00d4aa]/30 bg-[#00d4aa]/5" : "border-zinc-800"}`}>
                    <div className={`w-1.5 h-1.5 rounded-full mt-1 flex-shrink-0 ${r.modified ? "bg-[#00d4aa]" : "bg-zinc-700"}`} />
                    <div className="min-w-0 flex-1">
                      <code className="font-mono text-[11px] text-zinc-300 block truncate">{r.ruleFile}</code>
                      <span className="text-[11px] text-zinc-500">{r.change}</span>
                    </div>
                    {r.modified && <Badge label="updated" color="teal" />}
                  </div>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[10px] font-mono text-zinc-600 uppercase tracking-wide mb-2">Benign Baseline Activities (False Positive Control)</div>
              <div className="space-y-1.5 bg-zinc-900 p-3 border border-zinc-800">
                {["Normal user login / logout cycle", "Windows Update telemetry process", "Browser HTTP/S traffic & sandboxed renderer", "File open / save in Office productivity apps"].map(b => (
                  <div key={b} className="flex items-center gap-2">
                    <div className="w-1 h-1 bg-[#00d4aa] rounded-full" />
                    <span className="text-[11px] text-zinc-400">{b}</span>
                  </div>
                ))}
              </div>
            </div>

            <button
              onClick={handleReEvaluate}
              disabled={evaluating}
              className="border border-[#00d4aa] text-[#00d4aa] font-mono text-[11px] px-4 py-2.5 uppercase tracking-wide hover:bg-[#00d4aa]/10 transition-colors w-full flex items-center justify-center gap-2 disabled:opacity-40"
            >
              {evaluating && <span className="w-2 h-2 rounded-full bg-[#00d4aa] animate-ping" />}
              {evaluating ? "Evaluating Rules & Benign Baselines..." : "Run Re-Evaluation"}
            </button>
          </div>

          {/* Outputs */}
          <div className="space-y-4">
            <div className="border border-zinc-800 p-5 bg-zinc-950">
              <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600 mb-3">Outputs — Blind Spots</div>
              <div className="space-y-3">
                {blindspots.map(b => (
                  <div key={b.id} className={`border p-4 ${b.status === "open" ? "border-red-900/50 bg-red-950/10" : "border-emerald-900/40 bg-emerald-950/10"}`}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[11px] text-zinc-500">{b.id}</span>
                        <span className="font-mono text-[12px] text-[#00d4aa]">{b.techniqueId}</span>
                        <span className="text-[11px] font-mono text-zinc-400">({b.variantId})</span>
                      </div>
                      <Badge label={b.status} color={b.status === "open" ? "red" : "green"} />
                    </div>
                    <p className="text-[11px] text-zinc-300 leading-relaxed mb-2">{b.cause}</p>
                    <div className="text-[11px] text-zinc-500 border-l-2 border-zinc-800 pl-2">
                      <strong>Fix:</strong> {b.recommendation}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* False positive check */}
            <div className="border border-zinc-800 p-5 bg-zinc-950">
              <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600 mb-3">False Positive Evaluation</div>
              <div className="space-y-2">
                {[
                  { rule: "sigma/powershell_exec.yml",        benign: "Normal PS scripts", fp: false },
                  { rule: "sigma/cred_dump_lsass_direct.yml", benign: "Windows Update",    fp: false },
                  { rule: "sigma/process_hollowing.yml",      benign: "Browser launch",    fp: true  },
                ].map(row => (
                  <div key={row.rule} className="flex items-center gap-3 p-2 bg-zinc-900 border border-zinc-800/50">
                    <Badge label={row.fp ? "FP" : "clean"} color={row.fp ? "amber" : "green"} />
                    <code className="font-mono text-[11px] text-zinc-400 truncate flex-1">{row.rule}</code>
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

  // 5. Matrix View
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
            <div className="text-2xl font-bold font-mono text-[#00d4aa] tabular-nums">{matrixData.coveragePct}%</div>
            <div className="text-[11px] text-zinc-600">{matrixData.hitCells}/{matrixData.totalCells} test cells</div>
          </div>
          <div className="bg-zinc-950 px-4 py-3">
            <div className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest mb-1">Techniques Fully Covered</div>
            <div className="text-2xl font-bold font-mono text-zinc-100 tabular-nums">
              {matrixData.fullyCovered}
            </div>
            <div className="text-[11px] text-zinc-600">of {techniques.length} techniques</div>
          </div>
          <div className="bg-zinc-950 px-4 py-3">
            <div className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest mb-1">Techniques with Gaps</div>
            <div className="text-2xl font-bold font-mono text-red-400 tabular-nums">
              {matrixData.withGaps}
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
                {matrixData.columns.map(c => (
                  <th key={c} className="px-3 py-3 text-center text-[10px] font-mono uppercase tracking-widest text-zinc-600">{c}</th>
                ))}
                <th className="px-4 py-3 text-center text-[10px] font-mono uppercase tracking-widest text-zinc-600">Score</th>
              </tr>
            </thead>
            <tbody>
              {techniques.map(t => {
                const row = matrixData.matrix[t.id] || [null, null, null, null, null];
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
                            ? <span className="inline-flex w-5 h-5 items-center justify-center bg-[#00d4aa]/15 border border-[#00d4aa]/40 text-[#00d4aa] text-[10px] font-bold" title="SIEM Alert Detected">✓</span>
                            : <span className="inline-flex w-5 h-5 items-center justify-center bg-red-900/25 border border-red-800/40 text-red-400 text-[10px] font-bold" title="Evaded Detection">✗</span>
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

        <div className="flex items-center justify-between pt-2">
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

          <button
            onClick={() => { refreshAllData(); showToast("Coverage matrix refreshed!"); }}
            className="text-[10px] font-mono text-zinc-400 hover:text-[#00d4aa] border border-zinc-800 px-3 py-1.5 transition-colors"
          >
            ↻ Refresh Matrix
          </button>
        </div>
      </div>
    );
  }

  // ── Navigation Items ──────────────────────────────────────────────────────

  const NAV: { id: View; label: string; useCase?: string }[] = [
    { id: "dashboard",   label: "Dashboard" },
    { id: "execute",     label: "Test Execution",  useCase: "UC-1" },
    { id: "variations",  label: "Variations",       useCase: "UC-2" },
    { id: "reevaluate",  label: "Re-Evaluation",    useCase: "UC-3" },
    { id: "matrix",      label: "Coverage Matrix",  useCase: "UC-4" },
  ];

  return (
    <div className="flex h-screen bg-[#09090b] text-zinc-200 overflow-hidden" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>
      {/* Toast Notification */}
      {notification && (
        <div className={`fixed top-4 right-4 z-50 border px-4 py-2 font-mono text-[12px] shadow-lg backdrop-blur transition-all ${
          notification.type === "success" ? "bg-emerald-950/90 border-[#00d4aa] text-[#00d4aa]" :
          notification.type === "error" ? "bg-red-950/90 border-red-800 text-red-400" :
          "bg-zinc-900/90 border-zinc-700 text-zinc-200"
        }`}>
          {notification.msg}
        </div>
      )}

      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 border-r border-zinc-800 flex flex-col bg-zinc-950/50">
        <div className="px-5 py-5 border-b border-zinc-800">
          <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-600 mb-1">Capstone · RAD v1</div>
          <div className="text-[14px] font-semibold text-zinc-100 flex items-center gap-1.5">
            DetectIQ
            <span className={`w-1.5 h-1.5 rounded-full ${backendOnline ? "bg-[#00d4aa]" : "bg-zinc-600"}`} />
          </div>
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

        {/* Actors */}
        <div className="px-5 py-4 border-t border-zinc-800 space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-widest text-zinc-700">Team & Actors</div>
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-[#00d4aa]" />
            <span className="text-[11px] text-zinc-500">Security Team (Evaluator)</span>
          </div>
          <div className="pt-2 text-[10px] font-mono text-zinc-700">Nathan Amend · Alex Lap</div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 overflow-y-auto flex flex-col">
        <header className="border-b border-zinc-800 px-8 py-4 flex items-center justify-between sticky top-0 bg-[#09090b]/95 backdrop-blur z-10">
          <div>
            <h1 className="text-sm font-semibold text-zinc-100">{NAV.find(n => n.id === view)?.label}</h1>
            <p className="text-[10px] font-mono text-zinc-600">MITRE ATT&CK · Sysmon · FastAPI · SQLite/PostgreSQL · React</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <div className={`w-1.5 h-1.5 rounded-full ${backendOnline ? "bg-[#00d4aa] animate-pulse" : "bg-red-500"}`} />
              <span className="text-[11px] font-mono text-zinc-500">
                {backendOnline ? (agentActive ? "lab-dc01 (Agent Active)" : "Built-in Engine") : "Backend Offline"}
              </span>
            </div>
            <span className="text-[11px] font-mono text-zinc-700">2026-10-25</span>
          </div>
        </header>

        <div className="px-8 py-6 flex-1">
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
