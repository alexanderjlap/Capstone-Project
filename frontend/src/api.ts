const API_BASE = "http://127.0.0.1:8000/api";

export interface Technique {
  id: string;
  name: string;
  tactic: string;
  severity: "critical" | "high" | "medium" | "low";
  description?: string;
  defaultPayload?: string;
}

export type ExecResult = "ALERT" | "NO_ALERT" | "ERROR" | "RUNNING" | "QUEUED";

export interface TelemetryBreakdown {
  eid1: number;
  eid3: number;
  eid11: number;
  eid13: number;
}

export interface RunLog {
  runId: string;
  techniqueId: string;
  variant: string;
  variantId?: string | null;
  result: ExecResult;
  execMs: number | null;
  sysmonEvents: number | null;
  telemetry?: TelemetryBreakdown;
  commandLine?: string | null;
  parentProcess?: string | null;
  alertGenerated?: boolean | null;
  latency?: number | null;
  ts: string;
  error?: string | null;
}

export interface Variation {
  id: string;
  techniqueId: string;
  method: string;
  description: string;
  status: "pending_review" | "approved" | "rejected";
  source: "manual" | "rule_based" | string;
  strategy?: string;
  llmPrompt?: string;
  payload?: string;
  createdAt?: string;
}

export interface BlindSpot {
  id: string;
  techniqueId: string;
  variantId: string;
  status: "open" | "patched";
  cause: string;
  sigmaRule: string;
  recommendation: string;
}

export interface DetectionRule {
  ruleFile: string;
  ruleName: string;
  techniqueId: string;
  modified: boolean;
  change: string;
  benign: string;
  falsePositive: boolean;
}

export interface MatrixResponse {
  matrix: Record<string, (boolean | null)[]>;
  columns: string[];
  totalCells: number;
  hitCells: number;
  coveragePct: number;
  fullyCovered: number;
  withGaps: number;
}

export interface DashboardStats {
  coveragePct: number;
  totalCells: number;
  hitCells: number;
  techniquesCount: number;
  openBlindSpots: number;
  variantsGenerated?: number;
  aiVariantsGenerated?: number;
  agentConnected: boolean;
  recentRuns: RunLog[];
}

export async function fetchHealth(): Promise<{ status: string; agentConnected: boolean; agentMode: string }> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error("Health check failed");
  return res.json();
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const res = await fetch(`${API_BASE}/dashboard/stats`);
  if (!res.ok) throw new Error("Failed to fetch dashboard stats");
  return res.json();
}

export async function fetchTechniques(): Promise<Technique[]> {
  const res = await fetch(`${API_BASE}/techniques`);
  if (!res.ok) throw new Error("Failed to fetch techniques");
  return res.json();
}

export async function fetchRuns(): Promise<RunLog[]> {
  const res = await fetch(`${API_BASE}/runs`);
  if (!res.ok) throw new Error("Failed to fetch runs");
  return res.json();
}

export async function executeTests(
  techniqueIDs: string[],
  variant: string = "Base",
  variantId?: string,
  customPayload?: string
): Promise<any> {
  const res = await fetch(`${API_BASE}/runs/execute`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      techniqueIDs,
      variant,
      variantId,
      customPayload,
      autoExecute: true
    })
  });
  if (!res.ok) throw new Error("Failed to execute tests");
  return res.json();
}

export async function fetchVariations(techniqueId?: string): Promise<Variation[]> {
  const url = techniqueId
    ? `${API_BASE}/variations?techniqueId=${encodeURIComponent(techniqueId)}`
    : `${API_BASE}/variations`;
  const res = await fetch(url);
  if (!res.ok) throw new Error("Failed to fetch variations");
  return res.json();
}

export async function generateVariation(baseTechnique: string, strategy: string = "", method: string = "Rule-Based"): Promise<Variation> {
  const res = await fetch(`${API_BASE}/variations/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ baseTechnique, strategy, prompt: strategy, method })
  });
  if (!res.ok) throw new Error("Failed to generate variation");
  const data = await res.json();
  return data.variant;
}

export async function updateVariationStatus(
  id: string,
  status: "approved" | "rejected" | "pending_review"
): Promise<void> {
  const res = await fetch(`${API_BASE}/variations/${encodeURIComponent(id)}/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status })
  });
  if (!res.ok) throw new Error("Failed to update status");
}

export async function fetchBlindSpots(): Promise<BlindSpot[]> {
  const res = await fetch(`${API_BASE}/blindspots`);
  if (!res.ok) throw new Error("Failed to fetch blindspots");
  return res.json();
}

export async function fetchDetectionRules(): Promise<DetectionRule[]> {
  const res = await fetch(`${API_BASE}/detections/rules`);
  if (!res.ok) throw new Error("Failed to fetch detection rules");
  return res.json();
}

export async function runReEvaluation(): Promise<any> {
  const res = await fetch(`${API_BASE}/detections/reevaluate`, {
    method: "POST"
  });
  if (!res.ok) throw new Error("Failed to run re-evaluation");
  return res.json();
}

export async function fetchCoverageMatrix(): Promise<MatrixResponse> {
  const res = await fetch(`${API_BASE}/coverage/matrix`);
  if (!res.ok) throw new Error("Failed to fetch coverage matrix");
  return res.json();
}

