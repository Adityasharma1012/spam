export type Verdict = 'PHISHING' | 'SPAM' | 'SUSPICIOUS' | 'LEGITIMATE' | 'ABSTAIN';
export type ConsensusVerdict = 'PHISHING' | 'SPAM' | 'SUSPICIOUS' | 'LEGITIMATE' | 'NEEDS_REVIEW';
export type CalibrationStatus = 'UNVALIDATED' | 'DEMO_ONLY' | 'VALIDATED';
export type AvailabilityStatus = 'AVAILABLE' | 'DEGRADED' | 'UNAVAILABLE';
export type EvidenceCategory =
  | 'HEADER_MISMATCH'
  | 'RECEIVED_CHAIN'
  | 'AUTH_RESULTS'
  | 'URL_ANALYSIS'
  | 'ATTACHMENT_ANALYSIS'
  | 'IP_REPUTATION'
  | 'CONTENT_ANOMALY'
  | 'PROMPT_INJECTION'
  | 'GEOLOCATION';

export interface InvestigationSummary {
  investigation_id: string;
  email_sha256: string;
  receipt_time_utc: string;
  source: string;
  final_verdict?: ConsensusVerdict | null;
  confidence?: number | null;
  evidence_count: number;
  state_hash: string;
}

export interface Finding {
  text: string;
  evidence_ids: string[];
}

export interface AgentReport {
  agent_id: 'ml' | 'gemini' | 'laya';
  round: number;
  protocol_version: string;
  verdict: Verdict;
  confidence: number;
  calibration_status: CalibrationStatus;
  findings: Finding[];
  limitations: string[];
  availability: AvailabilityStatus;
  availability_reason?: string;
  created_at: string;
  model_identifiers: Record<string, any>;
  raw_output?: Record<string, any>;
  revised_from_round1?: boolean;
}

export interface EvidenceItem {
  evidence_id: string;
  category: string;
  description: string;
  source: string;
  parser_version: string;
  provenance: string;
  raw_data?: Record<string, any>;
  defanged_data?: Record<string, any>;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface DebateMessage {
  from_agent: string;
  round: number;
  summary: string;
  cited_evidence_ids: string[];
  created_at: string;
}

export interface ConsensusResult {
  final_verdict: ConsensusVerdict;
  confidence: number;
  reasons: string[];
  partial: boolean;
  matched_rule_id: string;
  agent_verdicts: Record<string, Verdict | null>;
  prompt_injection_detected: boolean;
  created_at: string;
}

export interface InvestigationState {
  investigation_id: string;
  email_sha256: string;
  receipt_time_utc: string;
  source: string;
  parser_version: string;
  evidence: EvidenceItem[];
  reports: AgentReport[];
  debate_messages: DebateMessage[];
  final_result?: ConsensusResult;
  state_hash?: string;
}

export interface AgentStatusInfo {
  agent_id: string;
  name: string;
  availability: AvailabilityStatus;
  availability_reason?: string;
  calibration_status: CalibrationStatus;
  details: Record<string, any>;
}

export interface HealthResponse {
  status: string;
  agents: AgentStatusInfo[];
  system_info: Record<string, any>;
}

export interface SampleEmailItem {
  id: string;
  filename: string;
  category: string;
}

export interface DecisionRuleInfo {
  rule_id: string;
  name: string;
  description: string;
  outcome: string;
  confidence: number;
  partial: boolean;
}
