import { z } from 'zod';

// =====================================================================
// 1. Zod Schemas for Runtime Validation
// =====================================================================

export const VerdictSchema = z.enum([
  'PHISHING',
  'SPAM',
  'SUSPICIOUS',
  'LEGITIMATE',
  'ABSTAIN',
]);

export const ConsensusVerdictSchema = z.enum([
  'PHISHING',
  'SPAM',
  'SUSPICIOUS',
  'LEGITIMATE',
  'NEEDS_REVIEW',
]);

export const CalibrationStatusSchema = z.enum([
  'UNVALIDATED',
  'DEMO_ONLY',
  'VALIDATED',
]);

export const AvailabilityStatusSchema = z.enum([
  'AVAILABLE',
  'DEGRADED',
  'UNAVAILABLE',
]);

export const EvidenceCategorySchema = z.enum([
  'HEADER_MISMATCH',
  'AUTH_RESULTS',
  'RECEIVED_CHAIN',
  'ATTACHMENT_ANALYSIS',
  'URL_ANALYSIS',
  'PROMPT_INJECTION',
  'IP_REPUTATION',
]);

export const EvidenceSeveritySchema = z.enum([
  'INFO',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
]);

export const EvidenceItemSchema = z.object({
  evidence_id: z.string(),
  category: EvidenceCategorySchema,
  description: z.string(),
  source: z.string(),
  parser_version: z.string(),
  provenance: z.string(),
  raw_data: z.record(z.string(), z.any()).default({}),
  defanged_data: z.record(z.string(), z.any()).default({}),
  severity: EvidenceSeveritySchema,
  created_at: z.string().optional(),
});

export const FindingSchema = z.object({
  text: z.string(),
  evidence_ids: z.array(z.string()).default([]),
  severity: EvidenceSeveritySchema.optional(),
});

export const AgentReportSchema = z.object({
  agent_id: z.string(),
  round: z.number(),
  protocol_version: z.string().default('1.0.0'),
  verdict: VerdictSchema,
  confidence: z.number().min(0).max(1),
  calibration_status: CalibrationStatusSchema,
  findings: z.array(FindingSchema).default([]),
  limitations: z.array(z.string()).default([]),
  availability: AvailabilityStatusSchema,
  availability_reason: z.string().nullable().optional(),
  model_identifiers: z.record(z.string(), z.any()).default({}),
  raw_output: z.record(z.string(), z.any()).nullable().optional(),
  revised_from_round1: z.boolean().nullable().optional(),
  created_at: z.string().optional(),
});

export const DebateMessageSchema = z.object({
  from_agent: z.string(),
  round: z.number().default(2),
  summary: z.string(),
  cited_evidence_ids: z.array(z.string()).default([]),
  created_at: z.string().optional(),
});

export const ConsensusResultSchema = z.object({
  final_verdict: ConsensusVerdictSchema,
  confidence: z.number().min(0).max(1),
  reasons: z.array(z.string()).default([]),
  partial: z.boolean().default(false),
  matched_rule_id: z.string(),
  agent_verdicts: z.record(z.string(), VerdictSchema.nullable()).default({}),
  prompt_injection_detected: z.boolean().default(false),
  risk_indicator: z.number().nullable().optional(),
  created_at: z.string().optional(),
});

export const InvestigationStateSchema = z.object({
  investigation_id: z.string(),
  email_sha256: z.string(),
  receipt_time_utc: z.any().optional(),
  received_at: z.any().optional(),
  source: z.string().default('unknown'),
  parser_version: z.string().default('1.0.0'),
  evidence: z.array(EvidenceItemSchema).default([]),
  reports: z.array(AgentReportSchema).default([]),
  debate_messages: z.array(DebateMessageSchema).default([]),
  final_result: ConsensusResultSchema.nullable().optional(),
  state_hash: z.string().optional(),
});

export const InvestigationSummarySchema = z.object({
  investigation_id: z.string(),
  email_sha256: z.string(),
  receipt_time_utc: z.any().optional(),
  received_at: z.any().optional(),
  source: z.string().default('unknown'),
  parser_version: z.string().optional(),
  final_verdict: ConsensusVerdictSchema.nullable().optional(),
  confidence: z.number().nullable().optional(),
  partial: z.boolean().default(false),
  matched_rule_id: z.string().optional(),
  prompt_injection_detected: z.boolean().default(false),
  evidence_count: z.number().default(0),
  reports_count: z.number().default(0),
  risk_indicator: z.number().nullable().optional(),
});

export const AgentStatusInfoSchema = z.object({
  agent_id: z.string(),
  name: z.string(),
  availability: AvailabilityStatusSchema,
  availability_reason: z.string().nullable().optional(),
  calibration_status: CalibrationStatusSchema,
  details: z.record(z.string(), z.any()).default({}),
});

export const HealthResponseSchema = z.object({
  status: z.string(),
  agents: z.array(AgentStatusInfoSchema),
  system_info: z.record(z.string(), z.any()).default({}),
});

export const ReadinessAgentSchema = z.object({
  ready: z.boolean(),
  trained: z.boolean().optional(),
  enabled: z.boolean().optional(),
  disclosure_required: z.boolean().optional(),
  cached: z.boolean().optional(),
  smoke_test_verdict: z.string().nullable().optional(),
  error: z.string().nullable().optional(),
});

export const ReadinessResponseSchema = z.object({
  ready: z.boolean(),
  timestamp_utc: z.string(),
  agents: z.record(z.string(), ReadinessAgentSchema).default({}),
});

export const ProgressResponseSchema = z.object({
  status: z.enum(['queued', 'processing', 'completed', 'failed']),
  progress_pct: z.number().min(0).max(100),
  stage: z.string(),
  investigation_id: z.string().optional(),
  final_verdict: z.string().nullable().optional(),
  confidence: z.number().nullable().optional(),
  error: z.string().nullable().optional(),
});

export const DecisionRuleInfoSchema = z.object({
  rule_id: z.string(),
  name: z.string(),
  description: z.string(),
  outcome: z.string(),
  confidence: z.number(),
  partial: z.boolean(),
});

export const SampleItemSchema = z.object({
  id: z.string(),
  filename: z.string(),
  category: z.string(),
});

// =====================================================================
// 2. TypeScript Types Inferred from Zod
// =====================================================================

export type Verdict = z.infer<typeof VerdictSchema>;
export type ConsensusVerdict = z.infer<typeof ConsensusVerdictSchema>;
export type CalibrationStatus = z.infer<typeof CalibrationStatusSchema>;
export type AvailabilityStatus = z.infer<typeof AvailabilityStatusSchema>;
export type EvidenceCategory = z.infer<typeof EvidenceCategorySchema>;
export type EvidenceSeverity = z.infer<typeof EvidenceSeveritySchema>;

export type EvidenceItem = z.infer<typeof EvidenceItemSchema>;
export type Finding = z.infer<typeof FindingSchema>;
export type AgentReport = z.infer<typeof AgentReportSchema>;
export type DebateMessage = z.infer<typeof DebateMessageSchema>;
export type ConsensusResult = z.infer<typeof ConsensusResultSchema>;
export type InvestigationState = z.infer<typeof InvestigationStateSchema>;
export type InvestigationSummary = z.infer<typeof InvestigationSummarySchema>;
export type AgentStatusInfo = z.infer<typeof AgentStatusInfoSchema>;
export type HealthResponse = z.infer<typeof HealthResponseSchema>;
export type ReadinessResponse = z.infer<typeof ReadinessResponseSchema>;
export type ProgressResponse = z.infer<typeof ProgressResponseSchema>;
export type DecisionRuleInfo = z.infer<typeof DecisionRuleInfoSchema>;
export type SampleItem = z.infer<typeof SampleItemSchema>;

// =====================================================================
// 3. User-Facing Mappings and Text Rules
// =====================================================================

export const VERDICT_LABELS: Record<string, string> = {
  PHISHING: 'Phishing',
  SPAM: 'Spam',
  SUSPICIOUS: 'Suspicious',
  LEGITIMATE: 'No threat indicators found',
  NEEDS_REVIEW: 'Needs review',
  ABSTAIN: 'Abstained / Unavailable',
};

export function getVerdictLabel(v: string | null | undefined): string {
  if (!v) return 'Unknown';
  return VERDICT_LABELS[v.toUpperCase()] || v;
}

export function getCalibrationLabel(status: CalibrationStatus | string): string {
  if (status === 'UNVALIDATED') {
    return 'Unvalidated score, not a probability';
  }
  if (status === 'DEMO_ONLY') {
    return 'Demo model only (synthetic demo data)';
  }
  if (status === 'VALIDATED') {
    return 'Benchmark validated';
  }
  return status;
}

export function getAvailabilityLabel(status: AvailabilityStatus | string): string {
  if (status === 'AVAILABLE') return 'Available & resident';
  if (status === 'DEGRADED') return 'Degraded / Rate limited';
  if (status === 'UNAVAILABLE') return 'Unavailable / Offline';
  return status;
}
