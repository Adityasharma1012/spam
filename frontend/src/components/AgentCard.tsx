import React, { useState } from 'react';
import {
  Cpu,
  Sparkles,
  Shield,
  Layers,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  CheckCircle,
  HelpCircle,
  Tag,
  ArrowRight,
} from 'lucide-react';
import { AgentReport } from '../types';

interface AgentCardProps {
  r1Report?: AgentReport;
  r2Report?: AgentReport;
  onEvidenceClick?: (evidenceId: string) => void;
}

export const AgentCard: React.FC<AgentCardProps> = ({
  r1Report,
  r2Report,
  onEvidenceClick,
}) => {
  const [showRawOutput, setShowRawOutput] = useState(false);
  const report = r2Report || r1Report;
  if (!report) return null;

  const getAgentHeader = () => {
    switch (report.agent_id) {
      case 'ml':
        return {
          name: 'Agent 1: Scikit-Learn TF-IDF',
          subtitle: 'Multinomial Naive Bayes Baseline',
          icon: <Cpu className="w-5 h-5 text-amber-400" />,
          borderColor: 'border-amber-500/30',
          badgeColor: 'badge-demo',
        };
      case 'gemini':
        return {
          name: 'Agent 2: Google Gemini Adapter',
          subtitle: 'Cloud LLM Structured Analyst (Redacted)',
          icon: <Sparkles className="w-5 h-5 text-blue-400" />,
          borderColor: 'border-blue-500/30',
          badgeColor: 'badge-unvalidated',
        };
      case 'laya':
      default:
        return {
          name: 'Agent 3: Laya System 1 Engine',
          subtitle: 'Local Typed Decisions (ModernBERT 421M)',
          icon: <Shield className="w-5 h-5 text-purple-400" />,
          borderColor: 'border-purple-500/30',
          badgeColor: 'badge-unvalidated',
        };
    }
  };

  const header = getAgentHeader();
  const isAvailable = report.availability === 'AVAILABLE';

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case 'PHISHING':
        return 'badge-phishing';
      case 'SUSPICIOUS':
        return 'badge-suspicious';
      case 'SPAM':
        return 'badge-spam';
      case 'LEGITIMATE':
        return 'badge-legitimate';
      default:
        return 'badge-needs-review';
    }
  };

  return (
    <div className={`panel-card border ${header.borderColor} flex flex-col justify-between`}>
      <div>
        {/* Header */}
        <div className="flex items-start justify-between gap-2 pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
              {header.icon}
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">{header.name}</h3>
              <p className="text-[11px] text-slate-400 font-mono">{header.subtitle}</p>
            </div>
          </div>
          <span className={`badge ${header.badgeColor}`}>
            {report.calibration_status}
          </span>
        </div>

        {/* Availability Notice */}
        {!isAvailable ? (
          <div className="mt-4 p-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 text-xs">
            <div className="flex items-center gap-1.5 text-amber-400 font-semibold mb-1">
              <AlertCircle className="w-4 h-4" />
              <span>Status: {report.availability}</span>
            </div>
            <p className="text-[11px] leading-relaxed">
              {report.availability_reason || 'Component uninitialized or disabled by configuration policy.'}
            </p>
          </div>
        ) : (
          <div className="mt-4 space-y-3">
            {/* Rounds Comparison */}
            <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800/80">
              <div className="flex items-center justify-between text-xs mb-1.5">
                <span className="text-slate-400 font-mono text-[11px]">Round 1 Assessment:</span>
                {r1Report ? (
                  <div className="flex items-center gap-1.5">
                    <span className={`badge ${getVerdictBadge(r1Report.verdict)} text-[10px]`}>
                      {r1Report.verdict}
                    </span>
                    <span className="font-mono text-slate-300 text-[11px]">
                      {(r1Report.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                ) : (
                  <span className="text-slate-500 text-[11px]">N/A</span>
                )}
              </div>

              <div className="flex items-center justify-between text-xs pt-1.5 border-t border-slate-800/60">
                <span className="text-slate-400 font-mono text-[11px] flex items-center gap-1">
                  <span>Round 2 Revision:</span>
                  {r2Report?.revised_from_round1 && (
                    <span className="text-[10px] text-blue-400 font-bold">(REVISED)</span>
                  )}
                </span>
                {r2Report ? (
                  <div className="flex items-center gap-1.5">
                    <span className={`badge ${getVerdictBadge(r2Report.verdict)} text-[10px]`}>
                      {r2Report.verdict}
                    </span>
                    <span className="font-mono text-slate-300 text-[11px]">
                      {(r2Report.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                ) : (
                  <span className="text-slate-500 text-[11px]">In progress</span>
                )}
              </div>
            </div>

            {/* Findings List */}
            <div>
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block mb-1.5">
                Agent Findings:
              </span>
              <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                {report.findings.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No threat signals identified.</p>
                ) : (
                  report.findings.map((f, idx) => (
                    <div
                      key={idx}
                      className="p-2 rounded bg-slate-900/60 border border-slate-800/70 text-xs text-slate-300"
                    >
                      <p className="mb-1 leading-snug">{f.text}</p>
                      {f.evidence_ids.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1">
                          {f.evidence_ids.map((eid) => (
                            <button
                              key={eid}
                              onClick={() => onEvidenceClick?.(eid)}
                              className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-blue-950 text-blue-300 border border-blue-800 hover:bg-blue-900 transition-colors cursor-pointer"
                              title="Inspect evidence in catalog"
                            >
                              {eid}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Typed Decision Primitives (Laya Specific) */}
            {report.agent_id === 'laya' && report.raw_output && (
              <div className="p-2.5 rounded-lg bg-purple-950/20 border border-purple-900/40 text-xs">
                <span className="text-[11px] font-mono text-purple-300 block mb-1 font-semibold">
                  Typed Decision Outputs:
                </span>
                <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                  <div className="bg-slate-900/80 p-1.5 rounded border border-slate-800">
                    <span className="text-slate-400 block">Harvesting:</span>
                    <span className={report.raw_output.credential_harvesting?.answer ? 'text-red-400 font-bold' : 'text-slate-300'}>
                      {String(report.raw_output.credential_harvesting?.answer ?? 'false').toUpperCase()}
                    </span>
                  </div>
                  <div className="bg-slate-900/80 p-1.5 rounded border border-slate-800">
                    <span className="text-slate-400 block">Impersonation:</span>
                    <span className={report.raw_output.sender_impersonation?.answer ? 'text-red-400 font-bold' : 'text-slate-300'}>
                      {String(report.raw_output.sender_impersonation?.answer ?? 'false').toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Footer & Limitations */}
      <div className="mt-4 pt-3 border-t border-slate-800/80">
        <div className="flex items-center justify-between">
          <button
            onClick={() => setShowRawOutput(!showRawOutput)}
            className="text-[11px] font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1"
          >
            {showRawOutput ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            <span>{showRawOutput ? 'Hide Raw Output' : 'Inspect Raw Data'}</span>
          </button>
          <span className="text-[10px] font-mono text-slate-500">
            {report.model_identifiers?.device ? `Device: ${report.model_identifiers.device}` : ''}
          </span>
        </div>

        {showRawOutput && (
          <div className="mt-2.5 p-2 rounded bg-black/80 border border-slate-800 font-mono text-[10px] text-slate-300 max-h-48 overflow-y-auto">
            <pre>{JSON.stringify(report.raw_output || report.model_identifiers, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
};
