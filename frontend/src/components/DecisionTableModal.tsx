import React from 'react';
import { X, BookOpen, Scale, CheckCircle2, ShieldAlert } from 'lucide-react';
import { DecisionRuleInfo } from '../types';

interface DecisionTableModalProps {
  isOpen: boolean;
  onClose: () => void;
  rules: DecisionRuleInfo[];
  matchedRuleId?: string;
}

export const DecisionTableModal: React.FC<DecisionTableModalProps> = ({
  isOpen,
  onClose,
  rules,
  matchedRuleId,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-blue-950/80 border border-blue-800 text-blue-400">
              <Scale className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Consensus Engine Decision Table</h2>
              <p className="text-xs text-slate-400">
                Deterministic synthesis rules weighting evidence severity, quorum availability, and calibration status
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-4">
          <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800 text-xs text-slate-300 leading-relaxed font-mono">
            <span className="font-bold text-blue-300 block mb-1">DECISION PHILOSOPHY:</span>
            • Confidences are NEVER averaged; agreeing models are not treated as independent proof.<br />
            • Objective deterministic evidence (DKIM failure, brand-spoofed URLs) supersedes probabilistic models.<br />
            • Conflicting agent findings or incomplete agent quorum automatically escalate to <span className="text-orange-400 font-bold">NEEDS_REVIEW</span>.<br />
            • Models tagged DEMO_ONLY (Agent 1) or UNVALIDATED (Agent 3) cannot certify production benign status alone.
          </div>

          <div className="space-y-2.5">
            {rules.map((r) => {
              const isCurrentMatch = matchedRuleId === r.rule_id;

              return (
                <div
                  key={r.rule_id}
                  className={`p-3.5 rounded-lg border transition-all ${
                    isCurrentMatch
                      ? 'bg-blue-950/50 border-blue-500 shadow-lg ring-1 ring-blue-500'
                      : 'bg-slate-950/40 border-slate-800/80'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-blue-300 border border-slate-700">
                        {r.rule_id}
                      </span>
                      <span className="text-sm font-bold text-white">{r.name}</span>
                      {isCurrentMatch && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-600 text-white font-bold uppercase tracking-wider">
                          ACTIVE MATCH
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span
                        className={`badge ${
                          r.outcome === 'PHISHING'
                            ? 'badge-phishing'
                            : r.outcome === 'LEGITIMATE'
                            ? 'badge-legitimate'
                            : r.outcome === 'SPAM'
                            ? 'badge-spam'
                            : r.outcome === 'SUSPICIOUS'
                            ? 'badge-suspicious'
                            : 'badge-needs-review'
                        } text-[10px]`}
                      >
                        {r.outcome}
                      </span>
                      <span className="text-xs font-mono text-slate-300">
                        {(r.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 mt-2 leading-relaxed font-mono">
                    {r.description}
                  </p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/40 flex justify-end">
          <button onClick={onClose} className="btn-secondary text-xs">
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
