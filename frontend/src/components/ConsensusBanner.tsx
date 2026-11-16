import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Hash,
  Clock,
  ShieldCheck,
  Flame,
  FileCode2,
} from 'lucide-react';
import { ConsensusResult, InvestigationState } from '../types';

interface ConsensusBannerProps {
  state: InvestigationState;
}

export const ConsensusBanner: React.FC<ConsensusBannerProps> = ({ state }) => {
  const consensus = state.final_result;
  if (!consensus) return null;

  const verdict = consensus.final_verdict;

  const getVerdictStyle = () => {
    switch (verdict) {
      case 'PHISHING':
        return {
          bg: 'bg-red-950/40 border-red-500/50',
          badge: 'badge-phishing',
          icon: <ShieldAlert className="w-8 h-8 text-red-500" />,
          title: 'PHISHING DETECTED',
          desc: 'High-confidence threat: credential harvesting, account spoofing, or malware deployment.',
        };
      case 'SUSPICIOUS':
        return {
          bg: 'bg-amber-950/40 border-amber-500/50',
          badge: 'badge-suspicious',
          icon: <AlertTriangle className="w-8 h-8 text-amber-500" />,
          title: 'SUSPICIOUS ACTIVITY',
          desc: 'Anomalous headers, unverified domains, or unauthenticated delivery chain.',
        };
      case 'SPAM':
        return {
          bg: 'bg-purple-950/40 border-purple-500/50',
          badge: 'badge-spam',
          icon: <AlertTriangle className="w-8 h-8 text-purple-400" />,
          title: 'UNSOLICITED BULK SPAM',
          desc: 'Promotional mass communication without direct exploitation payloads.',
        };
      case 'LEGITIMATE':
        return {
          bg: 'bg-emerald-950/40 border-emerald-500/50',
          badge: 'badge-legitimate',
          icon: <CheckCircle2 className="w-8 h-8 text-emerald-400" />,
          title: 'VERIFIED LEGITIMATE',
          desc: 'Standard authentic communication passing all domain authentication checks.',
        };
      case 'NEEDS_REVIEW':
      default:
        return {
          bg: 'bg-orange-950/40 border-orange-500/50',
          badge: 'badge-needs-review',
          icon: <HelpCircle className="w-8 h-8 text-orange-400" />,
          title: 'NEEDS SECURITY REVIEW',
          desc: 'Inconclusive signals, agent conflict, or unvalidated confidence quorum requires tier-2 human inspection.',
        };
    }
  };

  const style = getVerdictStyle();

  return (
    <div className={`panel border-2 ${style.bg} mb-6 transition-all`}>
      {/* Prompt Injection Warning Banner */}
      {consensus.prompt_injection_detected && (
        <div className="mb-4 p-3 rounded-lg bg-red-900/60 border border-red-500 text-red-100 flex items-start gap-2.5 shadow-lg">
          <Flame className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="text-xs">
            <span className="font-bold uppercase tracking-wider block text-red-200">
              Prompt Injection Neutralized
            </span>
            <span>
              Adversarial directives or override instructions were discovered inside the untrusted email body/headers.
              In accordance with security protocol, injection attempts cannot modify platform verdicts and have been logged as active threat evidence.
            </span>
          </div>
        </div>
      )}

      {/* Main Consensus Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800">
            {style.icon}
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h2 className="text-xl font-extrabold tracking-tight text-white">{style.title}</h2>
              <span className={`badge ${style.badge}`}>{verdict}</span>
              {consensus.partial && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  PARTIAL EVALUATION
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-0.5">{style.desc}</p>
          </div>
        </div>

        {/* Confidence & Rule Badge */}
        <div className="flex items-center gap-4 text-right">
          <div>
            <span className="text-[11px] font-mono text-slate-400 block uppercase">Confidence Level</span>
            <div className="flex items-center gap-1.5 justify-end">
              <span className="text-lg font-bold font-mono text-white">
                {(consensus.confidence * 100).toFixed(0)}%
              </span>
              <div className="w-16 h-2 bg-slate-800 rounded-full overflow-hidden border border-slate-700">
                <div
                  className={`h-full ${
                    consensus.confidence >= 0.85
                      ? 'bg-blue-500'
                      : consensus.confidence >= 0.65
                      ? 'bg-amber-500'
                      : 'bg-slate-500'
                  }`}
                  style={{ width: `${consensus.confidence * 100}%` }}
                />
              </div>
            </div>
          </div>

          <div className="pl-4 border-l border-slate-800">
            <span className="text-[11px] font-mono text-slate-400 block uppercase">Decision Rule</span>
            <span className="text-xs font-mono px-2 py-1 rounded bg-blue-950/80 border border-blue-800 text-blue-300 inline-block font-bold">
              {consensus.matched_rule_id}
            </span>
          </div>
        </div>
      </div>

      {/* Rationale Bullet Points */}
      <div className="mt-4">
        <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-2 font-mono">
          Consensus Rationale & Weighing:
        </span>
        <ul className="space-y-1.5">
          {consensus.reasons.map((r, idx) => (
            <li key={idx} className="text-xs text-slate-300 flex items-start gap-2">
              <span className="text-blue-400 mt-0.5">•</span>
              <span>{r}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Cryptographic Hash and Receipt Integrity Footer */}
      <div className="mt-4 pt-3 border-t border-slate-800/60 flex flex-wrap items-center justify-between text-[11px] text-slate-500 font-mono gap-2">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-slate-400 font-semibold">Integrity Verified:</span>
          <span>SHA-256: {state.email_sha256.substring(0, 16)}...</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3 text-slate-500" />
            <span>UTC: {state.receipt_time_utc.substring(11, 19)}</span>
          </span>
          <span className="flex items-center gap-1">
            <FileCode2 className="w-3 h-3 text-slate-500" />
            <span>Parser: v{state.parser_version}</span>
          </span>
          <a
            href={`/api/investigations/${state.investigation_id}/export`}
            target="_blank"
            rel="noreferrer"
            className="px-2 py-0.5 rounded bg-blue-950/80 border border-blue-800/80 text-blue-300 hover:text-white hover:bg-blue-900 transition-colors inline-flex items-center gap-1"
            title="Download verified JSON audit export"
          >
            Export JSON
          </a>
        </div>
      </div>
    </div>
  );
};
