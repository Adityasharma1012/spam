import React from 'react';
import { Shield, Cpu, Sparkles, BookOpen, AlertTriangle } from 'lucide-react';
import { HealthResponse } from '../types';

interface HeaderProps {
  health?: HealthResponse | null;
  onOpenDecisionTable: () => void;
}

export const Header: React.FC<HeaderProps> = ({ health, onOpenDecisionTable }) => {
  return (
    <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight text-white">Email Threat Detection Platform</h1>
              <span className="text-xs px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 font-mono">v1.0.0</span>
            </div>
            <p className="text-xs text-slate-400">Multi-Agent Deliberation • Typed Decisions • Consensus Verification</p>
          </div>
        </div>

        {/* Agent Status Indicators */}
        <div className="flex flex-wrap items-center gap-2">
          {/* ML Agent Indicator */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-800/80 border border-slate-700/60 text-xs">
            <Cpu className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-slate-300 font-medium">Agent 1 (ML):</span>
            <span className="text-amber-300 text-[10px] font-mono px-1.5 py-0.2 bg-amber-950/60 border border-amber-800/50 rounded">DEMO_ONLY</span>
          </div>

          {/* Gemini Indicator */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-800/80 border border-slate-700/60 text-xs">
            <Sparkles className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-slate-300 font-medium">Agent 2 (Gemini):</span>
            {health?.agents.find(a => a.agent_id === 'gemini')?.availability === 'AVAILABLE' ? (
              <span className="text-emerald-400 text-[10px] font-mono px-1.5 py-0.2 bg-emerald-950/60 border border-emerald-800/50 rounded">ENABLED (REDACTED)</span>
            ) : (
              <span className="text-slate-400 text-[10px] font-mono px-1.5 py-0.2 bg-slate-800 border border-slate-700 rounded">OFF (PRIVACY GATE)</span>
            )}
          </div>

          {/* Laya Indicator */}
          {(() => {
            const laya = health?.agents.find(a => a.agent_id === 'laya');
            const device = (laya?.details?.device || 'cpu').toUpperCase();
            const calStatus = laya?.calibration_status || 'UNVALIDATED';
            return (
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-800/80 border border-slate-700/60 text-xs">
                <Shield className="w-3.5 h-3.5 text-purple-400" />
                <span className="text-slate-300 font-medium">Agent 3 (Laya):</span>
                <span className="text-purple-300 text-[10px] font-mono px-1.5 py-0.2 bg-purple-950/60 border border-purple-800/50 rounded">
                  RESIDENT ({device})
                </span>
                <span className="text-slate-400 text-[10px] font-mono">{calStatus}</span>
              </div>
            );
          })()}

          <button
            onClick={onOpenDecisionTable}
            className="btn-secondary text-xs py-1 px-2.5"
            title="View Consensus Decision Table Rules"
          >
            <BookOpen className="w-3.5 h-3.5 text-blue-400" />
            <span>Decision Table</span>
          </button>
        </div>
      </div>
    </header>
  );
};
