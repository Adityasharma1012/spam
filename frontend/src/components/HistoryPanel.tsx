import React, { useState, useEffect } from 'react';
import { History, Download, Trash2, ExternalLink, RefreshCw, Clock, Shield } from 'lucide-react';
import { InvestigationSummary, InvestigationState, ConsensusVerdict } from '../types';

interface HistoryPanelProps {
  onSelectInvestigation: (state: InvestigationState) => void;
  currentInvestigationId?: string;
}

export const HistoryPanel: React.FC<HistoryPanelProps> = ({
  onSelectInvestigation,
  currentInvestigationId,
}) => {
  const [history, setHistory] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [isOpen, setIsOpen] = useState<boolean>(true);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/investigations');
      if (res.ok) {
        const data: InvestigationSummary[] = await res.json();
        setHistory(data);
      }
    } catch (err) {
      console.error('Failed to fetch investigations history', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [currentInvestigationId]);

  const handleLoad = async (invId: string) => {
    try {
      const res = await fetch(`/api/investigations/${invId}`);
      if (!res.ok) throw new Error('Failed to load investigation');
      const state: InvestigationState = await res.json();
      onSelectInvestigation(state);
      setActionMessage(`Loaded investigation ${invId}`);
      setTimeout(() => setActionMessage(null), 3000);
    } catch (err: any) {
      alert(`Error loading investigation: ${err.message}`);
    }
  };

  const handleExport = (invId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    window.open(`/api/investigations/${invId}/export`, '_blank');
  };

  const handleDelete = async (invId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`Permanently delete investigation ${invId}? (A tombstone audit record will be logged)`)) {
      return;
    }
    try {
      const res = await fetch(`/api/investigations/${invId}`, { method: 'DELETE' });
      if (res.ok) {
        setActionMessage(`Investigation ${invId} deleted`);
        setTimeout(() => setActionMessage(null), 3000);
        fetchHistory();
      }
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  const getVerdictBadge = (verdict?: ConsensusVerdict | null) => {
    switch (verdict) {
      case 'PHISHING':
        return 'bg-red-950 text-red-300 border-red-800';
      case 'SPAM':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'SUSPICIOUS':
        return 'bg-yellow-950 text-yellow-300 border-yellow-800';
      case 'LEGITIMATE':
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
      case 'NEEDS_REVIEW':
      default:
        return 'bg-purple-950 text-purple-300 border-purple-800';
    }
  };

  return (
    <div className="panel mb-6">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-slate-800 border border-slate-700">
            <History className="w-4 h-4 text-blue-400" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">Investigation Audit History</h3>
            <p className="text-[11px] text-slate-400 font-mono">
              Append-only audit trail with cryptographic SHA-256 integrity ({history.length} logged)
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {actionMessage && (
            <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800 animate-fadeIn">
              {actionMessage}
            </span>
          )}
          <button
            onClick={fetchHistory}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
            title="Refresh history"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-blue-400' : ''}`} />
          </button>
          <button
            onClick={() => setIsOpen(!isOpen)}
            className="text-[11px] font-mono text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800/80 border border-slate-700"
          >
            {isOpen ? 'Collapse' : 'Expand'}
          </button>
        </div>
      </div>

      {isOpen && (
        <div className="mt-3">
          {history.length === 0 ? (
            <p className="text-xs text-slate-500 italic p-4 text-center">
              No investigations logged in session. Run an analysis above to populate audit history.
            </p>
          ) : (
            <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
              {history.map((inv) => {
                const isSelected = currentInvestigationId === inv.investigation_id;
                return (
                  <div
                    key={inv.investigation_id}
                    onClick={() => handleLoad(inv.investigation_id)}
                    className={`p-2.5 rounded-lg border cursor-pointer transition-all flex items-center justify-between gap-3 text-xs ${
                      isSelected
                        ? 'bg-blue-950/40 border-blue-500 ring-1 ring-blue-500/50'
                        : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-xs font-bold text-blue-300">
                        {inv.investigation_id}
                      </span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${getVerdictBadge(
                          inv.final_verdict
                        )}`}
                      >
                        {inv.final_verdict || 'PENDING'}
                      </span>
                      {inv.confidence !== null && inv.confidence !== undefined && (
                        <span className="text-[11px] font-mono text-slate-400">
                          conf: {(inv.confidence * 100).toFixed(0)}%
                        </span>
                      )}
                      <span className="text-[11px] font-mono text-slate-500">
                        {inv.evidence_count} evidence items
                      </span>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-1 text-[10px] text-slate-400 font-mono">
                        <Clock className="w-3 h-3 text-slate-500" />
                        <span>{new Date(inv.receipt_time_utc).toLocaleTimeString()}</span>
                      </div>
                      <span className="text-[10px] text-slate-600 font-mono">
                        hash: {inv.state_hash.substring(0, 8)}...
                      </span>

                      <div className="flex items-center gap-1 ml-2">
                        <button
                          onClick={(e) => handleExport(inv.investigation_id, e)}
                          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-blue-300 transition-colors"
                          title="Export verified JSON"
                        >
                          <Download className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={(e) => handleDelete(inv.investigation_id, e)}
                          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-red-400 transition-colors"
                          title="Delete investigation (tombstone preserved)"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
