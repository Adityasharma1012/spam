import React, { useState } from 'react';
import {
  Search,
  Filter,
  ShieldAlert,
  Link,
  Mail,
  FileCheck,
  Paperclip,
  Network,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  MapPin,
} from 'lucide-react';
import { EvidenceCategory, EvidenceItem } from '../types';

interface EvidenceExplorerProps {
  evidence: EvidenceItem[];
  highlightedId?: string | null;
}

export const EvidenceExplorer: React.FC<EvidenceExplorerProps> = ({
  evidence,
  highlightedId,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [expandedItem, setExpandedItem] = useState<string | null>(null);

  const categories = ['ALL', 'URL_ANALYSIS', 'AUTH_RESULTS', 'HEADER_MISMATCH', 'ATTACHMENT_ANALYSIS', 'PROMPT_INJECTION', 'GEOLOCATION', 'RECEIVED_CHAIN'];

  const filteredEvidence = evidence.filter((item) => {
    if (selectedCategory === 'ALL') return true;
    return item.category === selectedCategory;
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-950 text-red-300 border-red-800';
      case 'HIGH':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'MEDIUM':
        return 'bg-yellow-950 text-yellow-300 border-yellow-800';
      case 'LOW':
        return 'bg-blue-950 text-blue-300 border-blue-800';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  const getCategoryIcon = (cat: string) => {
    switch (cat) {
      case 'URL_ANALYSIS':
        return <Link className="w-4 h-4 text-cyan-400" />;
      case 'HEADER_MISMATCH':
        return <Mail className="w-4 h-4 text-amber-400" />;
      case 'AUTH_RESULTS':
        return <FileCheck className="w-4 h-4 text-emerald-400" />;
      case 'ATTACHMENT_ANALYSIS':
        return <Paperclip className="w-4 h-4 text-purple-400" />;
      case 'PROMPT_INJECTION':
        return <ShieldAlert className="w-4 h-4 text-red-400" />;
      case 'GEOLOCATION':
        return <MapPin className="w-4 h-4 text-emerald-400" />;
      case 'RECEIVED_CHAIN':
      default:
        return <Network className="w-4 h-4 text-slate-400" />;
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="panel mb-6">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-blue-950/60 border border-blue-800/80">
            <Search className="w-4 h-4 text-blue-400" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">Deterministic Evidence Catalog</h3>
            <p className="text-[11px] text-slate-400 font-mono">
              Cryptographically verified findings ({evidence.length} total items)
            </p>
          </div>
        </div>

        {/* Category Filters */}
        <div className="flex flex-wrap gap-1.5">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`text-[11px] font-mono px-2 py-0.5 rounded border transition-colors ${
                selectedCategory === cat
                  ? 'bg-blue-600 text-white border-blue-500'
                  : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-white'
              }`}
            >
              {cat.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {/* Evidence Table / Cards */}
      <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
        {filteredEvidence.length === 0 ? (
          <p className="text-xs text-slate-500 italic p-4 text-center">No evidence items in this category.</p>
        ) : (
          filteredEvidence.map((ev) => {
            const isHighlighted = highlightedId === ev.evidence_id;
            const isExpanded = expandedItem === ev.evidence_id;

            return (
              <div
                key={ev.evidence_id}
                id={`evidence-${ev.evidence_id}`}
                className={`p-3 rounded-lg border transition-all ${
                  isHighlighted
                    ? 'bg-blue-950/40 border-blue-500 shadow-md ring-1 ring-blue-500'
                    : 'bg-slate-900/70 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-2.5">
                    <div className="mt-0.5 p-1 rounded bg-slate-800 border border-slate-700">
                      {getCategoryIcon(ev.category)}
                    </div>
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-xs font-bold text-blue-300">
                          {ev.evidence_id}
                        </span>
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.2 rounded border font-semibold ${getSeverityBadge(
                            ev.severity
                          )}`}
                        >
                          {ev.severity}
                        </span>
                        <span className="text-[11px] text-slate-400 font-mono">
                          Source: {ev.source}
                        </span>
                      </div>
                      <p className="text-xs text-slate-200 leading-relaxed font-mono">
                        {ev.description}
                      </p>
                      <p className="text-[10px] text-slate-400 mt-1 italic">
                        Provenance: {ev.provenance}
                      </p>

                      {/* Network Geolocation Box with Strict Privacy Disclaimer */}
                      {ev.category === 'GEOLOCATION' && (
                        <div className="mt-2.5 p-2.5 rounded-lg bg-emerald-950/40 border border-emerald-800/60 text-xs text-emerald-200">
                          <div className="flex items-center gap-1.5 font-bold mb-1">
                            <MapPin className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Network Infrastructure Geolocation</span>
                          </div>
                          <p className="text-[11px] text-emerald-400/90 italic mb-2">
                            Disclaimer: Approximate network-level location, never a person's location.
                          </p>
                          {ev.defanged_data && (
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[10px] bg-black/60 p-2 rounded border border-emerald-900/50">
                              <div><span className="text-slate-400">Public IP:</span> <span className="text-white font-bold">{ev.defanged_data.ip}</span></div>
                              <div><span className="text-slate-400">Country:</span> <span className="text-emerald-300">{ev.defanged_data.country}</span></div>
                              <div><span className="text-slate-400">City:</span> <span className="text-emerald-300">{ev.defanged_data.city}</span></div>
                              <div><span className="text-slate-400">ASN:</span> <span className="text-emerald-300">{ev.defanged_data.asn}</span></div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      onClick={() =>
                        copyToClipboard(
                          ev.defanged_data?.url || ev.description,
                          ev.evidence_id
                        )
                      }
                      className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
                      title="Copy safe defanged representation"
                    >
                      {copiedId === ev.evidence_id ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                    {(ev.raw_data || ev.defanged_data) && (
                      <button
                        onClick={() =>
                          setExpandedItem(isExpanded ? null : ev.evidence_id)
                        }
                        className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
                        title="Toggle metadata inspection"
                      >
                        {isExpanded ? (
                          <ChevronUp className="w-3.5 h-3.5" />
                        ) : (
                          <ChevronDown className="w-3.5 h-3.5" />
                        )}
                      </button>
                    )}
                  </div>
                </div>

                {/* Expanded metadata */}
                {isExpanded && (
                  <div className="mt-2.5 pt-2 border-t border-slate-800/80 font-mono text-[10px] text-slate-300 bg-black/60 p-2 rounded">
                    <pre>{JSON.stringify(ev.defanged_data || ev.raw_data, null, 2)}</pre>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
