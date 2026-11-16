import React, { useEffect, useState } from 'react';
import { useRouter } from '../router';
import { api, ApiError } from '../api/client';
import { InvestigationSummary, getVerdictLabel } from '../api/types';
import {
  Clock,
  Search,
  Trash2,
  AlertTriangle,
  FileText,
  ChevronRight,
  Filter,
} from 'lucide-react';

export const HistoryPage: React.FC = () => {
  const { navigate } = useRouter();
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);

  const loadData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.listInvestigations();
      setInvestigations(data);
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Failed to load history');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleDelete = async (id: string) => {
    setIsDeleting(true);
    try {
      await api.deleteInvestigation(id);
      setInvestigations((prev) => prev.filter((i) => i.investigation_id !== id));
      setDeletingId(null);
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    } finally {
      setIsDeleting(false);
    }
  };

  // Filter items
  const filtered = investigations.filter((inv) => {
    if (verdictFilter !== 'ALL' && inv.final_verdict !== verdictFilter) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = inv.investigation_id.toLowerCase().includes(q);
      const matchSha = inv.email_sha256.toLowerCase().includes(q);
      const matchSource = inv.source.toLowerCase().includes(q);
      return matchId || matchSha || matchSource;
    }
    return true;
  });

  const filterOptions = [
    { label: 'All', value: 'ALL' },
    { label: 'Phishing', value: 'PHISHING' },
    { label: 'Spam', value: 'SPAM' },
    { label: 'Suspicious', value: 'SUSPICIOUS' },
    { label: 'No threats found', value: 'LEGITIMATE' },
    { label: 'Needs review', value: 'NEEDS_REVIEW' },
  ];

  const getVerdictStyle = (v: string, partial: boolean) => {
    if (partial) {
      return {
        bg: 'var(--warning-amber-bg)',
        color: 'var(--warning-amber)',
        border: 'var(--warning-amber-border)',
      };
    }
    switch (v) {
      case 'PHISHING':
        return {
          bg: 'var(--threat-red-bg)',
          color: 'var(--threat-red)',
          border: 'var(--threat-red-border)',
        };
      case 'SPAM':
      case 'SUSPICIOUS':
        return {
          bg: 'var(--suspicious-orange-bg)',
          color: 'var(--suspicious-orange)',
          border: 'var(--suspicious-orange-border)',
        };
      case 'LEGITIMATE':
        return {
          bg: 'var(--clean-green-bg)',
          color: 'var(--clean-green)',
          border: 'var(--clean-green-border)',
        };
      default:
        return {
          bg: 'var(--warning-amber-bg)',
          color: 'var(--warning-amber)',
          border: 'var(--warning-amber-border)',
        };
    }
  };

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, margin: 0, color: 'var(--text-main)' }}>
          Investigation History
        </h1>
        <p style={{ margin: '4px 0 0', fontSize: '14px', color: 'var(--text-muted)' }}>
          Chronological audit trail of past email threat analyses and SHA-256 evidence integrity logs
        </p>
      </div>

      {/* Search and Filter Controls */}
      <div
        className="card-base"
        style={{
          padding: '16px 20px',
          marginBottom: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px',
        }}
      >
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search
              size={18}
              color="var(--text-subtle)"
              style={{ position: 'absolute', left: '12px', top: '10px' }}
            />
            <input
              type="text"
              placeholder="Search by investigation ID, source, or SHA-256..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: '100%',
                padding: '9px 12px 9px 38px',
                borderRadius: '6px',
                border: '1px solid var(--border-strong)',
                fontSize: '13px',
                backgroundColor: 'var(--bg-app)',
                color: 'var(--text-main)',
              }}
            />
          </div>
        </div>

        {/* Filter chips */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Filter size={14} /> Filter:
          </span>
          {filterOptions.map((opt) => {
            const active = verdictFilter === opt.value;
            return (
              <button
                key={opt.value}
                type="button"
                onClick={() => setVerdictFilter(opt.value)}
                style={{
                  padding: '4px 10px',
                  borderRadius: '16px',
                  border: `1px solid ${active ? 'var(--primary)' : 'var(--border-light)'}`,
                  backgroundColor: active ? 'var(--primary-subtle)' : 'var(--bg-card)',
                  color: active ? 'var(--primary-hover)' : 'var(--text-muted)',
                  fontSize: '12px',
                  fontWeight: active ? 600 : 500,
                  cursor: 'pointer',
                }}
              >
                {opt.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div
          role="alert"
          style={{
            padding: '14px 16px',
            backgroundColor: 'var(--threat-red-bg)',
            border: '1px solid var(--threat-red-border)',
            borderRadius: '8px',
            color: 'var(--threat-red)',
            marginBottom: '20px',
            fontSize: '14px',
          }}
        >
          {error}
        </div>
      )}

      {/* History Table */}
      <div className="card-base" style={{ overflow: 'hidden' }}>
        {isLoading ? (
          <div style={{ padding: '48px 20px', textAlign: 'center', color: 'var(--text-subtle)', fontSize: '14px' }}>
            Loading audit history...
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: '60px 20px', textAlign: 'center' }}>
            <FileText size={44} color="var(--border-strong)" style={{ margin: '0 auto 12px' }} />
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-main)', margin: '0 0 4px' }}>
              No matching investigations found
            </h3>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0 }}>
              Try adjusting your search query or verdict filter.
            </p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
              <thead>
                <tr style={{ backgroundColor: 'var(--bg-subtle)', borderBottom: '1px solid var(--border-light)' }}>
                  <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-muted)' }}>Investigation ID</th>
                  <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-muted)' }}>Verdict</th>
                  <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-muted)' }}>Risk Indicator</th>
                  <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-muted)' }}>Evidence Count</th>
                  <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-muted)' }}>Date & Time (UTC)</th>
                  <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-muted)', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((inv) => {
                  const vStyle = getVerdictStyle(inv.final_verdict || 'NEEDS_REVIEW', inv.partial);
                  return (
                    <tr
                      key={inv.investigation_id}
                      onClick={() => navigate(`/investigations/${inv.investigation_id}`)}
                      style={{
                        borderBottom: '1px solid var(--border-light)',
                        cursor: 'pointer',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-subtle)')}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                    >
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontWeight: 600 }}>
                        {inv.investigation_id.slice(0, 10)}...
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px',
                            padding: '3px 8px',
                            borderRadius: '4px',
                            backgroundColor: vStyle.bg,
                            color: vStyle.color,
                            border: `1px solid ${vStyle.border}`,
                            fontWeight: 600,
                            fontSize: '12px',
                          }}
                        >
                          {inv.partial && <AlertTriangle size={12} />}
                          {getVerdictLabel(inv.final_verdict)}
                          {inv.partial && ' (Partial)'}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        {inv.risk_indicator !== null && inv.risk_indicator !== undefined ? (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <div
                              style={{
                                width: '50px',
                                height: '6px',
                                backgroundColor: 'var(--border-light)',
                                borderRadius: '3px',
                                overflow: 'hidden',
                              }}
                            >
                              <div
                                style={{
                                  width: `${inv.risk_indicator}%`,
                                  height: '100%',
                                  backgroundColor:
                                    inv.risk_indicator > 65
                                      ? 'var(--threat-red)'
                                      : inv.risk_indicator > 35
                                      ? 'var(--warning-amber)'
                                      : 'var(--clean-green)',
                                }}
                              />
                            </div>
                            <span style={{ fontWeight: 600, fontSize: '12px' }}>{inv.risk_indicator}/100</span>
                          </div>
                        ) : (
                          <span style={{ color: 'var(--text-subtle)' }}>N/A</span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px', color: 'var(--text-muted)' }}>
                        {inv.evidence_count} items
                      </td>
                      <td style={{ padding: '12px 16px', color: 'var(--text-subtle)', fontSize: '12px' }}>
                        {(inv.receipt_time_utc || inv.received_at) ? new Date(inv.receipt_time_utc || inv.received_at).toLocaleString() : 'N/A'}
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '8px' }}>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              navigate(`/investigations/${inv.investigation_id}`);
                            }}
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                              background: 'none',
                              border: 'none',
                              color: 'var(--primary)',
                              fontWeight: 600,
                              cursor: 'pointer',
                              padding: '4px 6px',
                            }}
                          >
                            <span>View</span>
                            <ChevronRight size={14} />
                          </button>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setDeletingId(inv.investigation_id);
                            }}
                            title="Delete investigation record"
                            aria-label={`Delete investigation ${inv.investigation_id}`}
                            style={{
                              background: 'none',
                              border: 'none',
                              color: 'var(--text-subtle)',
                              cursor: 'pointer',
                              padding: '4px 6px',
                            }}
                            onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--threat-red)')}
                            onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-subtle)')}
                          >
                            <Trash2 size={16} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      {deletingId && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-dialog-title"
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(15, 23, 42, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
            padding: '16px',
          }}
        >
          <div
            className="card-base"
            style={{
              maxWidth: '440px',
              width: '100%',
              padding: '24px',
              backgroundColor: 'var(--bg-card)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <div
                style={{
                  width: '40px',
                  height: '40px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--threat-red-bg)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--threat-red)',
                }}
              >
                <Trash2 size={20} />
              </div>
              <div>
                <h2 id="delete-dialog-title" style={{ fontSize: '16px', fontWeight: 600, margin: 0, color: 'var(--text-main)' }}>
                  Delete Investigation Record?
                </h2>
                <div style={{ fontSize: '12px', color: 'var(--text-subtle)', fontFamily: 'monospace' }}>
                  {deletingId}
                </div>
              </div>
            </div>

            <p style={{ fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.5, margin: '0 0 20px' }}>
              This action is permanent and irreversible. It removes the entire investigation state, reports, debate history, and cryptographic audit log from disk.
            </p>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                type="button"
                onClick={() => setDeletingId(null)}
                disabled={isDeleting}
                style={{
                  padding: '8px 16px',
                  borderRadius: '6px',
                  border: '1px solid var(--border-strong)',
                  backgroundColor: 'transparent',
                  color: 'var(--text-main)',
                  fontWeight: 600,
                  fontSize: '13px',
                  cursor: isDeleting ? 'not-allowed' : 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => handleDelete(deletingId)}
                disabled={isDeleting}
                style={{
                  padding: '8px 16px',
                  borderRadius: '6px',
                  border: 'none',
                  backgroundColor: 'var(--threat-red)',
                  color: '#ffffff',
                  fontWeight: 600,
                  fontSize: '13px',
                  cursor: isDeleting ? 'not-allowed' : 'pointer',
                }}
              >
                {isDeleting ? 'Deleting...' : 'Delete permanently'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
