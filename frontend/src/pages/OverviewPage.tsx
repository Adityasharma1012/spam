import React, { useEffect, useState } from 'react';
import { useRouter } from '../router';
import { api, ApiError } from '../api/client';
import { InvestigationSummary, ReadinessResponse, getVerdictLabel } from '../api/types';
import {
  Shield,
  PlusCircle,
  Clock,
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  RefreshCw,
  FileText,
} from 'lucide-react';

export const OverviewPage: React.FC = () => {
  const { navigate } = useRouter();
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [invList, ready] = await Promise.all([
        api.listInvestigations(),
        api.getReadiness().catch(() => null),
      ]);
      setInvestigations(invList);
      if (ready) setReadiness(ready);
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Failed to load investigations');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

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
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 700, margin: 0, color: 'var(--text-main)' }}>
            Investigation Overview
          </h1>
          <p style={{ margin: '4px 0 0', fontSize: '14px', color: 'var(--text-muted)' }}>
            Deterministic, multi-agent digital forensics and consensus deliberation
          </p>
        </div>

        <button
          type="button"
          onClick={() => navigate('/new')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            backgroundColor: 'var(--primary)',
            color: '#ffffff',
            border: 'none',
            borderRadius: '6px',
            padding: '10px 18px',
            fontSize: '14px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          <PlusCircle size={18} />
          <span>New analysis</span>
        </button>
      </div>

      {/* Readiness / System Status Widget */}
      {readiness && (
        <div
          className="card-base"
          style={{
            padding: '16px 20px',
            marginBottom: '24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderLeft: readiness.ready ? '4px solid var(--clean-green)' : '4px solid var(--warning-amber)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {readiness.ready ? (
              <CheckCircle2 size={24} color="var(--clean-green)" />
            ) : (
              <AlertTriangle size={24} color="var(--warning-amber)" />
            )}
            <div>
              <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--text-main)' }}>
                {readiness.ready ? 'All Platform Systems Ready' : 'Platform Operating in Degraded State'}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                {readiness.ready
                  ? 'ML Classifier, Privacy-Gated Gemini, and Laya Local Decision Engine operational'
                  : 'One or more forensic intelligence agents are offline or unvalidated'}
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={() => navigate('/status')}
            style={{
              padding: '6px 12px',
              backgroundColor: 'var(--bg-subtle)',
              border: '1px solid var(--border-light)',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: 600,
              color: 'var(--text-muted)',
              cursor: 'pointer',
            }}
          >
            Agent Details →
          </button>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div
          role="alert"
          style={{
            padding: '16px',
            backgroundColor: 'var(--threat-red-bg)',
            border: '1px solid var(--threat-red-border)',
            borderRadius: '8px',
            color: 'var(--threat-red)',
            marginBottom: '24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertTriangle size={20} />
            <span style={{ fontSize: '14px', fontWeight: 500 }}>{error}</span>
          </div>
          <button
            type="button"
            onClick={loadData}
            style={{
              padding: '6px 12px',
              backgroundColor: '#ffffff',
              border: '1px solid var(--threat-red-border)',
              borderRadius: '6px',
              color: 'var(--threat-red)',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Retry
          </button>
        </div>
      )}

      {/* Recent Investigations Card */}
      <div className="card-base" style={{ overflow: 'hidden' }}>
        <div
          style={{
            padding: '16px 20px',
            borderBottom: '1px solid var(--border-light)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Clock size={18} color="var(--primary)" />
            <h2 style={{ fontSize: '16px', fontWeight: 600, margin: 0, color: 'var(--text-main)' }}>
              Recent Forensic Investigations
            </h2>
          </div>
          <button
            type="button"
            onClick={loadData}
            aria-label="Refresh investigations list"
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: 'var(--text-subtle)',
              display: 'flex',
              alignItems: 'center',
              padding: '4px',
            }}
          >
            <RefreshCw size={16} />
          </button>
        </div>

        {/* Content */}
        {isLoading ? (
          <div style={{ padding: '48px 20px', textAlign: 'center', color: 'var(--text-subtle)', fontSize: '14px' }}>
            Loading investigations...
          </div>
        ) : investigations.length === 0 ? (
          <div style={{ padding: '60px 20px', textAlign: 'center' }}>
            <FileText size={48} color="var(--border-strong)" style={{ margin: '0 auto 16px' }} />
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-main)', margin: '0 0 8px' }}>
              No investigations found
            </h3>
            <p style={{ fontSize: '14px', color: 'var(--text-muted)', margin: '0 0 20px', maxWidth: '400px', marginLeft: 'auto', marginRight: 'auto' }}>
              Submit an email file (.eml) or paste raw email RFC822 content to trigger deterministic multi-agent analysis.
            </p>
            <button
              type="button"
              onClick={() => navigate('/new')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                backgroundColor: 'var(--primary)',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                padding: '10px 20px',
                fontSize: '14px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <PlusCircle size={16} />
              <span>Start New Analysis</span>
            </button>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
              <thead>
                <tr style={{ backgroundColor: 'var(--bg-subtle)', borderBottom: '1px solid var(--border-light)' }}>
                  <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-muted)' }}>Investigation ID</th>
                  <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-muted)' }}>Verdict</th>
                  <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-muted)' }}>Risk Indicator</th>
                  <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-muted)' }}>Evidence Items</th>
                  <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-muted)' }}>Timestamp (UTC)</th>
                  <th style={{ padding: '12px 16px', fontWeight: 600, color: 'var(--text-muted)', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {investigations.map((inv) => {
                  const vStyle = getVerdictStyle(inv.final_verdict || 'NEEDS_REVIEW', inv.partial);
                  return (
                    <tr
                      key={inv.investigation_id}
                      onClick={() => navigate(`/investigations/${inv.investigation_id}`)}
                      style={{
                        borderBottom: '1px solid var(--border-light)',
                        cursor: 'pointer',
                        transition: 'background-color 0.1s ease',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-subtle)')}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                    >
                      <td style={{ padding: '12px 16px', fontFamily: 'monospace', fontWeight: 600 }}>
                        {inv.investigation_id.slice(0, 8)}...
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
                        {inv.risk_indicator !== undefined && inv.risk_indicator !== null ? (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <div
                              style={{
                                width: '60px',
                                height: '6px',
                                backgroundColor: 'var(--border-light)',
                                borderRadius: '3px',
                                overflow: 'hidden',
                              }}
                            >
                              <div
                                style={{
                                  width: `${Math.min(100, Math.max(0, inv.risk_indicator))}%`,
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
                            padding: '4px 8px',
                          }}
                        >
                          <span>View</span>
                          <ChevronRight size={14} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
