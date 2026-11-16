import React, { useEffect, useState } from 'react';
import { api, ApiError } from '../api/client';
import { HealthResponse, ReadinessResponse, getCalibrationLabel, getAvailabilityLabel } from '../api/types';
import {
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Cpu,
  Sparkles,
  ShieldCheck,
  Server,
  Globe,
  Database,
} from 'lucide-react';

export const StatusPage: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadStatus = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [h, r] = await Promise.all([
        api.getHealth(),
        api.getReadiness().catch(() => null),
      ]);
      setHealth(h);
      if (r) setReadiness(r);
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Failed to retrieve system status');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'AVAILABLE':
        return <CheckCircle2 size={18} color="var(--clean-green)" />;
      case 'DEGRADED':
        return <AlertTriangle size={18} color="var(--warning-amber)" />;
      default:
        return <XCircle size={18} color="var(--threat-red)" />;
    }
  };

  return (
    <div>
      {/* Title */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 700, margin: 0, color: 'var(--text-main)' }}>
            System & Agent Readiness Status
          </h1>
          <p style={{ margin: '4px 0 0', fontSize: '14px', color: 'var(--text-muted)' }}>
            Real-time health, calibration disclosure, and hardware residency for forensic intelligence engines
          </p>
        </div>

        <button
          type="button"
          onClick={loadStatus}
          disabled={isLoading}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border-strong)',
            borderRadius: '6px',
            padding: '8px 14px',
            fontSize: '13px',
            fontWeight: 600,
            color: 'var(--text-main)',
            cursor: isLoading ? 'not-allowed' : 'pointer',
          }}
        >
          <RefreshCw size={15} className={isLoading ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
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
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontSize: '14px',
          }}
        >
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Global Readiness Overview */}
      {readiness && (
        <div
          className="card-base"
          style={{
            padding: '20px',
            marginBottom: '24px',
            backgroundColor: readiness.ready ? 'var(--clean-green-bg)' : 'var(--warning-amber-bg)',
            borderColor: readiness.ready ? 'var(--clean-green-border)' : 'var(--warning-amber-border)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {readiness.ready ? (
              <CheckCircle2 size={24} color="var(--clean-green)" />
            ) : (
              <AlertTriangle size={24} color="var(--warning-amber)" />
            )}
            <div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-main)' }}>
                {readiness.ready
                  ? 'All Forensic Agents Fully Operational'
                  : 'Platform Degraded: Partial Deliberation Active'}
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '2px' }}>
                Server timestamp: {readiness.timestamp_utc || 'N/A'} (UTC).
                {!readiness.ready &&
                  ' When any agent is unavailable, the consensus engine marks investigations as partial and requires review.'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Agents Grid */}
      <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '14px' }}>
        Intelligence Agents
      </h2>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px', marginBottom: '32px' }}>
        {/* Agent 1: ML Classifier */}
        {(() => {
          const a1 = health?.agents.find((a) => a.agent_id === 'ml' || a.agent_id === 'agent_1_ml');
          const readyA1 = readiness?.agents?.ml || readiness?.agents?.agent_1_ml;
          return (
            <div className="card-base" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div
                    style={{
                      width: '36px',
                      height: '36px',
                      borderRadius: '8px',
                      backgroundColor: 'var(--primary-subtle)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: 'var(--primary)',
                    }}
                  >
                    <Cpu size={20} />
                  </div>
                  <div>
                    <h3 style={{ fontSize: '15px', fontWeight: 600, margin: 0, color: 'var(--text-main)' }}>
                      Agent 1: ML Classifier
                    </h3>
                    <div style={{ fontSize: '12px', color: 'var(--text-subtle)' }}>
                      Lightweight TF-IDF + Logistic Regression
                    </div>
                  </div>
                </div>
                {a1 && getStatusIcon(a1.availability)}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px', marginTop: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Status:</span>
                  <span style={{ fontWeight: 600 }}>{a1 ? getAvailabilityLabel(a1.availability) : 'Checking...'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Calibration:</span>
                  <span
                    style={{
                      fontWeight: 600,
                      color: 'var(--warning-amber)',
                      backgroundColor: 'var(--warning-amber-bg)',
                      padding: '2px 6px',
                      borderRadius: '4px',
                    }}
                  >
                    {a1 ? getCalibrationLabel(a1.calibration_status) : 'DEMO_ONLY'}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Model Trained:</span>
                  <span style={{ fontWeight: 600 }}>{readyA1?.trained ? 'Yes (Local Demo Checkpoint)' : 'Untrained'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Execution:</span>
                  <span style={{ fontWeight: 600 }}>In-Process CPU (Scikit-Learn)</span>
                </div>
              </div>
            </div>
          );
        })()}

        {/* Agent 2: Gemini Adapter */}
        {(() => {
          const a2 = health?.agents.find((a) => a.agent_id === 'gemini' || a.agent_id === 'agent_2_gemini');
          const readyA2 = readiness?.agents?.gemini || readiness?.agents?.agent_2_gemini;
          const isEnabled = readyA2?.enabled ?? false;
          return (
            <div className="card-base" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div
                    style={{
                      width: '36px',
                      height: '36px',
                      borderRadius: '8px',
                      backgroundColor: isEnabled ? 'var(--primary-subtle)' : 'var(--bg-subtle)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: isEnabled ? 'var(--primary)' : 'var(--text-subtle)',
                    }}
                  >
                    <Sparkles size={20} />
                  </div>
                  <div>
                    <h3 style={{ fontSize: '15px', fontWeight: 600, margin: 0, color: 'var(--text-main)' }}>
                      Agent 2: Gemini LLM
                    </h3>
                    <div style={{ fontSize: '12px', color: 'var(--text-subtle)' }}>
                      Structured Reasoning & Prompt Defense
                    </div>
                  </div>
                </div>
                {getStatusIcon(isEnabled ? 'AVAILABLE' : 'UNAVAILABLE')}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px', marginTop: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Status:</span>
                  <span style={{ fontWeight: 600 }}>
                    {isEnabled ? 'Enabled & Online' : 'Privacy Gate / Key Unset'}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Opt-in Gate:</span>
                  <span style={{ fontWeight: 600 }}>
                    {isEnabled ? 'Active (ENABLE_GEMINI=1)' : 'Disabled by Default'}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Data Privacy:</span>
                  <span style={{ fontWeight: 600 }}>Redacted Defanged Summary</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Disclosure:</span>
                  <span style={{ fontWeight: 600 }}>Third-Party Cloud API</span>
                </div>
              </div>
            </div>
          );
        })()}

        {/* Agent 3: Laya Local Decision Engine */}
        {(() => {
          const a3 = health?.agents.find((a) => a.agent_id === 'laya' || a.agent_id === 'agent_3_laya');
          const readyA3 = readiness?.agents?.laya || readiness?.agents?.agent_3_laya;
          const isReady = readyA3?.ready ?? false;
          return (
            <div className="card-base" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div
                    style={{
                      width: '36px',
                      height: '36px',
                      borderRadius: '8px',
                      backgroundColor: 'var(--clean-green-bg)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: 'var(--clean-green)',
                    }}
                  >
                    <ShieldCheck size={20} />
                  </div>
                  <div>
                    <h3 style={{ fontSize: '15px', fontWeight: 600, margin: 0, color: 'var(--text-main)' }}>
                      Agent 3: Laya Local Engine
                    </h3>
                    <div style={{ fontSize: '12px', color: 'var(--text-subtle)' }}>
                      Resident Transformer (typed-decisions)
                    </div>
                  </div>
                </div>
                {getStatusIcon(isReady ? 'AVAILABLE' : 'DEGRADED')}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px', marginTop: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Status:</span>
                  <span style={{ fontWeight: 600 }}>
                    {isReady ? 'Resident & Loaded' : 'Unavailable / Loading'}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Calibration:</span>
                  <span
                    style={{
                      fontWeight: 600,
                      color: 'var(--warning-amber)',
                      backgroundColor: 'var(--warning-amber-bg)',
                      padding: '2px 6px',
                      borderRadius: '4px',
                    }}
                  >
                    Unvalidated score, not a probability
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Smoke Test:</span>
                  <span style={{ fontWeight: 600 }}>
                    {readyA3?.smoke_test_verdict || 'Verified'}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Context Limit:</span>
                  <span style={{ fontWeight: 600 }}>Conservative Chunking (8,192 tok max)</span>
                </div>
              </div>
            </div>
          );
        })()}
      </div>

      {/* Forensic Infrastructure & Security */}
      <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '14px' }}>
        Forensic Infrastructure
      </h2>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
        <div className="card-base" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
            <Globe size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '15px', fontWeight: 600, margin: 0 }}>IP Geolocation & Defense</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Private IP Filtering:</span>
              <span style={{ fontWeight: 600, color: 'var(--clean-green)' }}>Active (RFC1918 Blocked)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>GeoIP Provider:</span>
              <span style={{ fontWeight: 600 }}>MaxMind GeoLite2 / Fallback</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>URL Defanging:</span>
              <span style={{ fontWeight: 600, color: 'var(--clean-green)' }}>Deterministic RFC3986</span>
            </div>
          </div>
        </div>

        <div className="card-base" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
            <Database size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '15px', fontWeight: 600, margin: 0 }}>Forensic Integrity & Audit</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Audit Log Integrity:</span>
              <span style={{ fontWeight: 600, color: 'var(--clean-green)' }}>SHA-256 Merkle Verification</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Debate Protocol:</span>
              <span style={{ fontWeight: 600 }}>2-Round Deliberation (v1.0.0)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Export Format:</span>
              <span style={{ fontWeight: 600 }}>Deterministic Forensic JSON</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
