import React, { useEffect, useState, useRef } from 'react';
import { useRouter } from '../router';
import { api, ApiError } from '../api/client';
import {
  InvestigationState,
  getVerdictLabel,
  getCalibrationLabel,
  getAvailabilityLabel,
  EvidenceItem,
  AgentReport,
} from '../api/types';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Download,
  PlusCircle,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Cpu,
  Sparkles,
  Layers,
  ArrowRight,
  Globe,
  Hash,
  Clock,
  FileText,
  RefreshCw,
  ExternalLink,
  Info,
} from 'lucide-react';

export const InvestigationDetailPage: React.FC = () => {
  const { params, navigate } = useRouter();
  const investigationId = params.id;

  const [state, setState] = useState<InvestigationState | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [evidenceFilter, setEvidenceFilter] = useState<string>('ALL');
  const [evidenceSearch, setEvidenceSearch] = useState<string>('');
  const [highlightedEvidenceId, setHighlightedEvidenceId] = useState<string | null>(null);
  const [isDebateExpanded, setIsDebateExpanded] = useState<boolean>(true);
  const [activeNavSection, setActiveNavSection] = useState<string>('summary');
  const [showStickySummary, setShowStickySummary] = useState<boolean>(false);

  const summaryRef = useRef<HTMLDivElement>(null);
  const riskRef = useRef<HTMLDivElement>(null);
  const keyEvidenceRef = useRef<HTMLDivElement>(null);
  const agentsRef = useRef<HTMLDivElement>(null);
  const debateRef = useRef<HTMLDivElement>(null);
  const evidenceCatalogRef = useRef<HTMLDivElement>(null);
  const forensicsRef = useRef<HTMLDivElement>(null);

  const loadInvestigation = async () => {
    if (!investigationId) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getInvestigation(investigationId);
      setState(data);
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Failed to load investigation');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadInvestigation();
  }, [investigationId]);

  // Section observer for sticky section navigator
  useEffect(() => {
    const handleScroll = () => {
      if (summaryRef.current) {
        const rect = summaryRef.current.getBoundingClientRect();
        setShowStickySummary(rect.bottom < 64);
      }

      const sections = [
        { id: 'summary', ref: summaryRef },
        { id: 'risk', ref: riskRef },
        { id: 'key-evidence', ref: keyEvidenceRef },
        { id: 'agents', ref: agentsRef },
        { id: 'debate', ref: debateRef },
        { id: 'evidence-catalog', ref: evidenceCatalogRef },
        { id: 'forensics', ref: forensicsRef },
      ];

      for (const section of sections) {
        if (section.ref.current) {
          const rect = section.ref.current.getBoundingClientRect();
          if (rect.top <= 140 && rect.bottom >= 140) {
            setActiveNavSection(section.id);
            break;
          }
        }
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const scrollToSection = (ref: React.RefObject<HTMLDivElement | null>) => {
    if (ref.current) {
      const yOffset = -90;
      const y = ref.current.getBoundingClientRect().top + window.pageYOffset + yOffset;
      window.scrollTo({ top: y, behavior: 'smooth' });
    }
  };

  if (isLoading) {
    return (
      <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--text-subtle)' }}>
        <RefreshCw size={28} className="animate-spin" style={{ margin: '0 auto 12px' }} />
        <div style={{ fontSize: '15px', fontWeight: 600 }}>Loading investigation state...</div>
        <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Retrieving forensic audit trail and evidence graphs</div>
      </div>
    );
  }

  if (error || !state) {
    return (
      <div
        role="alert"
        className="card-base"
        style={{
          padding: '32px',
          textAlign: 'center',
          borderColor: 'var(--threat-red-border)',
        }}
      >
        <AlertTriangle size={36} color="var(--threat-red)" style={{ margin: '0 auto 12px' }} />
        <h2 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-main)', margin: '0 0 8px' }}>
          Unable to Load Investigation
        </h2>
        <p style={{ fontSize: '14px', color: 'var(--text-muted)', margin: '0 0 20px' }}>
          {error || 'Investigation not found or invalid response shape received.'}
        </p>
        <div style={{ display: 'flex', justifyContent: 'center', gap: '12px' }}>
          <button
            type="button"
            onClick={loadInvestigation}
            style={{
              padding: '8px 16px',
              backgroundColor: 'var(--primary)',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontWeight: 600,
              fontSize: '13px',
              cursor: 'pointer',
            }}
          >
            Retry
          </button>
          <button
            type="button"
            onClick={() => navigate('/history')}
            style={{
              padding: '8px 16px',
              backgroundColor: 'var(--bg-subtle)',
              border: '1px solid var(--border-strong)',
              borderRadius: '6px',
              fontWeight: 600,
              fontSize: '13px',
              cursor: 'pointer',
            }}
          >
            Return to History
          </button>
        </div>
      </div>
    );
  }

  const final = state.final_result;
  const isPartial = final?.partial ?? false;
  const verdict = final?.final_verdict || 'NEEDS_REVIEW';
  const confidence = final?.confidence ?? 0;
  const reasons = final?.reasons || [];
  const riskIndicator = final?.risk_indicator;
  const isPromptInjection = final?.prompt_injection_detected ?? false;

  // Determine styling for verdict
  // Note: Data honesty rule: if partial is true, LEGITIMATE must NEVER look plain green safe!
  let verdictStyle = {
    bg: 'var(--threat-red-bg)',
    color: 'var(--threat-red)',
    border: 'var(--threat-red-border)',
    icon: ShieldAlert,
  };

  if (isPartial) {
    verdictStyle = {
      bg: 'var(--warning-amber-bg)',
      color: 'var(--warning-amber)',
      border: 'var(--warning-amber-border)',
      icon: AlertTriangle,
    };
  } else if (verdict === 'LEGITIMATE') {
    verdictStyle = {
      bg: 'var(--clean-green-bg)',
      color: 'var(--clean-green)',
      border: 'var(--clean-green-border)',
      icon: ShieldCheck,
    };
  } else if (verdict === 'SPAM' || verdict === 'SUSPICIOUS') {
    verdictStyle = {
      bg: 'var(--suspicious-orange-bg)',
      color: 'var(--suspicious-orange)',
      border: 'var(--suspicious-orange-border)',
      icon: AlertTriangle,
    };
  } else if (verdict === 'NEEDS_REVIEW') {
    verdictStyle = {
      bg: 'var(--warning-amber-bg)',
      color: 'var(--warning-amber)',
      border: 'var(--warning-amber-border)',
      icon: AlertTriangle,
    };
  }

  const VerdictIcon = verdictStyle.icon;

  // Separate evidence items into supporting vs conflicting
  const criticalOrHighEvidence = state.evidence.filter(
    (e) => e.severity === 'CRITICAL' || e.severity === 'HIGH' || e.severity === 'MEDIUM'
  );
  const infoOrLowEvidence = state.evidence.filter(
    (e) => e.severity === 'INFO' || e.severity === 'LOW'
  );

  // Filtered evidence items for catalog
  const filteredEvidence = state.evidence.filter((item) => {
    if (evidenceFilter !== 'ALL' && item.category !== evidenceFilter) return false;
    if (evidenceSearch.trim()) {
      const q = evidenceSearch.toLowerCase();
      const matchDesc = item.description.toLowerCase().includes(q);
      const matchId = item.evidence_id.toLowerCase().includes(q);
      const matchSource = item.source.toLowerCase().includes(q);
      return matchDesc || matchId || matchSource;
    }
    return true;
  });

  const categories = ['ALL', ...Array.from(new Set(state.evidence.map((e) => e.category)))];

  return (
    <div>
      {/* Sticky Compact Header for Narrow Screens / Scrolling past fold */}
      {showStickySummary && (
        <div
          style={{
            position: 'fixed',
            top: 64,
            left: 0,
            right: 0,
            backgroundColor: 'var(--bg-card)',
            borderBottom: '1px solid var(--border-light)',
            padding: '8px 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            zIndex: 25,
            boxShadow: '0 2px 4px rgba(0,0,0,0.04)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '4px 10px',
                borderRadius: '4px',
                backgroundColor: verdictStyle.bg,
                color: verdictStyle.color,
                border: `1px solid ${verdictStyle.border}`,
                fontWeight: 700,
                fontSize: '13px',
              }}
            >
              <VerdictIcon size={14} />
              {getVerdictLabel(verdict)}
            </span>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
              Confidence: {(confidence * 100).toFixed(0)}%
            </span>
            {riskIndicator !== null && riskIndicator !== undefined && (
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-main)' }}>
                Risk: {riskIndicator}/100
              </span>
            )}
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <a
              href={api.getExportUrl(state.investigation_id)}
              download={`investigation-${state.investigation_id}.json`}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 12px',
                backgroundColor: 'var(--bg-subtle)',
                border: '1px solid var(--border-strong)',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 600,
                color: 'var(--text-main)',
                textDecoration: 'none',
              }}
            >
              <Download size={14} />
              <span>Export</span>
            </a>
          </div>
        </div>
      )}

      {/* Sticky Section Navigator */}
      <nav
        aria-label="Investigation sections"
        style={{
          display: 'flex',
          gap: '8px',
          padding: '8px 0',
          marginBottom: '20px',
          borderBottom: '1px solid var(--border-light)',
          position: 'sticky',
          top: 64,
          backgroundColor: 'var(--bg-app)',
          zIndex: 20,
          overflowX: 'auto',
          whiteSpace: 'nowrap',
        }}
      >
        {[
          { id: 'summary', label: 'Summary', ref: summaryRef },
          { id: 'risk', label: 'Risk Indicator', ref: riskRef },
          { id: 'key-evidence', label: 'Key Signals', ref: keyEvidenceRef },
          { id: 'agents', label: 'Agents', ref: agentsRef },
          { id: 'debate', label: 'Debate', ref: debateRef },
          { id: 'evidence-catalog', label: `Evidence (${state.evidence.length})`, ref: evidenceCatalogRef },
          { id: 'forensics', label: 'Forensic Audit', ref: forensicsRef },
        ].map((item) => {
          const isActive = activeNavSection === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => scrollToSection(item.ref)}
              style={{
                padding: '6px 12px',
                borderRadius: '16px',
                border: `1px solid ${isActive ? 'var(--primary)' : 'var(--border-light)'}`,
                backgroundColor: isActive ? 'var(--primary-subtle)' : 'var(--bg-card)',
                color: isActive ? 'var(--primary-hover)' : 'var(--text-muted)',
                fontWeight: isActive ? 600 : 500,
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              {item.label}
            </button>
          );
        })}
      </nav>

      {/* Section 1: Verdict Summary Card */}
      <div ref={summaryRef} className="card-base" style={{ padding: '24px', marginBottom: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <span style={{ fontSize: '13px', color: 'var(--text-subtle)' }}>Investigation ID:</span>
              <code style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-main)' }}>
                {state.investigation_id}
              </code>
              <button
                type="button"
                onClick={() => copyToClipboard(state.investigation_id, 'id')}
                aria-label="Copy investigation ID"
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: copiedText === 'id' ? 'var(--clean-green)' : 'var(--text-subtle)',
                  padding: '2px',
                }}
              >
                {copiedText === 'id' ? <Check size={14} /> : <Copy size={14} />}
              </button>
            </div>

            <h1 style={{ fontSize: '26px', fontWeight: 800, margin: '0 0 10px', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '6px 14px',
                  borderRadius: '6px',
                  backgroundColor: verdictStyle.bg,
                  color: verdictStyle.color,
                  border: `1px solid ${verdictStyle.border}`,
                  fontSize: '20px',
                }}
              >
                <VerdictIcon size={24} />
                {getVerdictLabel(verdict)}
              </span>
            </h1>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '13px', color: 'var(--text-muted)', flexWrap: 'wrap' }}>
              <span>
                <strong>Confidence:</strong> {(confidence * 100).toFixed(0)}%
              </span>
              <span style={{ color: 'var(--border-strong)' }}>•</span>
              <span style={{ color: 'var(--warning-amber)', fontWeight: 600 }}>
                Unvalidated score, not a probability
              </span>
              <span style={{ color: 'var(--border-strong)' }}>•</span>
              <span>
                <strong>Rule:</strong> {final?.matched_rule_id || 'DEFAULT_NEEDS_REVIEW'}
              </span>
            </div>
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: '10px' }}>
            <a
              href={api.getExportUrl(state.investigation_id)}
              download={`investigation-${state.investigation_id}.json`}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '10px 16px',
                backgroundColor: 'var(--bg-card)',
                border: '1px solid var(--border-strong)',
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: 600,
                color: 'var(--text-main)',
                textDecoration: 'none',
              }}
            >
              <Download size={16} />
              <span>Export Audit JSON</span>
            </a>

            <button
              type="button"
              onClick={() => navigate('/new')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '10px 16px',
                backgroundColor: 'var(--primary)',
                border: 'none',
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: 600,
                color: '#ffffff',
                cursor: 'pointer',
              }}
            >
              <PlusCircle size={16} />
              <span>New Analysis</span>
            </button>
          </div>
        </div>

        {/* Prompt Injection Detection Alert */}
        {isPromptInjection && (
          <div
            role="alert"
            style={{
              marginTop: '20px',
              padding: '14px 16px',
              backgroundColor: 'var(--threat-red-bg)',
              border: '1px solid var(--threat-red-border)',
              borderRadius: '6px',
              color: 'var(--threat-red)',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '12px',
              fontSize: '13px',
            }}
          >
            <ShieldAlert size={20} style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong style={{ display: 'block', fontSize: '14px', marginBottom: '2px' }}>
                Prompt Injection Adversarial Attack Detected
              </strong>
              Adversarial instructions attempting to override model safety instructions or tamper with deliberation protocols were detected in email body/headers. Content was quarantined and evaluated defensively.
            </div>
          </div>
        )}

        {/* Persistent Partial Analysis Banner with reasons[] */}
        {isPartial && (
          <div
            role="alert"
            style={{
              marginTop: '16px',
              padding: '16px',
              backgroundColor: 'var(--warning-amber-bg)',
              border: '1px solid var(--warning-amber-border)',
              borderRadius: '6px',
              color: 'var(--warning-amber)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '14px', marginBottom: '6px' }}>
              <AlertTriangle size={18} />
              <span>Partial Forensic Analysis — Review Required</span>
            </div>
            <p style={{ margin: '0 0 10px', fontSize: '13px', color: 'var(--text-main)' }}>
              This verdict was formed under incomplete consensus or degraded agent availability. It must not be treated as a validated clean verdict.
            </p>
            {reasons.length > 0 && (
              <div style={{ fontSize: '12px' }}>
                <span style={{ fontWeight: 600, display: 'block', marginBottom: '4px' }}>System Deliberation Caveats:</span>
                <ul style={{ margin: 0, paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  {reasons.map((r, i) => (
                    <li key={i} style={{ color: 'var(--text-muted)' }}>
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Section 2: Deterministic Risk Indicator */}
      <div ref={riskRef} className="card-base" style={{ padding: '24px', marginBottom: '24px' }}>
        <h2 style={{ fontSize: '16px', fontWeight: 700, margin: '0 0 8px', color: 'var(--text-main)' }}>
          Forensic Risk Indicator
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: '0 0 16px' }}>
          Additive, deterministic heuristic score based on consensus verdict severity, critical auth failures, prompt injections, and verified malicious indicators. <strong>Labeled risk indicator, not a probability.</strong>
        </p>

        {riskIndicator !== null && riskIndicator !== undefined ? (
          <div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '12px', marginBottom: '10px' }}>
              <span style={{ fontSize: '32px', fontWeight: 800, color: 'var(--text-main)' }}>
                {riskIndicator}
              </span>
              <span style={{ fontSize: '16px', color: 'var(--text-subtle)' }}>/ 100</span>
              <span
                style={{
                  fontSize: '12px',
                  fontWeight: 600,
                  padding: '2px 8px',
                  borderRadius: '4px',
                  backgroundColor:
                    riskIndicator > 65
                      ? 'var(--threat-red-bg)'
                      : riskIndicator > 35
                      ? 'var(--warning-amber-bg)'
                      : 'var(--clean-green-bg)',
                  color:
                    riskIndicator > 65
                      ? 'var(--threat-red)'
                      : riskIndicator > 35
                      ? 'var(--warning-amber)'
                      : 'var(--clean-green)',
                }}
              >
                {riskIndicator > 65
                  ? 'High Forensic Risk'
                  : riskIndicator > 35
                  ? 'Elevated Risk / Degraded'
                  : 'Low Risk Indicators'}
              </span>
            </div>

            {/* Visual Gauge Bar */}
            <div
              style={{
                width: '100%',
                height: '10px',
                backgroundColor: 'var(--border-light)',
                borderRadius: '5px',
                overflow: 'hidden',
                marginBottom: '12px',
              }}
            >
              <div
                style={{
                  width: `${Math.min(100, Math.max(0, riskIndicator))}%`,
                  height: '100%',
                  backgroundColor:
                    riskIndicator > 65
                      ? 'var(--threat-red)'
                      : riskIndicator > 35
                      ? 'var(--warning-amber)'
                      : 'var(--clean-green)',
                  transition: 'width 0.3s ease',
                }}
              />
            </div>

            <div style={{ fontSize: '12px', color: 'var(--text-subtle)' }}>
              {isPartial || verdict === 'NEEDS_REVIEW'
                ? 'Score is capped and labeled indicative due to partial deliberation or missing agent verification.'
                : 'Score deterministically reflects weighted findings across 3 independent forensic engines.'}
            </div>
          </div>
        ) : (
          <div style={{ fontSize: '13px', color: 'var(--text-subtle)' }}>
            No risk indicator provided by consensus engine.
          </div>
        )}
      </div>

      {/* Section 3: Strongest Supporting vs Conflicting Signals */}
      <div ref={keyEvidenceRef} className="card-base" style={{ padding: '24px', marginBottom: '24px' }}>
        <h2 style={{ fontSize: '16px', fontWeight: 700, margin: '0 0 16px', color: 'var(--text-main)' }}>
          Forensic Evidence Signals
        </h2>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
          {/* Threat / Suspicious Indicators */}
          <div style={{ border: '1px solid var(--border-light)', borderRadius: '6px', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <ShieldAlert size={18} color="var(--threat-red)" />
              <h3 style={{ fontSize: '14px', fontWeight: 600, margin: 0, color: 'var(--text-main)' }}>
                Threat & Anomaly Indicators ({criticalOrHighEvidence.length})
              </h3>
            </div>
            {criticalOrHighEvidence.length === 0 ? (
              <div style={{ fontSize: '13px', color: 'var(--text-subtle)' }}>
                No high or critical severity anomalies detected.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {criticalOrHighEvidence.slice(0, 4).map((item) => (
                  <div
                    key={item.evidence_id}
                    onClick={() => {
                      setHighlightedEvidenceId(item.evidence_id);
                      scrollToSection(evidenceCatalogRef);
                    }}
                    style={{
                      padding: '8px 10px',
                      backgroundColor: 'var(--threat-red-bg)',
                      border: '1px solid var(--threat-red-border)',
                      borderRadius: '4px',
                      fontSize: '12px',
                      cursor: 'pointer',
                    }}
                  >
                    <div style={{ fontWeight: 600, color: 'var(--threat-red)' }}>
                      [{item.category}] {item.severity}
                    </div>
                    <div style={{ color: 'var(--text-main)', marginTop: '2px' }}>{item.description}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Legitimate / Neutral Signals */}
          <div style={{ border: '1px solid var(--border-light)', borderRadius: '6px', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <ShieldCheck size={18} color="var(--clean-green)" />
              <h3 style={{ fontSize: '14px', fontWeight: 600, margin: 0, color: 'var(--text-main)' }}>
                Low-Severity & Baseline Signals ({infoOrLowEvidence.length})
              </h3>
            </div>
            {infoOrLowEvidence.length === 0 ? (
              <div style={{ fontSize: '13px', color: 'var(--text-subtle)' }}>
                No baseline evidence recorded.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {infoOrLowEvidence.slice(0, 4).map((item) => (
                  <div
                    key={item.evidence_id}
                    onClick={() => {
                      setHighlightedEvidenceId(item.evidence_id);
                      scrollToSection(evidenceCatalogRef);
                    }}
                    style={{
                      padding: '8px 10px',
                      backgroundColor: 'var(--bg-subtle)',
                      border: '1px solid var(--border-light)',
                      borderRadius: '4px',
                      fontSize: '12px',
                      cursor: 'pointer',
                    }}
                  >
                    <div style={{ fontWeight: 600, color: 'var(--text-muted)' }}>
                      [{item.category}] {item.severity}
                    </div>
                    <div style={{ color: 'var(--text-main)', marginTop: '2px' }}>{item.description}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Section 4: 3 Multi-Agent Reports */}
      <div ref={agentsRef} className="card-base" style={{ padding: '24px', marginBottom: '24px' }}>
        <h2 style={{ fontSize: '16px', fontWeight: 700, margin: '0 0 16px', color: 'var(--text-main)' }}>
          Forensic Agent Deliberation Reports
        </h2>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
          {/* Agent 1 ML */}
          {renderAgentCard(
            'Agent 1: ML Classifier',
            'agent_1_ml',
            Cpu,
            state.reports.filter((r) => r.agent_id === 'ml' || r.agent_id === 'agent_1_ml')
          )}

          {/* Agent 2 Gemini */}
          {renderAgentCard(
            'Agent 2: Gemini LLM',
            'agent_2_gemini',
            Sparkles,
            state.reports.filter((r) => r.agent_id === 'gemini' || r.agent_id === 'agent_2_gemini')
          )}

          {/* Agent 3 Laya */}
          {renderAgentCard(
            'Agent 3: Laya Local Engine',
            'agent_3_laya',
            Shield,
            state.reports.filter((r) => r.agent_id === 'laya' || r.agent_id === 'agent_3_laya')
          )}
        </div>
      </div>

      {/* Section 5: Expandable Debate Timeline */}
      <div ref={debateRef} className="card-base" style={{ padding: '24px', marginBottom: '24px' }}>
        <div
          onClick={() => setIsDebateExpanded(!isDebateExpanded)}
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            cursor: 'pointer',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Layers size={18} color="var(--primary)" />
            <h2 style={{ fontSize: '16px', fontWeight: 700, margin: 0, color: 'var(--text-main)' }}>
              Two-Round Debate Timeline ({state.debate_messages.length} exchanges)
            </h2>
          </div>
          {isDebateExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
        </div>

        {isDebateExpanded && (
          <div style={{ marginTop: '20px' }}>
            {state.debate_messages.length === 0 ? (
              <div style={{ fontSize: '13px', color: 'var(--text-subtle)', fontStyle: 'italic' }}>
                No multi-round debate exchanges required or agents unanimously agreed in Round 1.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {state.debate_messages.map((msg, idx) => (
                  <div
                    key={idx}
                    style={{
                      borderLeft: '3px solid var(--primary)',
                      padding: '12px 16px',
                      backgroundColor: 'var(--bg-subtle)',
                      borderRadius: '0 6px 6px 0',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', fontWeight: 600, marginBottom: '6px' }}>
                      <span style={{ color: 'var(--primary-hover)' }}>{msg.from_agent}</span>
                      <span style={{ color: 'var(--text-subtle)' }}>Round {msg.round}</span>
                    </div>
                    <div style={{ fontSize: '13px', color: 'var(--text-main)', lineHeight: 1.5 }}>
                      {msg.summary}
                    </div>
                    {msg.cited_evidence_ids.length > 0 && (
                      <div style={{ marginTop: '8px', display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                        {msg.cited_evidence_ids.map((id) => (
                          <span
                            key={id}
                            onClick={() => {
                              setHighlightedEvidenceId(id);
                              scrollToSection(evidenceCatalogRef);
                            }}
                            style={{
                              fontSize: '11px',
                              fontFamily: 'monospace',
                              padding: '2px 6px',
                              borderRadius: '4px',
                              backgroundColor: 'var(--bg-card)',
                              border: '1px solid var(--border-light)',
                              cursor: 'pointer',
                            }}
                          >
                            #{id}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Section 6: Comprehensive Evidence Catalog */}
      <div ref={evidenceCatalogRef} className="card-base" style={{ padding: '24px', marginBottom: '24px' }}>
        <h2 style={{ fontSize: '16px', fontWeight: 700, margin: '0 0 16px', color: 'var(--text-main)' }}>
          Forensic Evidence Catalog ({state.evidence.length} parsed items)
        </h2>

        {/* Filter and Search */}
        <div style={{ display: 'flex', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
          <input
            type="text"
            placeholder="Search evidence description or ID..."
            value={evidenceSearch}
            onChange={(e) => setEvidenceSearch(e.target.value)}
            style={{
              flex: 1,
              minWidth: '220px',
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid var(--border-strong)',
              fontSize: '13px',
              backgroundColor: 'var(--bg-app)',
              color: 'var(--text-main)',
            }}
          />

          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {categories.map((cat) => (
              <button
                key={cat}
                type="button"
                onClick={() => setEvidenceFilter(cat)}
                style={{
                  padding: '4px 10px',
                  borderRadius: '16px',
                  border: `1px solid ${evidenceFilter === cat ? 'var(--primary)' : 'var(--border-light)'}`,
                  backgroundColor: evidenceFilter === cat ? 'var(--primary-subtle)' : 'var(--bg-card)',
                  color: evidenceFilter === cat ? 'var(--primary-hover)' : 'var(--text-muted)',
                  fontSize: '12px',
                  fontWeight: evidenceFilter === cat ? 600 : 500,
                  cursor: 'pointer',
                }}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Evidence Items List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {filteredEvidence.map((item) => {
            const isHighlighted = highlightedEvidenceId === item.evidence_id;
            return (
              <div
                key={item.evidence_id}
                id={`evidence-${item.evidence_id}`}
                style={{
                  padding: '16px',
                  borderRadius: '6px',
                  border: isHighlighted ? '2px solid var(--primary)' : '1px solid var(--border-light)',
                  backgroundColor: isHighlighted ? 'var(--primary-subtle)' : 'var(--bg-card)',
                  transition: 'all 0.2s ease',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span
                      style={{
                        fontSize: '11px',
                        fontWeight: 700,
                        padding: '2px 8px',
                        borderRadius: '4px',
                        backgroundColor:
                          item.severity === 'CRITICAL' || item.severity === 'HIGH'
                            ? 'var(--threat-red-bg)'
                            : item.severity === 'MEDIUM'
                            ? 'var(--warning-amber-bg)'
                            : 'var(--bg-subtle)',
                        color:
                          item.severity === 'CRITICAL' || item.severity === 'HIGH'
                            ? 'var(--threat-red)'
                            : item.severity === 'MEDIUM'
                            ? 'var(--warning-amber)'
                            : 'var(--text-muted)',
                      }}
                    >
                      {item.severity}
                    </span>
                    <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-main)' }}>
                      {item.category}
                    </span>
                    <code style={{ fontSize: '11px', color: 'var(--text-subtle)' }}>
                      #{item.evidence_id}
                    </code>
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--text-subtle)' }}>
                    Parser: {item.parser_version}
                  </span>
                </div>

                <div style={{ fontSize: '13px', color: 'var(--text-main)', lineHeight: 1.5, marginBottom: '10px' }}>
                  {item.description}
                </div>

                {/* If URL Analysis: Defanged text with copy button, NEVER clickable link! */}
                {item.category === 'URL_ANALYSIS' && item.defanged_data && (
                  <div
                    style={{
                      padding: '10px 12px',
                      backgroundColor: 'var(--bg-subtle)',
                      borderRadius: '4px',
                      border: '1px solid var(--border-light)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '8px',
                    }}
                  >
                    <div style={{ fontSize: '12px', fontFamily: 'monospace', color: 'var(--text-main)', wordBreak: 'break-all' }}>
                      {item.defanged_data.defanged_url || JSON.stringify(item.defanged_data)}
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        copyToClipboard(
                          item.defanged_data.defanged_url || JSON.stringify(item.defanged_data),
                          item.evidence_id
                        )
                      }
                      style={{
                        padding: '4px 8px',
                        fontSize: '11px',
                        fontWeight: 600,
                        backgroundColor: '#ffffff',
                        border: '1px solid var(--border-strong)',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                      }}
                    >
                      {copiedText === item.evidence_id ? <Check size={12} /> : <Copy size={12} />}
                      <span>Copy defanged URL</span>
                    </button>
                  </div>
                )}

                {/* If IP Reputation / GeoIP: Show disclaimer */}
                {item.category === 'IP_REPUTATION' && (
                  <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-subtle)', fontStyle: 'italic' }}>
                    Note: IP geolocation is indicative and does not represent physical sender origin.
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Section 7: Forensic Audit & Integrity */}
      <div ref={forensicsRef} className="card-base" style={{ padding: '24px', marginBottom: '32px' }}>
        <h2 style={{ fontSize: '16px', fontWeight: 700, margin: '0 0 16px', color: 'var(--text-main)' }}>
          Forensic Integrity & Audit Provenance
        </h2>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', fontSize: '13px' }}>
          <div>
            <span style={{ color: 'var(--text-subtle)', display: 'block', marginBottom: '2px' }}>Email Content SHA-256</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <code style={{ fontSize: '12px', fontWeight: 600, wordBreak: 'break-all' }}>
                {state.email_sha256}
              </code>
              <button
                type="button"
                onClick={() => copyToClipboard(state.email_sha256, 'sha')}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-subtle)' }}
              >
                {copiedText === 'sha' ? <Check size={14} color="var(--clean-green)" /> : <Copy size={14} />}
              </button>
            </div>
          </div>

          <div>
            <span style={{ color: 'var(--text-subtle)', display: 'block', marginBottom: '2px' }}>Received Timestamp</span>
            <span style={{ fontWeight: 600 }}>{state.receipt_time_utc || state.received_at || 'N/A'} (UTC)</span>
          </div>

          <div>
            <span style={{ color: 'var(--text-subtle)', display: 'block', marginBottom: '2px' }}>Parser Version</span>
            <span style={{ fontWeight: 600 }}>{state.parser_version}</span>
          </div>

          <div>
            <span style={{ color: 'var(--text-subtle)', display: 'block', marginBottom: '2px' }}>Source Label</span>
            <span style={{ fontWeight: 600 }}>{state.source}</span>
          </div>
        </div>
      </div>
    </div>
  );

  // Helper to render individual agent card
  function renderAgentCard(
    title: string,
    agentId: string,
    Icon: any,
    reports: AgentReport[]
  ) {
    const latestReport = reports[reports.length - 1];
    const isAvail = latestReport?.availability === 'AVAILABLE';

    return (
      <div
        className="card-base"
        style={{
          padding: '20px',
          borderLeft: isAvail ? '4px solid var(--primary)' : '4px solid var(--warning-amber)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Icon size={20} color="var(--primary)" />
            <h3 style={{ fontSize: '15px', fontWeight: 600, margin: 0, color: 'var(--text-main)' }}>
              {title}
            </h3>
          </div>
          <span
            style={{
              fontSize: '11px',
              fontWeight: 600,
              padding: '2px 6px',
              borderRadius: '4px',
              backgroundColor: isAvail ? 'var(--clean-green-bg)' : 'var(--warning-amber-bg)',
              color: isAvail ? 'var(--clean-green)' : 'var(--warning-amber)',
            }}
          >
            {latestReport ? getAvailabilityLabel(latestReport.availability) : 'Not Executed'}
          </span>
        </div>

        {latestReport ? (
          <div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '6px' }}>
              <span style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-main)' }}>
                {getVerdictLabel(latestReport.verdict)}
              </span>
              <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                ({(latestReport.confidence * 100).toFixed(0)}% conf)
              </span>
            </div>

            <div style={{ fontSize: '11px', color: 'var(--warning-amber)', fontWeight: 600, marginBottom: '12px' }}>
              {getCalibrationLabel(latestReport.calibration_status)}
            </div>

            {/* Findings */}
            {latestReport.findings.length > 0 && (
              <div style={{ marginTop: '10px' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                  Findings:
                </span>
                <ul style={{ margin: 0, paddingLeft: '16px', fontSize: '12px', color: 'var(--text-main)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {latestReport.findings.slice(0, 3).map((f, i) => (
                    <li key={i}>{f.text}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Limitations (e.g. chunk count) */}
            {latestReport.limitations.length > 0 && (
              <div style={{ marginTop: '10px', fontSize: '11px', color: 'var(--text-subtle)', fontStyle: 'italic' }}>
                {latestReport.limitations.join(' • ')}
              </div>
            )}
          </div>
        ) : (
          <div style={{ fontSize: '13px', color: 'var(--text-subtle)', fontStyle: 'italic' }}>
            Agent was unavailable or abstained from this investigation.
          </div>
        )}
      </div>
    );
  }
};
