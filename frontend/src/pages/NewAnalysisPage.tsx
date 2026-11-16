import React, { useState, useEffect, useRef } from 'react';
import { useRouter } from '../router';
import { api, ApiError } from '../api/client';
import { ReadinessResponse, SampleItem } from '../api/types';
import {
  UploadCloud,
  FileText,
  AlertTriangle,
  Shield,
  ShieldCheck,
  Info,
  Loader2,
  FileCode,
} from 'lucide-react';

const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20 MB
const MAX_TEXT_LENGTH = 500 * 1024; // 500 KB

export const NewAnalysisPage: React.FC = () => {
  const { navigate } = useRouter();
  const [activeTab, setActiveTab] = useState<'upload' | 'paste'>('upload');
  const [file, setFile] = useState<File | null>(null);
  const [pastedText, setPastedText] = useState<string>('');
  const [redactGemini, setRedactGemini] = useState<boolean>(true);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState<boolean>(false);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [samples, setSamples] = useState<SampleItem[]>([]);
  const [selectedSampleId, setSelectedSampleId] = useState<string>('');

  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let mounted = true;
    Promise.all([
      api.getReadiness().catch(() => null),
      api.listSamples().catch(() => []),
    ]).then(([ready, sampleList]) => {
      if (mounted) {
        if (ready) setReadiness(ready);
        if (sampleList) setSamples(sampleList);
      }
    });

    return () => {
      mounted = false;
    };
  }, []);

  // Prevent leaving while submitting
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (isSubmitting) {
        e.preventDefault();
        e.returnValue = '';
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [isSubmitting]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setErrorMsg(null);
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (f: File) => {
    if (f.size > MAX_FILE_SIZE) {
      setErrorMsg(`File size (${(f.size / (1024 * 1024)).toFixed(1)}MB) exceeds the 20MB limit.`);
      setFile(null);
      return;
    }
    const name = f.name.toLowerCase();
    if (!name.endsWith('.eml') && !name.endsWith('.msg') && !name.endsWith('.txt')) {
      setErrorMsg('Invalid file type. Please upload a standard email file (.eml, .msg, or RFC822 .txt).');
      setFile(null);
      return;
    }
    setFile(f);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    setErrorMsg(null);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleSampleSelect = async (sampleId: string) => {
    if (!sampleId) return;
    setSelectedSampleId(sampleId);
    setErrorMsg(null);
    try {
      const content = await api.getSampleContent(sampleId);
      setPastedText(content);
      setActiveTab('paste');
    } catch (err: any) {
      setErrorMsg(`Failed to load sample: ${err.message}`);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;

    setErrorMsg(null);

    if (activeTab === 'upload') {
      if (!file) {
        setErrorMsg('Please select or drop an .eml email file to analyze.');
        return;
      }
      setIsSubmitting(true);
      try {
        const state = await api.investigateFile(file);
        navigate(`/investigations/${state.investigation_id}`);
      } catch (err: any) {
        setIsSubmitting(false);
        setErrorMsg(err instanceof ApiError ? err.message : 'Investigation failed. Server error.');
      }
    } else {
      if (!pastedText.trim()) {
        setErrorMsg('Please paste raw email headers and body text.');
        return;
      }
      if (pastedText.length > MAX_TEXT_LENGTH) {
        setErrorMsg(`Pasted text exceeds maximum limit (${MAX_TEXT_LENGTH / 1024} KB).`);
        return;
      }
      setIsSubmitting(true);
      try {
        const state = await api.investigateText(pastedText, redactGemini);
        navigate(`/investigations/${state.investigation_id}`);
      } catch (err: any) {
        setIsSubmitting(false);
        setErrorMsg(err instanceof ApiError ? err.message : 'Investigation failed. Server error.');
      }
    }
  };

  // Check if Gemini is enabled in readiness
  const isGeminiEnabled = readiness?.agents?.agent_2_gemini?.enabled;

  return (
    <div>
      {/* Title */}
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, margin: 0, color: 'var(--text-main)' }}>
          New Email Threat Analysis
        </h1>
        <p style={{ margin: '4px 0 0', fontSize: '14px', color: 'var(--text-muted)' }}>
          Submit an RFC822 email for deterministic evidence parsing, multi-agent evaluation, and consensus deliberation.
        </p>
      </div>

      {/* Safety Notice */}
      <div
        style={{
          padding: '12px 16px',
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-light)',
          borderRadius: '6px',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          fontSize: '13px',
          color: 'var(--text-muted)',
        }}
      >
        <ShieldCheck size={18} color="var(--primary)" />
        <span>
          <strong>Forensic Safety Guarantee:</strong> All embedded links and domains are strictly defanged and analyzed as text. Links are <strong>never</strong> visited or resolved over the network.
        </span>
      </div>

      {/* Gemini Privacy Disclosure if Enabled */}
      {isGeminiEnabled && (
        <div
          role="note"
          style={{
            padding: '12px 16px',
            backgroundColor: 'var(--primary-subtle)',
            border: '1px solid var(--primary)',
            borderRadius: '6px',
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '10px',
            fontSize: '13px',
            color: 'var(--text-main)',
          }}
        >
          <Info size={18} color="var(--primary)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong>Third-Party Model Disclosure:</strong> Agent 2 (Gemini LLM) is currently enabled.
            Extracted header metadata and body text summaries are evaluated via the external Gemini API.
            Personal identifiers and internal IP addresses are defanged and redacted before transmission.
          </div>
        </div>
      )}

      {/* Error banner */}
      {errorMsg && (
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
            fontWeight: 500,
          }}
        >
          <AlertTriangle size={18} />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Quick Synthetic Sample Loader */}
      {samples.length > 0 && (
        <div
          className="card-base"
          style={{
            padding: '12px 16px',
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '10px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileCode size={18} color="var(--primary)" />
            <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-main)' }}>
              Test with synthetic sample:
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <select
              value={selectedSampleId}
              onChange={(e) => handleSampleSelect(e.target.value)}
              disabled={isSubmitting}
              style={{
                padding: '6px 12px',
                borderRadius: '6px',
                border: '1px solid var(--border-strong)',
                fontSize: '13px',
                backgroundColor: 'var(--bg-card)',
                color: 'var(--text-main)',
              }}
            >
              <option value="">Select a synthetic sample email...</option>
              {samples.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.filename} ({s.category})
                </option>
              ))}
            </select>
          </div>
        </div>
      )}

      {/* Main Analysis Form Card */}
      <div className="card-base" style={{ overflow: 'hidden' }}>
        {/* Tab switch */}
        <div
          style={{
            display: 'flex',
            borderBottom: '1px solid var(--border-light)',
            backgroundColor: 'var(--bg-subtle)',
          }}
        >
          <button
            type="button"
            onClick={() => {
              setActiveTab('upload');
              setErrorMsg(null);
            }}
            disabled={isSubmitting}
            style={{
              flex: 1,
              padding: '14px',
              border: 'none',
              background: activeTab === 'upload' ? 'var(--bg-card)' : 'transparent',
              borderBottom: activeTab === 'upload' ? '2px solid var(--primary)' : '2px solid transparent',
              fontWeight: activeTab === 'upload' ? 600 : 500,
              color: activeTab === 'upload' ? 'var(--primary)' : 'var(--text-muted)',
              fontSize: '14px',
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
            }}
          >
            <UploadCloud size={18} />
            <span>Upload .eml file</span>
          </button>

          <button
            type="button"
            onClick={() => {
              setActiveTab('paste');
              setErrorMsg(null);
            }}
            disabled={isSubmitting}
            style={{
              flex: 1,
              padding: '14px',
              border: 'none',
              background: activeTab === 'paste' ? 'var(--bg-card)' : 'transparent',
              borderBottom: activeTab === 'paste' ? '2px solid var(--primary)' : '2px solid transparent',
              fontWeight: activeTab === 'paste' ? 600 : 500,
              color: activeTab === 'paste' ? 'var(--primary)' : 'var(--text-muted)',
              fontSize: '14px',
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
            }}
          >
            <FileText size={18} />
            <span>Paste email text</span>
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} style={{ padding: '24px' }}>
          {activeTab === 'upload' ? (
            <div>
              {/* Drag & Drop Area */}
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragOver(true);
                }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                style={{
                  border: `2px dashed ${isDragOver ? 'var(--primary)' : 'var(--border-strong)'}`,
                  backgroundColor: isDragOver ? 'var(--primary-subtle)' : 'var(--bg-subtle)',
                  borderRadius: '8px',
                  padding: '40px 20px',
                  textAlign: 'center',
                  cursor: isSubmitting ? 'not-allowed' : 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".eml,.msg,.txt"
                  onChange={handleFileChange}
                  disabled={isSubmitting}
                  style={{ display: 'none' }}
                />
                <UploadCloud
                  size={44}
                  color={isDragOver ? 'var(--primary)' : 'var(--text-subtle)'}
                  style={{ margin: '0 auto 12px' }}
                />
                <div style={{ fontWeight: 600, fontSize: '15px', color: 'var(--text-main)', marginBottom: '4px' }}>
                  {file ? file.name : 'Drag & drop an email file here, or click to browse'}
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                  Supports standard RFC822 files (.eml, .msg, .txt) up to 20MB
                </div>

                {file && (
                  <div style={{ marginTop: '12px', fontSize: '12px', color: 'var(--primary)', fontWeight: 600 }}>
                    Selected: {file.name} ({(file.size / 1024).toFixed(1)} KB)
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div>
              <label
                htmlFor="raw-email-input"
                style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--text-main)', marginBottom: '6px' }}
              >
                Raw Email Headers & Body (RFC822 format)
              </label>
              <textarea
                id="raw-email-input"
                rows={12}
                value={pastedText}
                onChange={(e) => setPastedText(e.target.value)}
                disabled={isSubmitting}
                placeholder="From: sender@example.com&#10;To: recipient@example.com&#10;Subject: Urgent Security Update&#10;Date: Mon, 16 Nov 2026 12:00:00 +0000&#10;&#10;Please verify your account at http://login-security.info..."
                style={{
                  width: '100%',
                  padding: '12px',
                  borderRadius: '6px',
                  border: '1px solid var(--border-strong)',
                  fontFamily: 'monospace',
                  fontSize: '13px',
                  backgroundColor: 'var(--bg-card)',
                  color: 'var(--text-main)',
                  resize: 'vertical',
                }}
              />
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: 'var(--text-subtle)', marginTop: '4px' }}>
                <span>Include standard headers (Received, From, Subject, Authentication-Results) for accurate forensic analysis.</span>
                <span>{(pastedText.length / 1024).toFixed(1)} KB / 500 KB</span>
              </div>
            </div>
          )}

          {/* Redact Gemini toggle */}
          {isGeminiEnabled && (
            <div style={{ marginTop: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <input
                type="checkbox"
                id="redact-gemini"
                checked={redactGemini}
                onChange={(e) => setRedactGemini(e.target.checked)}
                disabled={isSubmitting}
                style={{ cursor: 'pointer' }}
              />
              <label htmlFor="redact-gemini" style={{ fontSize: '13px', color: 'var(--text-muted)', cursor: 'pointer' }}>
                Redact personal email addresses and internal private IPs before sending to Agent 2 (Gemini API)
              </label>
            </div>
          )}

          {/* Action button */}
          <div style={{ marginTop: '24px', display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
            <button
              type="submit"
              disabled={isSubmitting || (activeTab === 'upload' && !file) || (activeTab === 'paste' && !pastedText.trim())}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                backgroundColor: isSubmitting ? 'var(--text-subtle)' : 'var(--primary)',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                padding: '12px 24px',
                fontSize: '14px',
                fontWeight: 600,
                cursor: isSubmitting ? 'not-allowed' : 'pointer',
                boxShadow: '0 1px 3px rgba(2, 132, 199, 0.2)',
              }}
            >
              {isSubmitting ? (
                <>
                  <Loader2 size={18} className="animate-spin" />
                  <span>Analyzing email & synthesizing consensus...</span>
                </>
              ) : (
                <>
                  <Shield size={18} />
                  <span>Analyze email</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
