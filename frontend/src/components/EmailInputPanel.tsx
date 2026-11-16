import React, { useState } from 'react';
import { Upload, FileText, Play, ShieldAlert, Sparkles, RefreshCw, FileUp } from 'lucide-react';
import { SampleEmailItem } from '../types';

interface EmailInputPanelProps {
  samples: SampleEmailItem[];
  onSelectSample: (sampleId: string) => Promise<string>;
  onInvestigateText: (rawEmail: string, redactGemini: boolean) => Promise<void>;
  onInvestigateFile: (file: File) => Promise<void>;
  isLoading: boolean;
}

export const EmailInputPanel: React.FC<EmailInputPanelProps> = ({
  samples,
  onSelectSample,
  onInvestigateText,
  onInvestigateFile,
  isLoading,
}) => {
  const [activeTab, setActiveTab] = useState<'editor' | 'upload'>('editor');
  const [rawText, setRawText] = useState<string>('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [redactGemini, setRedactGemini] = useState<boolean>(true);
  const [activeSampleId, setActiveSampleId] = useState<string>('');

  const handleSampleClick = async (sampleId: string) => {
    setActiveSampleId(sampleId);
    try {
      const content = await onSelectSample(sampleId);
      setRawText(content);
      setActiveTab('editor');
    } catch (err) {
      console.error('Failed to load sample', err);
    }
  };

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (activeTab === 'editor') {
      if (!rawText.trim()) return;
      await onInvestigateText(rawText, redactGemini);
    } else {
      if (!selectedFile) return;
      await onInvestigateFile(selectedFile);
    }
  };

  return (
    <div className="panel mb-6">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setActiveTab('editor')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              activeTab === 'editor'
                ? 'bg-blue-600 text-white shadow'
                : 'text-slate-400 hover:text-white bg-slate-800/50'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            Raw RFC 5322 Editor
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('upload')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              activeTab === 'upload'
                ? 'bg-blue-600 text-white shadow'
                : 'text-slate-400 hover:text-white bg-slate-800/50'
            }`}
          >
            <Upload className="w-3.5 h-3.5" />
            Upload .EML / .TXT
          </button>
        </div>

        {/* Quick synthetic sample pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Synthetic Samples:</span>
          {samples.map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => handleSampleClick(s.id)}
              className={`text-[11px] font-mono px-2 py-0.5 rounded border transition-colors ${
                activeSampleId === s.id
                  ? 'bg-blue-900/60 border-blue-500 text-blue-200'
                  : 'bg-slate-800 border-slate-700 text-slate-300 hover:border-slate-500'
              }`}
            >
              {s.category}
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={handleFormSubmit}>
        {activeTab === 'editor' ? (
          <div>
            <textarea
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Paste complete raw email including headers (From, Subject, Received, etc.) and body..."
              rows={9}
              className="font-mono text-xs leading-relaxed resize-y"
              required
            />
          </div>
        ) : (
          <div className="border-2 border-dashed border-slate-700 hover:border-blue-500 rounded-xl p-8 text-center bg-slate-900/40 transition-colors">
            <FileUp className="w-10 h-10 text-slate-500 mx-auto mb-3" />
            <p className="text-sm font-medium text-slate-200 mb-1">
              Select or drag and drop an email file
            </p>
            <p className="text-xs text-slate-500 mb-4 font-mono">
              Accepted formats: .eml, .txt, .msg (Max 10 MB)
            </p>
            <input
              type="file"
              accept=".eml,.txt,.msg"
              onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
              className="text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-500 cursor-pointer"
            />
            {selectedFile && (
              <p className="text-xs text-emerald-400 font-mono mt-3">
                Selected: {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
              </p>
            )}
          </div>
        )}

        {/* Security and Privacy Options */}
        <div className="flex flex-wrap items-center justify-between gap-4 mt-4 pt-3 border-t border-slate-800/80">
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={redactGemini}
                onChange={(e) => setRedactGemini(e.target.checked)}
                className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0 w-3.5 h-3.5"
              />
              <span className="text-xs text-slate-300">
                Redact sensitive PII (emails, IPs) before cloud inference
              </span>
            </label>
            <div className="flex items-center gap-1 text-[11px] text-slate-400 font-mono">
              <Sparkles className="w-3 h-3 text-blue-400" />
              <span>Third-party disclosure active</span>
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading || (activeTab === 'editor' && !rawText.trim()) || (activeTab === 'upload' && !selectedFile)}
            className="btn-primary"
          >
            {isLoading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Running Deliberation...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span>Investigate Email Threat</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
