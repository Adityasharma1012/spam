import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { InvestigationDetailPage } from '../pages/InvestigationDetailPage';
import { api } from '../api/client';
import { InvestigationState } from '../api/types';

vi.mock('../api/client', () => ({
  api: {
    getInvestigation: vi.fn(),
    getExportUrl: vi.fn((id) => `/api/investigations/${id}/export`),
  },
  ApiError: class extends Error {},
}));

vi.mock('../router', () => ({
  useRouter: () => ({
    params: { id: 'test-sec-123' },
    currentPath: '/investigations/test-sec-123',
    navigate: vi.fn(),
  }),
}));

describe('Security & Inert Text Rendering', () => {
  it('renders defanged URLs as inert text with a copy button and never as clickable anchor links', async () => {
    const mockState: InvestigationState = {
      investigation_id: 'test-sec-123',
      email_sha256: 'deadbeef123',
      received_at: '2026-11-16T12:00:00Z',
      source: 'test',
      parser_version: '1.0.0',
      evidence: [
        {
          evidence_id: 'ev-url-1',
          category: 'URL_ANALYSIS',
          description: 'Phishing domain detected in body link',
          source: 'email_body',
          parser_version: '1.0.0',
          provenance: 'deterministic',
          raw_data: { raw_url: 'http://malicious-phishing.com/login' },
          defanged_data: { defanged_url: 'hxxp://malicious-phishing[.]com/login' },
          severity: 'HIGH',
        },
      ],
      reports: [],
      debate_messages: [],
      final_result: {
        final_verdict: 'PHISHING',
        confidence: 0.95,
        reasons: ['Malicious link detected'],
        partial: false,
        matched_rule_id: 'R1_PHISHING',
        agent_verdicts: {},
        prompt_injection_detected: false,
        risk_indicator: 85.0,
      },
    };

    vi.mocked(api.getInvestigation).mockResolvedValueOnce(mockState);

    render(<InvestigationDetailPage />);

    // Wait for the defanged url to render
    const defangedText = await screen.findByText('hxxp://malicious-phishing[.]com/login');
    expect(defangedText).toBeInTheDocument();

    // Verify it is NOT an anchor tag (<a href="...">)
    expect(defangedText.tagName).not.toBe('A');
    expect(defangedText.closest('a')).toBeNull();

    // Verify copy defanged URL button exists
    expect(screen.getByText('Copy defanged URL')).toBeInTheDocument();
  });
});
