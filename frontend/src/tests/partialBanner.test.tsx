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
    params: { id: 'test-inv-123' },
    currentPath: '/investigations/test-inv-123',
    navigate: vi.fn(),
  }),
}));

describe('Partial Analysis and Data Honesty Banner', () => {
  it('renders persistent Partial banner and reasons when partial=true on LEGITIMATE verdict', async () => {
    const mockState: InvestigationState = {
      investigation_id: 'test-inv-123',
      email_sha256: 'abc123sha256',
      received_at: '2026-11-16T12:00:00Z',
      source: 'test',
      parser_version: '1.0.0',
      evidence: [],
      reports: [],
      debate_messages: [],
      final_result: {
        final_verdict: 'LEGITIMATE',
        confidence: 0.65,
        reasons: ['Agent 2 (Gemini) was UNAVAILABLE', 'Confidence is unvalidated'],
        partial: true,
        matched_rule_id: 'R9_PARTIAL_LEGITIMATE',
        agent_verdicts: {},
        prompt_injection_detected: false,
        risk_indicator: 30.0,
      },
    };

    vi.mocked(api.getInvestigation).mockResolvedValueOnce(mockState);

    render(<InvestigationDetailPage />);

    // Wait for the investigation to load
    const banner = await screen.findByRole('alert');
    expect(banner).toBeInTheDocument();
    expect(banner).toHaveTextContent(/Partial Forensic Analysis — Review Required/i);
    expect(banner).toHaveTextContent(/Agent 2 \(Gemini\) was UNAVAILABLE/i);
    expect(banner).toHaveTextContent(/Confidence is unvalidated/i);

    // Verify unvalidated score caveat is rendered
    expect(screen.getByText(/Unvalidated score, not a probability/i)).toBeInTheDocument();

    // Verify risk indicator label
    expect(screen.getByText(/Forensic Risk Indicator/i)).toBeInTheDocument();
    expect(screen.getByText('30')).toBeInTheDocument();
  });
});
