import {
  HealthResponse,
  HealthResponseSchema,
  InvestigationState,
  InvestigationStateSchema,
  InvestigationSummary,
  InvestigationSummarySchema,
  ProgressResponse,
  ProgressResponseSchema,
  ReadinessResponse,
  ReadinessResponseSchema,
  DecisionRuleInfo,
  DecisionRuleInfoSchema,
  SampleItem,
  SampleItemSchema,
} from './types';
import { z } from 'zod';

export class ApiError extends Error {
  public status?: number;
  public details?: any;

  constructor(message: string, status?: number, details?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

async function request<T>(
  url: string,
  options: RequestInit,
  schema: z.ZodType<T>
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, options);
  } catch (err: any) {
    throw new ApiError(
      `Network connection failed: ${err.message || 'Server unreachable at 127.0.0.1'}`
    );
  }

  if (!response.ok) {
    let detailMsg = `HTTP Error ${response.status}`;
    try {
      const errorJson = await response.json();
      if (errorJson.detail) {
        detailMsg = typeof errorJson.detail === 'string'
          ? errorJson.detail
          : JSON.stringify(errorJson.detail);
      }
    } catch {
      // Non-json error
    }
    throw new ApiError(detailMsg, response.status);
  }

  let data: any;
  try {
    data = await response.json();
  } catch (err: any) {
    throw new ApiError(`Invalid JSON response: ${err.message}`, response.status);
  }

  const parseResult = schema.safeParse(data);
  if (!parseResult.success) {
    console.error('API Response Schema Validation Failure:', parseResult.error.format());
    throw new ApiError(
      `Received unexpected response structure from API: ${parseResult.error.issues[0]?.message || 'Schema mismatch'}`,
      response.status,
      parseResult.error
    );
  }

  return parseResult.data;
}

export const api = {
  async getHealth(): Promise<HealthResponse> {
    return request('/api/health', { method: 'GET' }, HealthResponseSchema);
  },

  async getReadiness(): Promise<ReadinessResponse> {
    return request('/api/ready', { method: 'GET' }, ReadinessResponseSchema);
  },

  async listInvestigations(): Promise<InvestigationSummary[]> {
    return request('/api/investigations', { method: 'GET' }, z.array(InvestigationSummarySchema));
  },

  async getInvestigation(id: string): Promise<InvestigationState> {
    return request(`/api/investigations/${id}`, { method: 'GET' }, InvestigationStateSchema);
  },

  async deleteInvestigation(id: string): Promise<{ status: string; message: string }> {
    const res = await fetch(`/api/investigations/${id}`, { method: 'DELETE' });
    if (!res.ok) {
      let msg = 'Failed to delete investigation';
      try {
        const j = await res.json();
        if (j.detail) msg = j.detail;
      } catch {}
      throw new ApiError(msg, res.status);
    }
    return res.json();
  },

  getExportUrl(id: string): string {
    return `/api/investigations/${id}/export`;
  },

  async investigateText(rawEmail: string, redactGemini: boolean = true): Promise<InvestigationState> {
    return request(
      '/api/investigate',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          raw_email: rawEmail,
          source_label: 'ui_text_input',
          redact_gemini: redactGemini,
        }),
      },
      InvestigationStateSchema
    );
  },

  async investigateFile(file: File): Promise<InvestigationState> {
    const formData = new FormData();
    formData.append('file', file);
    return request(
      '/api/investigate/file',
      {
        method: 'POST',
        body: formData,
      },
      InvestigationStateSchema
    );
  },

  async submitAsync(rawEmail: string, redactGemini: boolean = true): Promise<{ task_id: string; message: string }> {
    const res = await fetch('/api/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        raw_email: rawEmail,
        source_label: 'ui_async_submit',
        redact_gemini: redactGemini,
      }),
    });
    if (!res.ok) {
      let msg = 'Failed to submit investigation';
      try {
        const j = await res.json();
        if (j.detail) msg = j.detail;
      } catch {}
      throw new ApiError(msg, res.status);
    }
    return res.json();
  },

  async getProgress(taskId: string): Promise<ProgressResponse> {
    return request(`/api/progress/${taskId}`, { method: 'GET' }, ProgressResponseSchema);
  },

  async listSamples(): Promise<SampleItem[]> {
    return request('/api/samples', { method: 'GET' }, z.array(SampleItemSchema));
  },

  async getSampleContent(sampleId: string): Promise<string> {
    const res = await fetch(`/api/samples/${sampleId}`);
    if (!res.ok) throw new ApiError('Failed to load sample content', res.status);
    const data = await res.json();
    return data.content || '';
  },

  async getDecisionTable(): Promise<DecisionRuleInfo[]> {
    return request('/api/decision-table', { method: 'GET' }, z.array(DecisionRuleInfoSchema));
  },
};
