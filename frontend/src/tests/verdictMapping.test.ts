import { describe, it, expect } from 'vitest';
import { getVerdictLabel, getCalibrationLabel, getAvailabilityLabel } from '../api/types';

describe('Verdict & Label Data Honesty Mappings', () => {
  it('maps all backend verdict enums strictly to specified user-facing labels', () => {
    expect(getVerdictLabel('PHISHING')).toBe('Phishing');
    expect(getVerdictLabel('SPAM')).toBe('Spam');
    expect(getVerdictLabel('SUSPICIOUS')).toBe('Suspicious');
    expect(getVerdictLabel('LEGITIMATE')).toBe('No threat indicators found');
    expect(getVerdictLabel('NEEDS_REVIEW')).toBe('Needs review');
  });

  it('labels UNVALIDATED calibration as "Unvalidated score, not a probability"', () => {
    expect(getCalibrationLabel('UNVALIDATED')).toBe('Unvalidated score, not a probability');
  });

  it('labels DEMO_ONLY calibration appropriately', () => {
    expect(getCalibrationLabel('DEMO_ONLY')).toContain('Demo model only');
  });

  it('maps availability status faithfully', () => {
    expect(getAvailabilityLabel('AVAILABLE')).toBe('Available & resident');
    expect(getAvailabilityLabel('DEGRADED')).toBe('Degraded / Rate limited');
    expect(getAvailabilityLabel('UNAVAILABLE')).toBe('Unavailable / Offline');
  });
});
