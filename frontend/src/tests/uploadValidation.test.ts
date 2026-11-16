import { describe, it, expect } from 'vitest';

describe('Client-Side Upload Validation', () => {
  const MAX_FILE_SIZE = 20 * 1024 * 1024;
  const MAX_TEXT_LENGTH = 500 * 1024;

  const validateFile = (fileName: string, fileSize: number): { valid: boolean; error?: string } => {
    if (fileSize > MAX_FILE_SIZE) {
      return { valid: false, error: 'File size exceeds the 20MB limit.' };
    }
    const name = fileName.toLowerCase();
    if (!name.endsWith('.eml') && !name.endsWith('.msg') && !name.endsWith('.txt')) {
      return { valid: false, error: 'Invalid file type.' };
    }
    return { valid: true };
  };

  const validateText = (text: string): { valid: boolean; error?: string } => {
    if (!text.trim()) {
      return { valid: false, error: 'Empty text.' };
    }
    if (text.length > MAX_TEXT_LENGTH) {
      return { valid: false, error: 'Text exceeds maximum limit.' };
    }
    return { valid: true };
  };

  it('accepts valid .eml file within 20MB', () => {
    const res = validateFile('sample.eml', 1024 * 1024);
    expect(res.valid).toBe(true);
  });

  it('rejects file larger than 20MB', () => {
    const res = validateFile('large.eml', 21 * 1024 * 1024);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('exceeds');
  });

  it('rejects unsupported file extensions (e.g. .exe, .pdf)', () => {
    const res = validateFile('payload.exe', 1024);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('Invalid file type');
  });

  it('rejects pasted text greater than 500KB', () => {
    const bigString = 'a'.repeat(600 * 1024);
    const res = validateText(bigString);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('exceeds maximum limit');
  });
});
