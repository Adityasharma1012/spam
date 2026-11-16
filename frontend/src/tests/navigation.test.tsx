import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { AppLayout } from '../components/AppLayout';
import { RouterProvider } from '../router';

vi.mock('../api/client', () => ({
  api: {
    getReadiness: vi.fn().mockResolvedValue({
      ready: true,
      timestamp_utc: '2026-11-16T12:00:00Z',
      agents: {},
    }),
  },
}));

describe('Wayfinding & Accessible Navigation', () => {
  it('renders skip link targeting #main-content and landmark regions', () => {
    render(
      <RouterProvider>
        <AppLayout>
          <h1>Test Content</h1>
        </AppLayout>
      </RouterProvider>
    );

    // Skip to main content link
    const skipLink = screen.getByText('Skip to main content');
    expect(skipLink).toBeInTheDocument();
    expect(skipLink).toHaveAttribute('href', '#main-content');

    // Main content landmark
    const mainLandmark = screen.getByRole('main');
    expect(mainLandmark).toHaveAttribute('id', 'main-content');

    // Navigation landmarks
    const primaryNav = screen.getByRole('navigation', { name: /primary navigation/i });
    expect(primaryNav).toBeInTheDocument();

    const mobileNav = screen.getByRole('navigation', { name: /mobile navigation/i, hidden: true });
    expect(mobileNav).toBeInTheDocument();
  });

  it('marks active navigation item with aria-current="page"', () => {
    render(
      <RouterProvider>
        <AppLayout>
          <h1>Overview</h1>
        </AppLayout>
      </RouterProvider>
    );

    // Initial route is '/' so Overview should have aria-current="page"
    const overviewButtons = screen.getAllByRole('button', { name: /overview/i });
    expect(overviewButtons[0]).toHaveAttribute('aria-current', 'page');
  });
});
