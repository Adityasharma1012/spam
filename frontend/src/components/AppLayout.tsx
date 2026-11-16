import React, { useEffect, useState } from 'react';
import { useRouter } from '../router';
import { api } from '../api/client';
import { ReadinessResponse } from '../api/types';
import {
  LayoutDashboard,
  PlusCircle,
  Clock,
  Activity,
  Shield,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';

interface AppLayoutProps {
  children: React.ReactNode;
}

export const AppLayout: React.FC<AppLayoutProps> = ({ children }) => {
  const { currentPath, navigate } = useRouter();
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);

  useEffect(() => {
    let isMounted = true;
    api.getReadiness()
      .then((data) => {
        if (isMounted) setReadiness(data);
      })
      .catch((err) => {
        console.warn('Readiness check failed:', err);
      });
    return () => {
      isMounted = false;
    };
  }, [currentPath]);

  const navItems = [
    { label: 'Overview', path: '/', icon: LayoutDashboard },
    { label: 'New analysis', path: '/new', icon: PlusCircle, isPrimary: true },
    { label: 'History', path: '/history', icon: Clock },
    { label: 'System status', path: '/status', icon: Activity },
  ];

  // Helper to determine if a route is active
  const isActive = (path: string) => {
    if (path === '/') return currentPath === '/';
    return currentPath === path || (path === '/history' && currentPath.startsWith('/investigations/'));
  };

  // Readiness badge label & color
  let readyLabel = 'Checking system...';
  let readyBg = '#f1f5f9';
  let readyText = '#475569';
  let ReadyIcon = Activity;

  if (readiness) {
    if (readiness.ready) {
      readyLabel = 'System Ready';
      readyBg = 'var(--clean-green-bg)';
      readyText = 'var(--clean-green)';
      ReadyIcon = CheckCircle2;
    } else {
      readyLabel = 'Degraded / Unready';
      readyBg = 'var(--warning-amber-bg)';
      readyText = 'var(--warning-amber)';
      ReadyIcon = AlertTriangle;
    }
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh', backgroundColor: 'var(--bg-app)' }}>
      {/* Skip Link for Accessibility */}
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>

      {/* Desktop Left Sidebar (>= 1024px) */}
      <aside
        className="desktop-sidebar"
        aria-label="Desktop Sidebar"
        style={{
          width: '260px',
          backgroundColor: 'var(--bg-card)',
          borderRight: '1px solid var(--border-light)',
          display: 'flex',
          flexDirection: 'column',
          flexShrink: 0,
          position: 'sticky',
          top: 0,
          height: '100vh',
          zIndex: 40,
        }}
      >
        {/* Brand */}
        <div style={{ padding: '24px 20px', borderBottom: '1px solid var(--border-light)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                backgroundColor: 'var(--primary)',
                color: '#ffffff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Shield size={22} />
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: '15px', color: 'var(--text-main)', lineHeight: 1.2 }}>
                ThreatForensics
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-subtle)' }}>
                Email Threat Platform
              </div>
            </div>
          </div>
        </div>

        {/* Navigation Links */}
        <nav
          aria-label="Primary Navigation"
          style={{ padding: '16px 12px', flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}
        >
          {navItems.map((item) => {
            const active = isActive(item.path);
            const Icon = item.icon;
            return (
              <button
                key={item.path}
                type="button"
                onClick={() => navigate(item.path)}
                aria-current={active ? 'page' : undefined}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  width: '100%',
                  padding: '10px 14px',
                  borderRadius: '6px',
                  border: 'none',
                  backgroundColor: active ? 'var(--primary-subtle)' : 'transparent',
                  color: active ? 'var(--primary-hover)' : 'var(--text-muted)',
                  fontWeight: active ? 600 : 500,
                  fontSize: '14px',
                  cursor: 'pointer',
                  textAlign: 'left',
                  transition: 'background-color 0.15s ease, color 0.15s ease',
                }}
              >
                <Icon size={18} color={active ? 'var(--primary)' : 'var(--text-subtle)'} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        {/* System Readiness summary in sidebar bottom */}
        <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border-light)' }}>
          <button
            type="button"
            onClick={() => navigate('/status')}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              width: '100%',
              padding: '8px 12px',
              borderRadius: '6px',
              backgroundColor: readyBg,
              border: '1px solid var(--border-light)',
              cursor: 'pointer',
              color: readyText,
              fontSize: '12px',
              fontWeight: 600,
            }}
          >
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ReadyIcon size={14} />
              {readyLabel}
            </span>
            <span style={{ fontSize: '11px', textDecoration: 'underline' }}>View</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Top Header */}
        <header
          style={{
            height: '64px',
            backgroundColor: 'var(--bg-card)',
            borderBottom: '1px solid var(--border-light)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0 24px',
            position: 'sticky',
            top: 0,
            zIndex: 30,
          }}
        >
          {/* Mobile Brand / Page Indication */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div className="mobile-brand" style={{ display: 'none', alignItems: 'center', gap: '8px' }}>
              <Shield size={20} color="var(--primary)" />
              <span style={{ fontWeight: 700, fontSize: '15px' }}>ThreatForensics</span>
            </div>
            <span style={{ fontSize: '13px', color: 'var(--text-subtle)' }}>
              Deterministic Forensic Intelligence
            </span>
          </div>

          {/* Quick Header Actions: Always 1-click New Analysis */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button
              type="button"
              onClick={() => navigate('/status')}
              className="desktop-only"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 10px',
                borderRadius: '6px',
                backgroundColor: readyBg,
                color: readyText,
                border: '1px solid var(--border-light)',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <ReadyIcon size={14} />
              {readyLabel}
            </button>

            <button
              type="button"
              onClick={() => navigate('/new')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                backgroundColor: 'var(--primary)',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                padding: '8px 16px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer',
                boxShadow: '0 1px 2px rgba(2, 132, 199, 0.2)',
              }}
            >
              <PlusCircle size={16} />
              <span>New analysis</span>
            </button>
          </div>
        </header>

        {/* Route Page Container */}
        <main
          id="main-content"
          tabIndex={-1}
          style={{
            flex: 1,
            padding: '24px',
            maxWidth: '1200px',
            width: '100%',
            margin: '0 auto',
            outline: 'none',
            paddingBottom: '80px', // Extra space for mobile bottom tab bar
          }}
        >
          {children}
        </main>
      </div>

      {/* Mobile Bottom Tab Bar (< 1024px) */}
      <nav
        className="mobile-bottom-tabs"
        aria-label="Mobile Navigation"
        style={{
          position: 'fixed',
          bottom: 0,
          left: 0,
          right: 0,
          height: '60px',
          backgroundColor: 'var(--bg-card)',
          borderTop: '1px solid var(--border-light)',
          justifyContent: 'space-around',
          alignItems: 'center',
          zIndex: 50,
          boxShadow: '0 -2px 10px rgba(0,0,0,0.05)',
        }}
      >
        {navItems.map((item) => {
          const active = isActive(item.path);
          const Icon = item.icon;
          return (
            <button
              key={item.path}
              type="button"
              onClick={() => navigate(item.path)}
              aria-current={active ? 'page' : undefined}
              className="touch-target"
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '4px',
                flex: 1,
                height: '100%',
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: active ? 'var(--primary)' : 'var(--text-subtle)',
                fontWeight: active ? 600 : 500,
                fontSize: '11px',
                padding: '4px 0',
              }}
            >
              <Icon size={20} color={active ? 'var(--primary)' : 'var(--text-subtle)'} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>
    </div>
  );
};
