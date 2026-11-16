import React from 'react';
import { useRouter } from '../router';
import { FileQuestion, PlusCircle, LayoutDashboard } from 'lucide-react';

export const NotFoundPage: React.FC = () => {
  const { navigate } = useRouter();

  return (
    <div style={{ padding: '60px 20px', textAlign: 'center' }}>
      <FileQuestion size={48} color="var(--border-strong)" style={{ margin: '0 auto 16px' }} />
      <h1 style={{ fontSize: '22px', fontWeight: 700, color: 'var(--text-main)', margin: '0 0 8px' }}>
        Page Not Found
      </h1>
      <p style={{ fontSize: '14px', color: 'var(--text-muted)', margin: '0 0 24px', maxWidth: '400px', marginLeft: 'auto', marginRight: 'auto' }}>
        The requested URL was not found in the Email Threat Investigation Platform.
      </p>
      <div style={{ display: 'flex', justifyContent: 'center', gap: '12px' }}>
        <button
          type="button"
          onClick={() => navigate('/')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            backgroundColor: 'var(--primary)',
            color: '#ffffff',
            border: 'none',
            borderRadius: '6px',
            padding: '10px 18px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          <LayoutDashboard size={16} />
          <span>Return to Overview</span>
        </button>
        <button
          type="button"
          onClick={() => navigate('/new')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            backgroundColor: 'var(--bg-subtle)',
            color: 'var(--text-main)',
            border: '1px solid var(--border-strong)',
            borderRadius: '6px',
            padding: '10px 18px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          <PlusCircle size={16} />
          <span>New Analysis</span>
        </button>
      </div>
    </div>
  );
};
