import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';

export interface RouteInfo {
  path: string;
  params: Record<string, string>;
}

interface RouterContextType {
  currentPath: string;
  params: Record<string, string>;
  navigate: (to: string) => void;
  announcement: string;
}

const RouterContext = createContext<RouterContextType>({
  currentPath: '/',
  params: {},
  navigate: () => {},
  announcement: '',
});

export const useRouter = () => useContext(RouterContext);

interface RouterProviderProps {
  children: ReactNode;
}

export const RouterProvider: React.FC<RouterProviderProps> = ({ children }) => {
  const [currentPath, setCurrentPath] = useState<string>(
    window.location.pathname || '/'
  );
  const [announcement, setAnnouncement] = useState<string>('');

  const parseRoute = (path: string): { routePath: string; params: Record<string, string> } => {
    // Check for /investigations/:id
    const match = path.match(/^\/investigations\/([^/]+)/);
    if (match) {
      return { routePath: '/investigations/:id', params: { id: match[1] } };
    }
    return { routePath: path, params: {} };
  };

  const { params } = parseRoute(currentPath);

  const navigate = (to: string) => {
    if (to === currentPath) return;
    window.history.pushState({}, '', to);
    setCurrentPath(to);
  };

  useEffect(() => {
    const handlePopState = () => {
      setCurrentPath(window.location.pathname || '/');
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Set document.title & move focus to H1 after route change
  useEffect(() => {
    let title = 'Email Threat Platform';
    let announceMsg = 'Page loaded';

    if (currentPath === '/') {
      title = 'Overview · Email Threat Detection';
      announceMsg = 'Navigated to Overview';
    } else if (currentPath === '/new') {
      title = 'New Analysis · Email Threat Detection';
      announceMsg = 'Navigated to New Analysis';
    } else if (currentPath === '/history') {
      title = 'Investigation History · Email Threat Detection';
      announceMsg = 'Navigated to Investigation History';
    } else if (currentPath === '/status') {
      title = 'System Status · Email Threat Detection';
      announceMsg = 'Navigated to System Status';
    } else if (currentPath.startsWith('/investigations/')) {
      const id = currentPath.split('/')[2] || '';
      title = `Investigation ${id} · Email Threat Detection`;
      announceMsg = `Navigated to Investigation ${id}`;
    } else {
      title = 'Page Not Found · Email Threat Detection';
      announceMsg = 'Navigated to Page Not Found';
    }

    document.title = title;
    setAnnouncement(announceMsg);

    // Shift focus to the main H1 for screen reader wayfinding
    const timer = setTimeout(() => {
      const h1 = document.querySelector('h1');
      if (h1) {
        h1.setAttribute('tabindex', '-1');
        h1.focus({ preventScroll: true });
      }
    }, 50);

    return () => clearTimeout(timer);
  }, [currentPath]);

  return (
    <RouterContext.Provider value={{ currentPath, params, navigate, announcement }}>
      {/* Screen reader live region for route change announcements */}
      <div
        role="status"
        aria-live="polite"
        aria-atomic="true"
        style={{
          position: 'absolute',
          width: '1px',
          height: '1px',
          padding: '0',
          margin: '-1px',
          overflow: 'hidden',
          clip: 'rect(0, 0, 0, 0)',
          whiteSpace: 'nowrap',
          border: '0',
        }}
      >
        {announcement}
      </div>
      {children}
    </RouterContext.Provider>
  );
};
