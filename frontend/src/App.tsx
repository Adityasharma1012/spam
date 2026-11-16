import React from 'react';
import { RouterProvider, useRouter } from './router';
import { AppLayout } from './components/AppLayout';
import { OverviewPage } from './pages/OverviewPage';
import { NewAnalysisPage } from './pages/NewAnalysisPage';
import { HistoryPage } from './pages/HistoryPage';
import { StatusPage } from './pages/StatusPage';
import { InvestigationDetailPage } from './pages/InvestigationDetailPage';
import { NotFoundPage } from './pages/NotFoundPage';

const AppRoutes: React.FC = () => {
  const { currentPath } = useRouter();

  if (currentPath === '/') {
    return <OverviewPage />;
  }
  if (currentPath === '/new') {
    return <NewAnalysisPage />;
  }
  if (currentPath === '/history') {
    return <HistoryPage />;
  }
  if (currentPath === '/status') {
    return <StatusPage />;
  }
  if (currentPath.startsWith('/investigations/')) {
    return <InvestigationDetailPage />;
  }

  return <NotFoundPage />;
};

export const App: React.FC = () => {
  return (
    <RouterProvider>
      <AppLayout>
        <AppRoutes />
      </AppLayout>
    </RouterProvider>
  );
};

export default App;
