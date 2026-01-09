import { useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { Dashboard } from './pages/Dashboard';
import { KnowledgeBase } from './pages/KnowledgeBase';
import { ArticleDetail } from './pages/ArticleDetail';
import { DiagramExplorer } from './pages/DiagramExplorer';
import { QuizMode } from './pages/QuizMode';
import { ContentManager } from './pages/ContentManager';
import { Settings } from './pages/Settings';
import { useContentStore } from './store/contentStore';
import { initializeStarterContent } from './services/initializeData';

function App() {
  const { loadAllData, settings } = useContentStore();

  useEffect(() => {
    const init = async () => {
      // Initialize starter content
      await initializeStarterContent();

      // Load data from IndexedDB on app start
      await loadAllData();

      // Set initial dark mode based on settings
      if (settings.darkMode) {
        document.documentElement.classList.add('dark');
      }
    };

    init();
  }, []);

  return (
    <BrowserRouter basename={import.meta.env.BASE_URL}>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="knowledge" element={<KnowledgeBase />} />
          <Route path="knowledge/:id" element={<ArticleDetail />} />
          <Route path="diagrams" element={<DiagramExplorer />} />
          <Route path="quiz" element={<QuizMode />} />
          <Route path="content" element={<ContentManager />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
