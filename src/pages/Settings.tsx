import { useState, useEffect, useRef } from 'react';
import { useContentStore } from '../store/contentStore';
import { Key, Moon, Target, Database, Download, Upload, Trash2, AlertCircle } from 'lucide-react';
import { downloadExport, importData, clearUserData, getStorageStats } from '../services/exportImport';

export function Settings() {
  const { settings, updateSettings, loadAllData } = useContentStore();
  const [apiKey, setApiKey] = useState(settings.openaiApiKey || '');
  const [saved, setSaved] = useState(false);
  const [stats, setStats] = useState({ articles: 0, quizzes: 0, flashcards: 0, diagrams: 0, starterArticles: 0, starterDiagrams: 0 });
  const [importing, setImporting] = useState(false);
  const [importMessage, setImportMessage] = useState('');
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    const storageStats = await getStorageStats();
    setStats(storageStats);
  };

  const handleSaveApiKey = async () => {
    await updateSettings({ openaiApiKey: apiKey });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleExport = async () => {
    try {
      await downloadExport();
    } catch (error) {
      console.error('Export failed:', error);
      alert('Failed to export data');
    }
  };

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setImporting(true);
    setImportMessage('');

    try {
      const text = await file.text();
      const result = await importData(text);

      if (result.success) {
        setImportMessage(
          `Successfully imported: ${result.imported.articles} articles, ${result.imported.quizzes} quizzes, ${result.imported.flashcards} flashcards, ${result.imported.diagrams} diagrams`
        );
        await loadAllData(); // Reload data
        await loadStats(); // Reload stats
      } else {
        setImportMessage(`Import failed: ${result.message}`);
      }
    } catch (error) {
      setImportMessage('Failed to import data. Please check the file format.');
    } finally {
      setImporting(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const handleClearData = async () => {
    try {
      await clearUserData();
      await loadAllData(); // Reload data
      await loadStats(); // Reload stats
      setShowClearConfirm(false);
      alert('User data cleared successfully. Starter content has been preserved.');
    } catch (error) {
      console.error('Clear failed:', error);
      alert('Failed to clear data');
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
          Settings
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          Configure your learning preferences and API keys
        </p>
      </div>

      <div className="space-y-6">
        {/* OpenAI API Key */}
        <div className="card p-6">
          <div className="flex items-center gap-3 mb-4">
            <Key className="w-6 h-6 text-okta-blue" />
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">
              OpenAI API Key
            </h2>
          </div>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Required for AI-powered features like summarization and quiz generation
          </p>
          <div className="flex gap-3">
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="sk-..."
              className="input flex-1"
            />
            <button
              onClick={handleSaveApiKey}
              className="btn-primary"
            >
              {saved ? 'Saved!' : 'Save'}
            </button>
          </div>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
            Get your API key from{' '}
            <a
              href="https://platform.openai.com/api-keys"
              target="_blank"
              rel="noopener noreferrer"
              className="text-okta-blue hover:underline"
            >
              OpenAI Platform
            </a>
          </p>
        </div>

        {/* Dark Mode */}
        <div className="card p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Moon className="w-6 h-6 text-okta-blue" />
              <div>
                <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                  Dark Mode
                </h2>
                <p className="text-gray-600 dark:text-gray-400 text-sm">
                  Toggle dark mode theme
                </p>
              </div>
            </div>
            <button
              onClick={() => {
                const newValue = !settings.darkMode;
                updateSettings({ darkMode: newValue });
                document.documentElement.classList.toggle('dark', newValue);
              }}
              className={`relative w-14 h-7 rounded-full transition-colors ${
                settings.darkMode ? 'bg-okta-blue' : 'bg-gray-300'
              }`}
            >
              <div
                className={`absolute top-1 w-5 h-5 bg-white rounded-full transition-transform ${
                  settings.darkMode ? 'translate-x-8' : 'translate-x-1'
                }`}
              />
            </button>
          </div>
        </div>

        {/* Daily Goal */}
        <div className="card p-6">
          <div className="flex items-center gap-3 mb-4">
            <Target className="w-6 h-6 text-okta-blue" />
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">
              Daily Flashcard Goal
            </h2>
          </div>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Set how many flashcards you want to review each day
          </p>
          <input
            type="number"
            value={settings.dailyFlashcardGoal}
            onChange={(e) => updateSettings({ dailyFlashcardGoal: parseInt(e.target.value) || 20 })}
            min="1"
            max="100"
            className="input w-32"
          />
        </div>

        {/* Data Management */}
        <div className="card p-6">
          <div className="flex items-center gap-3 mb-4">
            <Database className="w-6 h-6 text-okta-blue" />
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">
              Data Management
            </h2>
          </div>

          {/* Storage Stats */}
          <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 mb-4">
            <h3 className="font-semibold text-gray-900 dark:text-white mb-3">Storage Statistics</h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-gray-600 dark:text-gray-400">Your Articles:</span>
                <span className="ml-2 font-medium text-gray-900 dark:text-white">{stats.articles}</span>
              </div>
              <div>
                <span className="text-gray-600 dark:text-gray-400">Starter Articles:</span>
                <span className="ml-2 font-medium text-gray-900 dark:text-white">{stats.starterArticles}</span>
              </div>
              <div>
                <span className="text-gray-600 dark:text-gray-400">Your Diagrams:</span>
                <span className="ml-2 font-medium text-gray-900 dark:text-white">{stats.diagrams}</span>
              </div>
              <div>
                <span className="text-gray-600 dark:text-gray-400">Starter Diagrams:</span>
                <span className="ml-2 font-medium text-gray-900 dark:text-white">{stats.starterDiagrams}</span>
              </div>
              <div>
                <span className="text-gray-600 dark:text-gray-400">Quizzes:</span>
                <span className="ml-2 font-medium text-gray-900 dark:text-white">{stats.quizzes}</span>
              </div>
              <div>
                <span className="text-gray-600 dark:text-gray-400">Flashcards:</span>
                <span className="ml-2 font-medium text-gray-900 dark:text-white">{stats.flashcards}</span>
              </div>
            </div>
          </div>

          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Export your data for backup or import from a previous backup. Starter content is never exported or deleted.
          </p>

          {/* Import Message */}
          {importMessage && (
            <div className={`p-3 rounded-lg mb-4 ${
              importMessage.includes('Successfully')
                ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400'
                : 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400'
            }`}>
              {importMessage}
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-3">
            <button
              onClick={handleExport}
              className="btn-secondary flex items-center gap-2"
            >
              <Download className="w-4 h-4" />
              Export Data
            </button>

            <label className="btn-secondary flex items-center gap-2 cursor-pointer">
              <Upload className="w-4 h-4" />
              {importing ? 'Importing...' : 'Import Data'}
              <input
                ref={fileInputRef}
                type="file"
                accept=".json"
                onChange={handleImportFile}
                disabled={importing}
                className="hidden"
              />
            </label>

            {!showClearConfirm ? (
              <button
                onClick={() => setShowClearConfirm(true)}
                className="btn-secondary text-red-600 dark:text-red-400 flex items-center gap-2"
              >
                <Trash2 className="w-4 h-4" />
                Clear User Data
              </button>
            ) : (
              <div className="flex items-center gap-3 p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
                <AlertCircle className="w-5 h-5 text-red-600" />
                <span className="text-sm text-red-700 dark:text-red-400">
                  Are you sure? This cannot be undone.
                </span>
                <button
                  onClick={handleClearData}
                  className="px-3 py-1 bg-red-600 text-white rounded hover:bg-red-700 text-sm"
                >
                  Yes, Clear
                </button>
                <button
                  onClick={() => setShowClearConfirm(false)}
                  className="px-3 py-1 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600 text-sm"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>

          <p className="text-xs text-gray-500 dark:text-gray-400 mt-4">
            <strong>Note:</strong> Clearing data removes your articles, quizzes, and flashcards but preserves starter content and settings.
          </p>
        </div>
      </div>
    </div>
  );
}
