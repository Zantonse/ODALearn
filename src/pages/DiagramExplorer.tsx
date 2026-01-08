import { useContentStore } from '../store/contentStore';
import { GitBranch } from 'lucide-react';

export function DiagramExplorer() {
  const { diagrams } = useContentStore();

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
          Interactive Diagrams
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          Explore Okta Device Access flows and processes
        </p>
      </div>

      {diagrams.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {diagrams.map((diagram) => (
            <div key={diagram.id} className="card p-6">
              <GitBranch className="w-8 h-8 text-okta-blue mb-3" />
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                {diagram.title}
              </h3>
              <p className="text-gray-600 dark:text-gray-400 text-sm">
                {diagram.description || 'Interactive flow diagram'}
              </p>
            </div>
          ))}
        </div>
      ) : (
        <div className="card p-12 text-center">
          <GitBranch className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
            No diagrams yet
          </h3>
          <p className="text-gray-600 dark:text-gray-400">
            Diagrams will be available soon!
          </p>
        </div>
      )}
    </div>
  );
}
