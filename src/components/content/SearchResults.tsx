import { Link } from 'react-router-dom';
import { BookOpen, Tag } from 'lucide-react';
import { CATEGORY_LABELS } from '../../types';
import type { SearchResult } from '../../services/searchService';

interface SearchResultsProps {
  results: SearchResult[];
  query: string;
}

export function SearchResults({ results, query }: SearchResultsProps) {
  if (results.length === 0) {
    return (
      <div className="card p-12 text-center">
        <BookOpen className="w-16 h-16 text-gray-400 mx-auto mb-4" />
        <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
          No results found
        </h3>
        <p className="text-gray-600 dark:text-gray-400">
          Try different keywords or browse by category
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-600 dark:text-gray-400">
        Found {results.length} result{results.length !== 1 ? 's' : ''} for "{query}"
      </p>

      {results.map(({ article, matches, snippets }) => (
        <Link
          key={article.id}
          to={`/knowledge/${article.id}`}
          className="card p-6 hover:shadow-md transition-shadow block"
        >
          <div className="flex items-start justify-between mb-3">
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                {article.title}
              </h3>

              {/* Match indicators */}
              <div className="flex flex-wrap gap-2 mb-3">
                {matches.title && (
                  <span className="px-2 py-1 bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 text-xs rounded">
                    Title match
                  </span>
                )}
                {matches.tags && (
                  <span className="px-2 py-1 bg-purple-100 dark:bg-purple-900/20 text-purple-700 dark:text-purple-400 text-xs rounded">
                    Tag match
                  </span>
                )}
                {matches.summary && (
                  <span className="px-2 py-1 bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-400 text-xs rounded">
                    Summary match
                  </span>
                )}
                {matches.content && (
                  <span className="px-2 py-1 bg-orange-100 dark:bg-orange-900/20 text-orange-700 dark:text-orange-400 text-xs rounded">
                    Content match
                  </span>
                )}
              </div>

              {/* Snippets */}
              {snippets.length > 0 && (
                <div className="space-y-2 mb-3">
                  {snippets.map((snippet, idx) => (
                    <p
                      key={idx}
                      className="text-sm text-gray-600 dark:text-gray-400"
                      dangerouslySetInnerHTML={{ __html: snippet }}
                    />
                  ))}
                </div>
              )}

              {/* Category and tags */}
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 text-xs rounded">
                  {CATEGORY_LABELS[article.category]}
                </span>
                {article.tags.slice(0, 3).map(tag => (
                  <span
                    key={tag}
                    className="px-2 py-1 bg-gray-50 dark:bg-gray-800 text-gray-600 dark:text-gray-400 text-xs rounded flex items-center gap-1"
                  >
                    <Tag className="w-3 h-3" />
                    {tag}
                  </span>
                ))}
                {article.tags.length > 3 && (
                  <span className="text-xs text-gray-500 dark:text-gray-400">
                    +{article.tags.length - 3} more
                  </span>
                )}
              </div>
            </div>

            {article.isRead && (
              <span className="ml-4 px-2 py-1 bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-400 text-xs rounded whitespace-nowrap">
                Read
              </span>
            )}
          </div>
        </Link>
      ))}
    </div>
  );
}
