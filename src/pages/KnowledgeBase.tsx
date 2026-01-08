import { useState, useEffect } from 'react';
import { useContentStore } from '../store/contentStore';
import { CATEGORY_LABELS, type ArticleCategory } from '../types';
import { BookOpen, Filter, X } from 'lucide-react';
import { Link } from 'react-router-dom';
import { searchArticles } from '../services/searchService';
import { SearchResults } from '../components/content/SearchResults';

export function KnowledgeBase() {
  const { articles, searchQuery, selectedCategory, setSelectedCategory } = useContentStore();
  const [showFilters, setShowFilters] = useState(false);
  const [localSearchQuery, setLocalSearchQuery] = useState('');

  // Sync with store search query
  useEffect(() => {
    setLocalSearchQuery(searchQuery);
  }, [searchQuery]);

  const categories = Object.entries(CATEGORY_LABELS);

  // Use enhanced search when there's a query
  const searchResults = localSearchQuery.trim()
    ? searchArticles(articles, localSearchQuery)
    : null;

  // Filter articles by category when not searching
  const filteredArticles = !searchResults
    ? articles.filter(a => !selectedCategory || a.category === selectedCategory)
    : null;

  const hasActiveFilters = selectedCategory !== null;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
            Knowledge Base
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Browse and search Okta Device Access documentation
          </p>
        </div>
        <div className="flex gap-2">
          {hasActiveFilters && (
            <button
              onClick={() => setSelectedCategory(null)}
              className="btn-secondary flex items-center gap-2"
            >
              <X className="w-4 h-4" />
              Clear Filters
            </button>
          )}
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="btn-secondary flex items-center gap-2"
          >
            <Filter className="w-4 h-4" />
            Filter
          </button>
        </div>
      </div>

      {/* Category Filter */}
      {showFilters && (
        <div className="card p-4 mb-6">
          <h3 className="font-semibold text-gray-900 dark:text-white mb-3">
            Filter by Category
          </h3>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setSelectedCategory(null)}
              className={`px-4 py-2 rounded-lg transition-colors ${
                selectedCategory === null
                  ? 'bg-okta-blue text-white'
                  : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
              }`}
            >
              All
            </button>
            {categories.map(([value, label]) => (
              <button
                key={value}
                onClick={() => setSelectedCategory(value as ArticleCategory)}
                className={`px-4 py-2 rounded-lg transition-colors ${
                  selectedCategory === value
                    ? 'bg-okta-blue text-white'
                    : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Search Results or Articles Grid */}
      {searchResults ? (
        <SearchResults results={searchResults} query={localSearchQuery} />
      ) : filteredArticles && filteredArticles.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredArticles.map((article) => (
            <Link
              key={article.id}
              to={`/knowledge/${article.id}`}
              className="card p-6 hover:shadow-md transition-shadow"
            >
              <div className="flex items-start justify-between mb-3">
                <BookOpen className="w-8 h-8 text-okta-blue" />
                {article.isRead && (
                  <span className="px-2 py-1 bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-400 text-xs rounded">
                    Read
                  </span>
                )}
              </div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                {article.title}
              </h3>
              {article.summary && (
                <p className="text-gray-600 dark:text-gray-400 text-sm mb-3 line-clamp-3">
                  {article.summary}
                </p>
              )}
              <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                <span className="px-2 py-1 bg-gray-100 dark:bg-gray-700 rounded">
                  {CATEGORY_LABELS[article.category]}
                </span>
                {article.isStarter && (
                  <span className="px-2 py-1 bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 rounded">
                    Starter
                  </span>
                )}
              </div>
            </Link>
          ))}
        </div>
      ) : (
        <div className="card p-12 text-center">
          <BookOpen className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
            No articles found
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-6">
            {localSearchQuery
              ? 'Try different keywords or clear your search'
              : 'Start by adding some content to your knowledge base'}
          </p>
          {!localSearchQuery && (
            <Link to="/content" className="btn-primary inline-block">
              Add Content
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
