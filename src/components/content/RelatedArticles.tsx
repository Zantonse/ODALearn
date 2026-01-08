import { Link } from 'react-router-dom';
import { BookOpen, ArrowRight } from 'lucide-react';
import { CATEGORY_LABELS } from '../../types';
import type { Article } from '../../types';

interface RelatedArticlesProps {
  articles: Article[];
}

export function RelatedArticles({ articles }: RelatedArticlesProps) {
  if (articles.length === 0) {
    return null;
  }

  return (
    <div className="card p-6">
      <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
        <BookOpen className="w-5 h-5" />
        Related Articles
      </h2>
      <div className="space-y-3">
        {articles.map((article) => (
          <Link
            key={article.id}
            to={`/knowledge/${article.id}`}
            className="block p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors group"
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <h3 className="font-medium text-gray-900 dark:text-white mb-1 group-hover:text-okta-blue">
                  {article.title}
                </h3>
                <div className="flex items-center gap-2">
                  <span className="text-xs px-2 py-1 bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-300 rounded">
                    {CATEGORY_LABELS[article.category]}
                  </span>
                  {article.isRead && (
                    <span className="text-xs px-2 py-1 bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-400 rounded">
                      Read
                    </span>
                  )}
                </div>
              </div>
              <ArrowRight className="w-5 h-5 text-gray-400 group-hover:text-okta-blue group-hover:translate-x-1 transition-all" />
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
