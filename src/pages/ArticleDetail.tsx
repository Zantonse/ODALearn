import { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useContentStore } from '../store/contentStore';
import { ArrowLeft, CheckCircle, Circle, ExternalLink } from 'lucide-react';
import { CATEGORY_LABELS } from '../types';
import { findRelatedArticles } from '../services/searchService';
import { RelatedArticles } from '../components/content/RelatedArticles';

export function ArticleDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { articles, markArticleRead } = useContentStore();
  const [article, setArticle] = useState(articles.find(a => a.id === id));
  const [relatedArticles, setRelatedArticles] = useState(
    article ? findRelatedArticles(article, articles) : []
  );

  useEffect(() => {
    const found = articles.find(a => a.id === id);
    if (found) {
      setArticle(found);
      setRelatedArticles(findRelatedArticles(found, articles));
    }
  }, [id, articles]);

  if (!article) {
    return (
      <div className="p-6 max-w-4xl mx-auto">
        <div className="card p-12 text-center">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
            Article not found
          </h2>
          <Link to="/knowledge" className="btn-primary inline-block">
            Back to Knowledge Base
          </Link>
        </div>
      </div>
    );
  }

  const toggleReadStatus = async () => {
    await markArticleRead(article.id, !article.isRead);
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      {/* Back Button */}
      <button
        onClick={() => navigate('/knowledge')}
        className="btn-secondary flex items-center gap-2 mb-6"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to Knowledge Base
      </button>

      {/* Article Header */}
      <div className="card p-8 mb-6">
        <div className="flex items-start justify-between mb-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-3">
              <span className="px-3 py-1 bg-okta-light dark:bg-okta-blue/20 text-okta-blue text-sm rounded-full">
                {CATEGORY_LABELS[article.category]}
              </span>
              {article.isStarter && (
                <span className="px-3 py-1 bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 text-sm rounded-full">
                  Starter Content
                </span>
              )}
            </div>
            <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">
              {article.title}
            </h1>
            {article.summary && (
              <p className="text-lg text-gray-600 dark:text-gray-400">
                {article.summary}
              </p>
            )}
          </div>
        </div>

        {/* Meta Info */}
        <div className="flex items-center gap-6 text-sm text-gray-500 dark:text-gray-400 mb-4">
          <span>Updated: {new Date(article.updatedAt).toLocaleDateString()}</span>
          {article.source && (
            <a
              href={article.source}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-okta-blue hover:underline"
            >
              <ExternalLink className="w-4 h-4" />
              Source
            </a>
          )}
        </div>

        {/* Read Status Toggle */}
        <button
          onClick={toggleReadStatus}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
            article.isRead
              ? 'bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-400'
              : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300'
          }`}
        >
          {article.isRead ? (
            <>
              <CheckCircle className="w-5 h-5" />
              Mark as Unread
            </>
          ) : (
            <>
              <Circle className="w-5 h-5" />
              Mark as Read
            </>
          )}
        </button>
      </div>

      {/* Article Content */}
      <div className="card p-8">
        <div
          className="prose prose-blue dark:prose-invert max-w-none"
          dangerouslySetInnerHTML={{ __html: article.content }}
        />
      </div>

      {/* Tags */}
      {article.tags.length > 0 && (
        <div className="card p-6 mt-6">
          <h3 className="text-sm font-semibold text-gray-500 dark:text-gray-400 uppercase mb-3">
            Tags
          </h3>
          <div className="flex flex-wrap gap-2">
            {article.tags.map((tag) => (
              <span
                key={tag}
                className="px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 text-sm rounded-full"
              >
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Related Articles */}
      {relatedArticles.length > 0 && (
        <div className="mt-6">
          <RelatedArticles articles={relatedArticles} />
        </div>
      )}
    </div>
  );
}
