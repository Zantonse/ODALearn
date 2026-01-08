import { useEffect } from 'react';
import { useContentStore } from '../store/contentStore';
import { BookOpen, CheckCircle, Brain, TrendingUp } from 'lucide-react';

export function Dashboard() {
  const { getProgress, articles, getDueFlashcards } = useContentStore();
  const progress = getProgress();
  const dueFlashcards = getDueFlashcards();
  const recentArticles = articles.slice(0, 5);

  const stats = [
    {
      label: 'Articles Read',
      value: `${progress.articlesRead} / ${progress.totalArticles}`,
      icon: BookOpen,
      color: 'text-blue-500',
      bgColor: 'bg-blue-100 dark:bg-blue-900/20',
    },
    {
      label: 'Quizzes Completed',
      value: progress.quizzesCompleted,
      icon: CheckCircle,
      color: 'text-green-500',
      bgColor: 'bg-green-100 dark:bg-green-900/20',
    },
    {
      label: 'Flashcards Due',
      value: dueFlashcards.length,
      icon: Brain,
      color: 'text-purple-500',
      bgColor: 'bg-purple-100 dark:bg-purple-900/20',
    },
    {
      label: 'Average Score',
      value: progress.averageScore ? `${progress.averageScore}%` : 'N/A',
      icon: TrendingUp,
      color: 'text-orange-500',
      bgColor: 'bg-orange-100 dark:bg-orange-900/20',
    },
  ];

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
          Welcome to Okta Device Access Learning
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          Track your progress and continue your learning journey
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <div key={stat.label} className="card p-6">
              <div className="flex items-center justify-between mb-4">
                <div className={`p-3 rounded-lg ${stat.bgColor}`}>
                  <Icon className={`w-6 h-6 ${stat.color}`} />
                </div>
              </div>
              <div className="text-3xl font-bold text-gray-900 dark:text-white mb-1">
                {stat.value}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                {stat.label}
              </div>
            </div>
          );
        })}
      </div>

      {/* Recent Articles */}
      <div className="card p-6 mb-8">
        <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
          Recent Articles
        </h2>
        {recentArticles.length > 0 ? (
          <div className="space-y-3">
            {recentArticles.map((article) => (
              <div
                key={article.id}
                className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
              >
                <div>
                  <h3 className="font-medium text-gray-900 dark:text-white">
                    {article.title}
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {article.category}
                  </p>
                </div>
                {article.isRead && (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-500 dark:text-gray-400 text-center py-8">
            No articles yet. Start by adding some content!
          </p>
        )}
      </div>

      {/* Due Flashcards */}
      {dueFlashcards.length > 0 && (
        <div className="card p-6">
          <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
            Flashcards Due for Review
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            You have {dueFlashcards.length} flashcard(s) ready to review
          </p>
          <a
            href="/quiz"
            className="btn-primary inline-block"
          >
            Start Review
          </a>
        </div>
      )}
    </div>
  );
}
