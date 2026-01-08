import { useContentStore } from '../store/contentStore';
import { Brain } from 'lucide-react';

export function QuizMode() {
  const { quizzes, getDueFlashcards } = useContentStore();
  const dueFlashcards = getDueFlashcards();

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
          Quiz & Flashcards
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          Test your knowledge and review concepts
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Flashcards */}
        <div className="card p-6">
          <Brain className="w-12 h-12 text-purple-500 mb-4" />
          <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
            Flashcards
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            {dueFlashcards.length} card(s) due for review
          </p>
          <button
            className="btn-primary"
            disabled={dueFlashcards.length === 0}
          >
            Start Review
          </button>
        </div>

        {/* Quizzes */}
        <div className="card p-6">
          <Brain className="w-12 h-12 text-green-500 mb-4" />
          <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
            Quizzes
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            {quizzes.length} quiz(zes) available
          </p>
          <button
            className="btn-primary"
            disabled={quizzes.length === 0}
          >
            Take Quiz
          </button>
        </div>
      </div>
    </div>
  );
}
