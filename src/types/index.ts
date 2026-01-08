// Content types
export interface Article {
  id: string;
  title: string;
  content: string; // HTML content
  summary?: string; // AI-generated summary
  category: ArticleCategory;
  tags: string[];
  source?: string; // URL or filename of source
  createdAt: Date;
  updatedAt: Date;
  isRead: boolean;
  isStarter?: boolean; // Pre-built content
}

export type ArticleCategory =
  | 'overview'
  | 'enrollment'
  | 'authentication'
  | 'certificates'
  | 'troubleshooting'
  | 'integration'
  | 'policies'
  | 'other';

export const CATEGORY_LABELS: Record<ArticleCategory, string> = {
  overview: 'Overview',
  enrollment: 'Device Enrollment',
  authentication: 'Authentication',
  certificates: 'Certificates',
  troubleshooting: 'Troubleshooting',
  integration: 'Integrations',
  policies: 'Policies',
  other: 'Other',
};

// Quiz types
export interface Quiz {
  id: string;
  articleId?: string; // Associated article
  title: string;
  questions: QuizQuestion[];
  createdAt: Date;
}

export interface QuizQuestion {
  id: string;
  type: 'multiple-choice' | 'true-false' | 'fill-blank';
  question: string;
  options?: string[]; // For multiple choice
  correctAnswer: string | number; // Index for multiple choice, or text for fill-blank
  explanation?: string;
}

export interface QuizAttempt {
  id: string;
  quizId: string;
  score: number;
  totalQuestions: number;
  answers: Record<string, string | number>;
  completedAt: Date;
}

// Flashcard types
export interface Flashcard {
  id: string;
  front: string; // Question/term
  back: string; // Answer/definition
  category: ArticleCategory;
  articleId?: string;
  nextReviewAt: Date; // For spaced repetition
  easeFactor: number; // SM-2 algorithm
  interval: number; // Days until next review
  repetitions: number;
}

// Diagram types
export interface DiagramNode {
  id: string;
  type: 'step' | 'decision' | 'start' | 'end' | 'process';
  label: string;
  description?: string;
  position: { x: number; y: number };
}

export interface DiagramEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  animated?: boolean;
}

export interface Diagram {
  id: string;
  title: string;
  description?: string;
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  category: ArticleCategory;
  isStarter?: boolean;
}

// Progress tracking
export interface LearningProgress {
  articlesRead: number;
  totalArticles: number;
  quizzesCompleted: number;
  averageScore: number;
  flashcardsReviewed: number;
  flashcardsDue: number;
  streakDays: number;
  lastActivityAt: Date;
}

// Settings
export interface AppSettings {
  openaiApiKey?: string;
  darkMode: boolean;
  dailyFlashcardGoal: number;
}

// AI types
export interface AIProcessingResult {
  summary?: string;
  concepts?: string[];
  tags?: string[];
  flashcards?: Omit<Flashcard, 'id' | 'nextReviewAt' | 'easeFactor' | 'interval' | 'repetitions'>[];
  quizQuestions?: Omit<QuizQuestion, 'id'>[];
}
