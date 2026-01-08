import Dexie, { type EntityTable } from 'dexie';
import type { Article, Quiz, QuizAttempt, Flashcard, Diagram, AppSettings } from '../types';

// Define the database
const db = new Dexie('OktaLearningDB') as Dexie & {
  articles: EntityTable<Article, 'id'>;
  quizzes: EntityTable<Quiz, 'id'>;
  quizAttempts: EntityTable<QuizAttempt, 'id'>;
  flashcards: EntityTable<Flashcard, 'id'>;
  diagrams: EntityTable<Diagram, 'id'>;
  settings: EntityTable<AppSettings & { id: string }, 'id'>;
};

db.version(1).stores({
  articles: 'id, title, category, *tags, createdAt, isRead, isStarter',
  quizzes: 'id, articleId, title, createdAt',
  quizAttempts: 'id, quizId, completedAt',
  flashcards: 'id, category, articleId, nextReviewAt',
  diagrams: 'id, title, category, isStarter',
  settings: 'id',
});

// Article operations
export const articleStorage = {
  async getAll(): Promise<Article[]> {
    return db.articles.toArray();
  },

  async getById(id: string): Promise<Article | undefined> {
    return db.articles.get(id);
  },

  async getByCategory(category: string): Promise<Article[]> {
    return db.articles.where('category').equals(category).toArray();
  },

  async search(query: string): Promise<Article[]> {
    const lowerQuery = query.toLowerCase();
    return db.articles
      .filter(article =>
        article.title.toLowerCase().includes(lowerQuery) ||
        article.content.toLowerCase().includes(lowerQuery) ||
        article.tags.some(tag => tag.toLowerCase().includes(lowerQuery))
      )
      .toArray();
  },

  async save(article: Article): Promise<string> {
    await db.articles.put(article);
    return article.id;
  },

  async delete(id: string): Promise<void> {
    await db.articles.delete(id);
  },

  async markAsRead(id: string, isRead: boolean): Promise<void> {
    await db.articles.update(id, { isRead });
  },

  async count(): Promise<number> {
    return db.articles.count();
  },

  async countRead(): Promise<number> {
    return db.articles.where('isRead').equals(1).count();
  },
};

// Quiz operations
export const quizStorage = {
  async getAll(): Promise<Quiz[]> {
    return db.quizzes.toArray();
  },

  async getById(id: string): Promise<Quiz | undefined> {
    return db.quizzes.get(id);
  },

  async getByArticle(articleId: string): Promise<Quiz[]> {
    return db.quizzes.where('articleId').equals(articleId).toArray();
  },

  async save(quiz: Quiz): Promise<string> {
    await db.quizzes.put(quiz);
    return quiz.id;
  },

  async delete(id: string): Promise<void> {
    await db.quizzes.delete(id);
  },
};

// Quiz attempt operations
export const quizAttemptStorage = {
  async getByQuiz(quizId: string): Promise<QuizAttempt[]> {
    return db.quizAttempts.where('quizId').equals(quizId).toArray();
  },

  async save(attempt: QuizAttempt): Promise<string> {
    await db.quizAttempts.put(attempt);
    return attempt.id;
  },

  async getRecent(limit: number = 10): Promise<QuizAttempt[]> {
    return db.quizAttempts.orderBy('completedAt').reverse().limit(limit).toArray();
  },
};

// Flashcard operations
export const flashcardStorage = {
  async getAll(): Promise<Flashcard[]> {
    return db.flashcards.toArray();
  },

  async getDue(): Promise<Flashcard[]> {
    const now = new Date();
    return db.flashcards.where('nextReviewAt').belowOrEqual(now).toArray();
  },

  async getByCategory(category: string): Promise<Flashcard[]> {
    return db.flashcards.where('category').equals(category).toArray();
  },

  async save(flashcard: Flashcard): Promise<string> {
    await db.flashcards.put(flashcard);
    return flashcard.id;
  },

  async saveMany(flashcards: Flashcard[]): Promise<void> {
    await db.flashcards.bulkPut(flashcards);
  },

  async delete(id: string): Promise<void> {
    await db.flashcards.delete(id);
  },

  async count(): Promise<number> {
    return db.flashcards.count();
  },

  async countDue(): Promise<number> {
    const now = new Date();
    return db.flashcards.where('nextReviewAt').belowOrEqual(now).count();
  },
};

// Diagram operations
export const diagramStorage = {
  async getAll(): Promise<Diagram[]> {
    return db.diagrams.toArray();
  },

  async getById(id: string): Promise<Diagram | undefined> {
    return db.diagrams.get(id);
  },

  async getByCategory(category: string): Promise<Diagram[]> {
    return db.diagrams.where('category').equals(category).toArray();
  },

  async save(diagram: Diagram): Promise<string> {
    await db.diagrams.put(diagram);
    return diagram.id;
  },

  async delete(id: string): Promise<void> {
    await db.diagrams.delete(id);
  },
};

// Settings operations
export const settingsStorage = {
  async get(): Promise<AppSettings> {
    const settings = await db.settings.get('app-settings');
    return settings || {
      darkMode: window.matchMedia('(prefers-color-scheme: dark)').matches,
      dailyFlashcardGoal: 20,
    };
  },

  async save(settings: AppSettings): Promise<void> {
    await db.settings.put({ ...settings, id: 'app-settings' });
  },

  async setApiKey(key: string): Promise<void> {
    const current = await this.get();
    await this.save({ ...current, openaiApiKey: key });
  },

  async getApiKey(): Promise<string | undefined> {
    const settings = await this.get();
    return settings.openaiApiKey;
  },
};

export { db };
