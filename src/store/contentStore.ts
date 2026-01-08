import { create } from 'zustand';
import type { Article, Quiz, Flashcard, Diagram, AppSettings, LearningProgress } from '../types';
import { articleStorage, quizStorage, flashcardStorage, diagramStorage, settingsStorage } from '../services/storage';

interface ContentState {
  // Data
  articles: Article[];
  quizzes: Quiz[];
  flashcards: Flashcard[];
  diagrams: Diagram[];
  settings: AppSettings;

  // UI state
  isLoading: boolean;
  searchQuery: string;
  selectedCategory: string | null;

  // Actions
  loadAllData: () => Promise<void>;

  // Article actions
  addArticle: (article: Article) => Promise<void>;
  updateArticle: (article: Article) => Promise<void>;
  deleteArticle: (id: string) => Promise<void>;
  markArticleRead: (id: string, isRead: boolean) => Promise<void>;

  // Quiz actions
  addQuiz: (quiz: Quiz) => Promise<void>;
  deleteQuiz: (id: string) => Promise<void>;

  // Flashcard actions
  addFlashcards: (flashcards: Flashcard[]) => Promise<void>;
  updateFlashcard: (flashcard: Flashcard) => Promise<void>;
  deleteFlashcard: (id: string) => Promise<void>;

  // Diagram actions
  addDiagram: (diagram: Diagram) => Promise<void>;
  deleteDiagram: (id: string) => Promise<void>;

  // Settings actions
  updateSettings: (settings: Partial<AppSettings>) => Promise<void>;

  // UI actions
  setSearchQuery: (query: string) => void;
  setSelectedCategory: (category: string | null) => void;

  // Computed
  getProgress: () => LearningProgress;
  getDueFlashcards: () => Flashcard[];
  getFilteredArticles: () => Article[];
}

export const useContentStore = create<ContentState>((set, get) => ({
  // Initial state
  articles: [],
  quizzes: [],
  flashcards: [],
  diagrams: [],
  settings: {
    darkMode: false,
    dailyFlashcardGoal: 20,
  },
  isLoading: true,
  searchQuery: '',
  selectedCategory: null,

  // Load all data from IndexedDB
  loadAllData: async () => {
    set({ isLoading: true });
    try {
      const [articles, quizzes, flashcards, diagrams, settings] = await Promise.all([
        articleStorage.getAll(),
        quizStorage.getAll(),
        flashcardStorage.getAll(),
        diagramStorage.getAll(),
        settingsStorage.get(),
      ]);

      set({
        articles,
        quizzes,
        flashcards,
        diagrams,
        settings,
        isLoading: false,
      });
    } catch (error) {
      console.error('Failed to load data:', error);
      set({ isLoading: false });
    }
  },

  // Article actions
  addArticle: async (article) => {
    await articleStorage.save(article);
    set(state => ({ articles: [...state.articles, article] }));
  },

  updateArticle: async (article) => {
    await articleStorage.save(article);
    set(state => ({
      articles: state.articles.map(a => a.id === article.id ? article : a),
    }));
  },

  deleteArticle: async (id) => {
    await articleStorage.delete(id);
    set(state => ({ articles: state.articles.filter(a => a.id !== id) }));
  },

  markArticleRead: async (id, isRead) => {
    await articleStorage.markAsRead(id, isRead);
    set(state => ({
      articles: state.articles.map(a => a.id === id ? { ...a, isRead } : a),
    }));
  },

  // Quiz actions
  addQuiz: async (quiz) => {
    await quizStorage.save(quiz);
    set(state => ({ quizzes: [...state.quizzes, quiz] }));
  },

  deleteQuiz: async (id) => {
    await quizStorage.delete(id);
    set(state => ({ quizzes: state.quizzes.filter(q => q.id !== id) }));
  },

  // Flashcard actions
  addFlashcards: async (flashcards) => {
    await flashcardStorage.saveMany(flashcards);
    set(state => ({ flashcards: [...state.flashcards, ...flashcards] }));
  },

  updateFlashcard: async (flashcard) => {
    await flashcardStorage.save(flashcard);
    set(state => ({
      flashcards: state.flashcards.map(f => f.id === flashcard.id ? flashcard : f),
    }));
  },

  deleteFlashcard: async (id) => {
    await flashcardStorage.delete(id);
    set(state => ({ flashcards: state.flashcards.filter(f => f.id !== id) }));
  },

  // Diagram actions
  addDiagram: async (diagram) => {
    await diagramStorage.save(diagram);
    set(state => ({ diagrams: [...state.diagrams, diagram] }));
  },

  deleteDiagram: async (id) => {
    await diagramStorage.delete(id);
    set(state => ({ diagrams: state.diagrams.filter(d => d.id !== id) }));
  },

  // Settings actions
  updateSettings: async (newSettings) => {
    const updated = { ...get().settings, ...newSettings };
    await settingsStorage.save(updated);
    set({ settings: updated });
  },

  // UI actions
  setSearchQuery: (query) => set({ searchQuery: query }),
  setSelectedCategory: (category) => set({ selectedCategory: category }),

  // Computed values
  getProgress: () => {
    const { articles, quizzes, flashcards } = get();
    const readArticles = articles.filter(a => a.isRead).length;
    const dueFlashcards = flashcards.filter(f => new Date(f.nextReviewAt) <= new Date()).length;

    return {
      articlesRead: readArticles,
      totalArticles: articles.length,
      quizzesCompleted: quizzes.length,
      averageScore: 0, // TODO: Calculate from quiz attempts
      flashcardsReviewed: flashcards.filter(f => f.repetitions > 0).length,
      flashcardsDue: dueFlashcards,
      streakDays: 0, // TODO: Track streak
      lastActivityAt: new Date(),
    };
  },

  getDueFlashcards: () => {
    const { flashcards } = get();
    const now = new Date();
    return flashcards.filter(f => new Date(f.nextReviewAt) <= now);
  },

  getFilteredArticles: () => {
    const { articles, searchQuery, selectedCategory } = get();
    let filtered = articles;

    if (selectedCategory) {
      filtered = filtered.filter(a => a.category === selectedCategory);
    }

    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(a =>
        a.title.toLowerCase().includes(query) ||
        a.content.toLowerCase().includes(query) ||
        a.tags.some(t => t.toLowerCase().includes(query))
      );
    }

    return filtered;
  },
}));
