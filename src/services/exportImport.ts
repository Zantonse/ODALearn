import {
  articleStorage,
  quizStorage,
  quizAttemptStorage,
  flashcardStorage,
  diagramStorage,
  settingsStorage,
} from './storage';

export interface ExportData {
  version: string;
  exportedAt: string;
  articles: any[];
  quizzes: any[];
  quizAttempts: any[];
  flashcards: any[];
  diagrams: any[];
  settings: any;
}

/**
 * Export all user data as JSON
 */
export async function exportData(): Promise<string> {
  const [articles, quizzes, quizAttempts, flashcards, diagrams, settings] = await Promise.all([
    articleStorage.getAll(),
    quizStorage.getAll(),
    quizAttemptStorage.getRecent(1000), // Get all attempts
    flashcardStorage.getAll(),
    diagramStorage.getAll(),
    settingsStorage.get(),
  ]);

  const exportData: ExportData = {
    version: '1.0',
    exportedAt: new Date().toISOString(),
    articles,
    quizzes,
    quizAttempts,
    flashcards,
    diagrams,
    settings,
  };

  return JSON.stringify(exportData, null, 2);
}

/**
 * Download data as a JSON file
 */
export async function downloadExport(): Promise<void> {
  const data = await exportData();
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');

  const timestamp = new Date().toISOString().split('T')[0];
  link.download = `okta-learning-backup-${timestamp}.json`;
  link.href = url;
  link.click();

  URL.revokeObjectURL(url);
}

/**
 * Import data from JSON
 */
export async function importData(jsonData: string): Promise<{
  success: boolean;
  message: string;
  imported: {
    articles: number;
    quizzes: number;
    flashcards: number;
    diagrams: number;
  };
}> {
  try {
    const data: ExportData = JSON.parse(jsonData);

    // Validate data structure
    if (!data.version || !data.articles) {
      throw new Error('Invalid backup file format');
    }

    let importedCounts = {
      articles: 0,
      quizzes: 0,
      flashcards: 0,
      diagrams: 0,
    };

    // Import articles (skip starter content)
    if (data.articles) {
      for (const article of data.articles) {
        if (!article.isStarter) {
          await articleStorage.save(article);
          importedCounts.articles++;
        }
      }
    }

    // Import quizzes
    if (data.quizzes) {
      for (const quiz of data.quizzes) {
        await quizStorage.save(quiz);
        importedCounts.quizzes++;
      }
    }

    // Import quiz attempts
    if (data.quizAttempts) {
      for (const attempt of data.quizAttempts) {
        await quizAttemptStorage.save(attempt);
      }
    }

    // Import flashcards
    if (data.flashcards) {
      for (const flashcard of data.flashcards) {
        await flashcardStorage.save(flashcard);
        importedCounts.flashcards++;
      }
    }

    // Import diagrams (skip starter content)
    if (data.diagrams) {
      for (const diagram of data.diagrams) {
        if (!diagram.isStarter) {
          await diagramStorage.save(diagram);
          importedCounts.diagrams++;
        }
      }
    }

    // Import settings (excluding API key for security)
    if (data.settings) {
      const { openaiApiKey, ...safeSettings } = data.settings;
      const currentSettings = await settingsStorage.get();
      await settingsStorage.save({ ...currentSettings, ...safeSettings });
    }

    return {
      success: true,
      message: 'Data imported successfully',
      imported: importedCounts,
    };
  } catch (error) {
    console.error('Import error:', error);
    return {
      success: false,
      message: error instanceof Error ? error.message : 'Failed to import data',
      imported: {
        articles: 0,
        quizzes: 0,
        flashcards: 0,
        diagrams: 0,
      },
    };
  }
}

/**
 * Clear all user data (keeps starter content and settings)
 */
export async function clearUserData(): Promise<void> {
  // Get all articles and diagrams
  const articles = await articleStorage.getAll();
  const diagrams = await diagramStorage.getAll();

  // Delete only non-starter articles
  for (const article of articles) {
    if (!article.isStarter) {
      await articleStorage.delete(article.id);
    }
  }

  // Delete only non-starter diagrams
  for (const diagram of diagrams) {
    if (!diagram.isStarter) {
      await diagramStorage.delete(diagram.id);
    }
  }

  // Clear all quizzes, flashcards, and attempts
  const quizzes = await quizStorage.getAll();
  for (const quiz of quizzes) {
    await quizStorage.delete(quiz.id);
  }

  const flashcards = await flashcardStorage.getAll();
  for (const flashcard of flashcards) {
    await flashcardStorage.delete(flashcard.id);
  }

  // Note: Quiz attempts will be orphaned but that's okay
  // Could add cleanup logic if needed
}

/**
 * Get storage statistics
 */
export async function getStorageStats(): Promise<{
  articles: number;
  quizzes: number;
  flashcards: number;
  diagrams: number;
  starterArticles: number;
  starterDiagrams: number;
}> {
  const [articles, quizzes, flashcards, diagrams] = await Promise.all([
    articleStorage.getAll(),
    quizStorage.getAll(),
    flashcardStorage.getAll(),
    diagramStorage.getAll(),
  ]);

  return {
    articles: articles.filter(a => !a.isStarter).length,
    quizzes: quizzes.length,
    flashcards: flashcards.length,
    diagrams: diagrams.filter(d => !d.isStarter).length,
    starterArticles: articles.filter(a => a.isStarter).length,
    starterDiagrams: diagrams.filter(d => d.isStarter).length,
  };
}
