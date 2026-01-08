import { articleStorage, diagramStorage } from './storage';
import { starterArticles, starterDiagrams } from '../data/starterContent';

// Version 2 - Updated with correct Okta Device Access information
const INITIALIZED_KEY = 'data-initialized-v3';

export async function initializeStarterContent() {
  // Check if we've already initialized this version
  const alreadyInitialized = localStorage.getItem(INITIALIZED_KEY);

  if (alreadyInitialized) {
    console.log('Starter content already loaded');
    return;
  }

  try {
    console.log('Loading starter content...');

    // Delete old starter content if it exists (from v1)
    const existingArticles = await articleStorage.getAll();
    for (const article of existingArticles) {
      if (article.isStarter) {
        await articleStorage.delete(article.id);
      }
    }

    const existingDiagrams = await diagramStorage.getAll();
    for (const diagram of existingDiagrams) {
      if (diagram.isStarter) {
        await diagramStorage.delete(diagram.id);
      }
    }

    // Load new starter articles
    for (const article of starterArticles) {
      await articleStorage.save(article);
    }

    // Load new starter diagrams
    for (const diagram of starterDiagrams) {
      await diagramStorage.save(diagram);
    }

    // Mark as initialized
    localStorage.setItem(INITIALIZED_KEY, 'true');

    console.log('Starter content loaded successfully!');
  } catch (error) {
    console.error('Failed to load starter content:', error);
  }
}

export function resetStarterContent() {
  localStorage.removeItem(INITIALIZED_KEY);
  // Also remove old version key
  localStorage.removeItem('data-initialized');
}
