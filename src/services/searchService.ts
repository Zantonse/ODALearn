import type { Article } from '../types';

export interface SearchResult {
  article: Article;
  score: number;
  matches: {
    title: boolean;
    content: boolean;
    tags: boolean;
    summary: boolean;
  };
  snippets: string[];
}

/**
 * Strip HTML tags from content
 */
function stripHtml(html: string): string {
  const div = document.createElement('div');
  div.innerHTML = html;
  return div.textContent || div.innerText || '';
}

/**
 * Get text snippet around a match
 */
function getSnippet(text: string, query: string, contextLength: number = 100): string {
  const lowerText = text.toLowerCase();
  const lowerQuery = query.toLowerCase();
  const index = lowerText.indexOf(lowerQuery);

  if (index === -1) return '';

  const start = Math.max(0, index - contextLength);
  const end = Math.min(text.length, index + query.length + contextLength);

  let snippet = text.substring(start, end);

  // Add ellipsis if needed
  if (start > 0) snippet = '...' + snippet;
  if (end < text.length) snippet = snippet + '...';

  // Highlight the match
  const regex = new RegExp(`(${query})`, 'gi');
  snippet = snippet.replace(regex, '<mark>$1</mark>');

  return snippet;
}

/**
 * Calculate relevance score for an article based on query
 */
function calculateScore(article: Article, query: string): {
  score: number;
  matches: SearchResult['matches'];
  snippets: string[];
} {
  const lowerQuery = query.toLowerCase();
  const queryWords = lowerQuery.split(/\s+/);

  let score = 0;
  const matches = {
    title: false,
    content: false,
    tags: false,
    summary: false,
  };
  const snippets: string[] = [];

  // Check title (highest weight)
  const lowerTitle = article.title.toLowerCase();
  if (lowerTitle.includes(lowerQuery)) {
    score += 100;
    matches.title = true;
  } else {
    // Check individual words in title
    queryWords.forEach(word => {
      if (word.length > 2 && lowerTitle.includes(word)) {
        score += 20;
        matches.title = true;
      }
    });
  }

  // Check tags (high weight)
  const matchingTags = article.tags.filter(tag =>
    tag.toLowerCase().includes(lowerQuery) ||
    queryWords.some(word => word.length > 2 && tag.toLowerCase().includes(word))
  );
  if (matchingTags.length > 0) {
    score += matchingTags.length * 30;
    matches.tags = true;
  }

  // Check summary (medium weight)
  if (article.summary) {
    const lowerSummary = article.summary.toLowerCase();
    if (lowerSummary.includes(lowerQuery)) {
      score += 40;
      matches.summary = true;
      const snippet = getSnippet(article.summary, lowerQuery);
      if (snippet) snippets.push(snippet);
    } else {
      queryWords.forEach(word => {
        if (word.length > 2 && lowerSummary.includes(word)) {
          score += 10;
          matches.summary = true;
        }
      });
    }
  }

  // Check content (lower weight but important)
  const plainContent = stripHtml(article.content);
  const lowerContent = plainContent.toLowerCase();

  if (lowerContent.includes(lowerQuery)) {
    score += 20;
    matches.content = true;
    const snippet = getSnippet(plainContent, lowerQuery);
    if (snippet && snippets.length < 3) snippets.push(snippet);
  }

  // Count occurrences of query words in content
  queryWords.forEach(word => {
    if (word.length > 2) {
      const regex = new RegExp(word, 'gi');
      const occurrences = (plainContent.match(regex) || []).length;
      score += Math.min(occurrences * 2, 20); // Cap contribution from each word
      if (occurrences > 0) {
        matches.content = true;
      }
    }
  });

  // Boost for exact phrase matches
  const phraseOccurrences = (lowerContent.match(new RegExp(lowerQuery, 'g')) || []).length;
  score += phraseOccurrences * 15;

  // Boost for starter content (slightly)
  if (article.isStarter) {
    score += 5;
  }

  return { score, matches, snippets };
}

/**
 * Search articles with relevance scoring
 */
export function searchArticles(articles: Article[], query: string): SearchResult[] {
  if (!query.trim()) {
    return [];
  }

  const results: SearchResult[] = [];

  for (const article of articles) {
    const { score, matches, snippets } = calculateScore(article, query);

    // Only include articles with a score > 0
    if (score > 0) {
      results.push({
        article,
        score,
        matches,
        snippets: snippets.slice(0, 2), // Limit to 2 snippets per result
      });
    }
  }

  // Sort by score (descending)
  results.sort((a, b) => b.score - a.score);

  return results;
}

/**
 * Find related articles based on tags and category
 */
export function findRelatedArticles(
  article: Article,
  allArticles: Article[],
  limit: number = 5
): Article[] {
  const related: Array<{ article: Article; score: number }> = [];

  for (const other of allArticles) {
    // Skip the same article
    if (other.id === article.id) continue;

    let score = 0;

    // Same category
    if (other.category === article.category) {
      score += 30;
    }

    // Shared tags
    const sharedTags = other.tags.filter(tag => article.tags.includes(tag));
    score += sharedTags.length * 20;

    // Only include if there's some relation
    if (score > 0) {
      related.push({ article: other, score });
    }
  }

  // Sort by score and return top results
  return related
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map(r => r.article);
}

/**
 * Get search suggestions based on partial query
 */
export function getSearchSuggestions(
  articles: Article[],
  partialQuery: string,
  limit: number = 5
): string[] {
  if (!partialQuery.trim() || partialQuery.length < 2) {
    return [];
  }

  const lowerQuery = partialQuery.toLowerCase();
  const suggestions = new Set<string>();

  // Collect from titles
  articles.forEach(article => {
    if (article.title.toLowerCase().includes(lowerQuery)) {
      suggestions.add(article.title);
    }
  });

  // Collect from tags
  articles.forEach(article => {
    article.tags.forEach(tag => {
      if (tag.toLowerCase().includes(lowerQuery)) {
        suggestions.add(tag);
      }
    });
  });

  return Array.from(suggestions).slice(0, limit);
}
