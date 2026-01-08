import * as pdfjsLib from 'pdfjs-dist';
import mammoth from 'mammoth';
import type { ArticleCategory } from '../types';

// Configure PDF.js worker
pdfjsLib.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.js`;

export interface ParsedContent {
  title: string;
  content: string;
  rawText: string;
  category: ArticleCategory;
  tags: string[];
  source?: string;
}

/**
 * Clean HTML content by removing scripts, styles, and unwanted attributes
 */
export function cleanHtml(html: string): string {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');

  // Remove script and style tags
  doc.querySelectorAll('script, style, iframe, object, embed').forEach(el => el.remove());

  // Remove event handlers and dangerous attributes
  doc.querySelectorAll('*').forEach(el => {
    Array.from(el.attributes).forEach(attr => {
      if (attr.name.startsWith('on') || ['src', 'href'].includes(attr.name)) {
        if (attr.name === 'href' && el.tagName === 'A') {
          // Keep href for links but sanitize
          const href = attr.value;
          if (!href.startsWith('http://') && !href.startsWith('https://') && !href.startsWith('#')) {
            el.removeAttribute('href');
          }
        } else if (attr.name === 'src' && el.tagName === 'IMG') {
          // Keep image src
        } else if (attr.name.startsWith('on')) {
          el.removeAttribute(attr.name);
        }
      }
    });
  });

  return doc.body.innerHTML;
}

/**
 * Extract plain text from HTML
 */
export function htmlToText(html: string): string {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');
  return doc.body.textContent || '';
}

/**
 * Try to extract title from HTML content
 */
export function extractTitle(html: string): string {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');

  // Try h1 first
  const h1 = doc.querySelector('h1');
  if (h1?.textContent) {
    return h1.textContent.trim();
  }

  // Try title tag
  const title = doc.querySelector('title');
  if (title?.textContent) {
    return title.textContent.trim();
  }

  // Try first heading
  const firstHeading = doc.querySelector('h1, h2, h3');
  if (firstHeading?.textContent) {
    return firstHeading.textContent.trim();
  }

  // Use first line of text
  const text = htmlToText(html);
  const firstLine = text.split('\n')[0].trim();
  return firstLine.substring(0, 100) || 'Untitled Article';
}

/**
 * Auto-detect category based on content
 */
export function detectCategory(text: string): ArticleCategory {
  const lower = text.toLowerCase();

  if (lower.includes('enroll') || lower.includes('registration')) {
    return 'enrollment';
  }
  if (lower.includes('authentication') || lower.includes('login') || lower.includes('sign in')) {
    return 'authentication';
  }
  if (lower.includes('certificate') || lower.includes('cert')) {
    return 'certificates';
  }
  if (lower.includes('troubleshoot') || lower.includes('error') || lower.includes('issue')) {
    return 'troubleshooting';
  }
  if (lower.includes('mdm') || lower.includes('intune') || lower.includes('jamf') || lower.includes('integration')) {
    return 'integration';
  }
  if (lower.includes('policy') || lower.includes('policies')) {
    return 'policies';
  }
  if (lower.includes('overview') || lower.includes('introduction') || lower.includes('what is')) {
    return 'overview';
  }

  return 'other';
}

/**
 * Extract relevant tags from content
 */
export function extractTags(text: string): string[] {
  const tags = new Set<string>();
  const lower = text.toLowerCase();

  // Common Okta terms
  const keywords = [
    'device trust',
    'device access',
    'okta verify',
    'mdm',
    'intune',
    'jamf',
    'certificate',
    'enrollment',
    'authentication',
    'compliance',
    'zero trust',
    'mfa',
    'sso',
    'saml',
    'troubleshooting',
    'windows',
    'macos',
    'ios',
    'android',
  ];

  keywords.forEach(keyword => {
    if (lower.includes(keyword)) {
      tags.add(keyword);
    }
  });

  return Array.from(tags).slice(0, 8); // Limit to 8 tags
}

/**
 * Parse HTML content (from paste or HTML file)
 */
export async function parseHtml(html: string, source?: string): Promise<ParsedContent> {
  const cleanedHtml = cleanHtml(html);
  const rawText = htmlToText(cleanedHtml);
  const title = extractTitle(html);
  const category = detectCategory(rawText);
  const tags = extractTags(rawText);

  return {
    title,
    content: cleanedHtml,
    rawText,
    category,
    tags,
    source,
  };
}

/**
 * Parse PDF file
 */
export async function parsePdf(file: File): Promise<ParsedContent> {
  const arrayBuffer = await file.arrayBuffer();
  const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;

  let fullText = '';

  // Extract text from all pages
  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const textContent = await page.getTextContent();
    const pageText = textContent.items
      .map((item: any) => item.str)
      .join(' ');
    fullText += pageText + '\n\n';
  }

  // Convert text to basic HTML
  const paragraphs = fullText
    .split('\n\n')
    .filter(p => p.trim())
    .map(p => `<p>${p.trim()}</p>`)
    .join('\n');

  const title = file.name.replace('.pdf', '').replace(/[-_]/g, ' ');
  const category = detectCategory(fullText);
  const tags = extractTags(fullText);

  return {
    title,
    content: paragraphs,
    rawText: fullText,
    category,
    tags,
    source: file.name,
  };
}

/**
 * Parse DOCX file
 */
export async function parseDocx(file: File): Promise<ParsedContent> {
  const arrayBuffer = await file.arrayBuffer();
  const result = await mammoth.convertToHtml({ arrayBuffer });

  const html = result.value;
  const rawText = htmlToText(html);
  const title = file.name.replace('.docx', '').replace(/[-_]/g, ' ');
  const category = detectCategory(rawText);
  const tags = extractTags(rawText);

  return {
    title,
    content: cleanHtml(html),
    rawText,
    category,
    tags,
    source: file.name,
  };
}

/**
 * Fetch and parse content from URL
 */
export async function fetchUrl(url: string): Promise<ParsedContent> {
  try {
    // Use a CORS proxy for fetching (this may not work for all sites)
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`Failed to fetch: ${response.statusText}`);
    }

    const html = await response.text();
    return parseHtml(html, url);
  } catch (error) {
    throw new Error(`Failed to fetch URL: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Main parser function that handles all input types
 */
export async function parseContent(
  input: string | File,
  type: 'html' | 'pdf' | 'docx' | 'url'
): Promise<ParsedContent> {
  switch (type) {
    case 'html':
      return parseHtml(input as string);

    case 'pdf':
      return parsePdf(input as File);

    case 'docx':
      return parseDocx(input as File);

    case 'url':
      return fetchUrl(input as string);

    default:
      throw new Error('Unsupported content type');
  }
}
