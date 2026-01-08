# Okta Device Access Learning Platform

A React + TypeScript web application designed to help you learn Okta Device Access through interactive content, diagrams, and quizzes.

## Features

### ✅ Phase 1 & 2 Complete

- **Knowledge Base** - Browse and read articles about Okta Device Access
- **Starter Content** - Pre-loaded articles covering:
  - Overview of Okta Device Access (Desktop MFA and Password Sync)
  - Desktop MFA for Windows and macOS
  - Desktop Password Sync for macOS
  - Setup and Configuration Guide
  - Troubleshooting Guide
- **Content Ingestion** - Import content via three methods:
  - **Paste Text** - Rich text editor with formatting support
  - **Upload Files** - PDF, DOCX, and HTML file parsing
  - **Fetch URL** - Automatic content fetching from URLs
- **Smart Parsing** - Automatic detection of:
  - Article titles
  - Categories (enrollment, authentication, troubleshooting, etc.)
  - Relevant tags
- **Local Storage** - All data stored in IndexedDB (no server required)
- **Dark Mode** - Full dark mode support
- **Search** - Search across all articles

### 🚧 Coming Next (Phase 3+)

- AI-powered summarization and quiz generation
- Interactive flow diagrams with React Flow
- Flashcard system with spaced repetition
- Quiz mode with progress tracking

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

The app will be available at http://localhost:5173

### Building for Production

```bash
npm run build
```

## How to Use

### 1. Browse Starter Content

Navigate to the **Knowledge Base** to see 5 pre-loaded articles about Okta Device Access. Click any article to read it in detail.

### 2. Add Your Own Content

Go to **Add Content** and choose your preferred method:

#### Paste Text
- Copy content from Confluence, Okta docs, or any web page
- Paste into the rich text editor
- Use the toolbar for basic formatting
- Click "Process Content"

#### Upload Files
- Drag and drop or click to select files
- Supports PDF, DOCX, and HTML files
- Content is automatically extracted and formatted
- Click "Process Content"

#### Fetch URL
- Enter any URL (e.g., https://help.okta.com/...)
- Click "Process Content"
- **Note:** Some sites may block fetching due to CORS. If this fails, use the Paste method instead.

### 3. Review and Save

After processing:
- Review the extracted title, category, and tags
- Edit any details as needed
- Add or remove tags
- Preview the formatted content
- Click "Save Article" to add it to your knowledge base

### 4. Track Progress

- Mark articles as read/unread
- View your learning progress on the Dashboard
- Search for specific topics

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Framework | React 18 + TypeScript |
| Build Tool | Vite |
| Styling | Tailwind CSS |
| Routing | React Router v6 |
| State Management | Zustand |
| Database | IndexedDB (Dexie.js) |
| Rich Text Editor | TipTap |
| PDF Parsing | pdf.js |
| DOCX Parsing | mammoth.js |
| Icons | Lucide React |

## Project Structure

```
okta-learning/
├── src/
│   ├── components/
│   │   ├── ingestion/      # Content input components
│   │   └── layout/         # App layout (sidebar, header)
│   ├── pages/              # Main page components
│   │   ├── Dashboard.tsx
│   │   ├── KnowledgeBase.tsx
│   │   ├── ArticleDetail.tsx
│   │   ├── ContentManager.tsx
│   │   └── Settings.tsx
│   ├── services/
│   │   ├── storage.ts      # IndexedDB operations
│   │   ├── contentParser.ts # Content parsing logic
│   │   └── initializeData.ts # Starter content loader
│   ├── store/
│   │   └── contentStore.ts # Zustand state management
│   ├── types/
│   │   └── index.ts        # TypeScript interfaces
│   └── data/
│       └── starterContent.ts # Pre-built articles
├── public/
└── package.json
```

## Settings

Access the **Settings** page to configure:
- **OpenAI API Key** - For AI features (Phase 3)
- **Dark Mode** - Toggle between light and dark themes
- **Daily Flashcard Goal** - Set your learning target
- **Data Management** - Export or clear your data

## Data Storage

All data is stored locally in your browser using IndexedDB:
- No server required
- Data persists across sessions
- Privacy-focused (your data never leaves your device)
- Export/import capabilities (coming soon)

## Browser Support

- Chrome/Edge (recommended)
- Safari
- Firefox
- Any modern browser with IndexedDB support

## Tips

1. **Content Formatting** - The parser preserves headings, lists, and basic formatting from source documents
2. **Tag Management** - Auto-detected tags are suggestions; you can add or remove any tags
3. **Category Selection** - Categories are auto-detected but can be changed before saving
4. **Search** - Use the search bar in the header to find content across all articles
5. **Dark Mode** - The app respects your system preference but can be toggled in Settings

## Troubleshooting

### URL Fetching Fails
Some websites block cross-origin requests. Use the Paste method instead:
1. Open the webpage in your browser
2. Copy the content (Ctrl+A, Ctrl+C)
3. Paste into the editor

### PDF Not Parsing Correctly
- Ensure the PDF has selectable text (not scanned images)
- Try converting to DOCX first if issues persist

### Content Not Saving
- Check browser console for errors
- Ensure you have storage space available
- Try refreshing the page

## Development

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## License

Private project for learning purposes.
