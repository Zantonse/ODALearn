import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, Link as LinkIcon, FileText, Loader2, CheckCircle, AlertCircle } from 'lucide-react';
import { RichTextEditor } from '../components/ingestion/RichTextEditor';
import { parseContent, type ParsedContent } from '../services/contentParser';
import { useContentStore } from '../store/contentStore';
import { CATEGORY_LABELS, type ArticleCategory } from '../types';

type InputMethod = 'paste' | 'upload' | 'url';
type ProcessingState = 'idle' | 'processing' | 'success' | 'error';

export function ContentManager() {
  const navigate = useNavigate();
  const { addArticle } = useContentStore();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [activeMethod, setActiveMethod] = useState<InputMethod>('paste');
  const [processingState, setProcessingState] = useState<ProcessingState>('idle');
  const [error, setError] = useState<string>('');

  // Input states
  const [pastedContent, setPastedContent] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  // Parsed content state
  const [parsedContent, setParsedContent] = useState<ParsedContent | null>(null);

  // Edit states for parsed content
  const [editedTitle, setEditedTitle] = useState('');
  const [editedCategory, setEditedCategory] = useState<ArticleCategory>('other');
  const [editedTags, setEditedTags] = useState<string[]>([]);
  const [newTag, setNewTag] = useState('');

  const resetState = () => {
    setPastedContent('');
    setUrlInput('');
    setSelectedFile(null);
    setParsedContent(null);
    setError('');
    setProcessingState('idle');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setError('');
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) {
      setSelectedFile(file);
      setError('');
    }
  };

  const handleProcess = async () => {
    setError('');
    setProcessingState('processing');

    try {
      let parsed: ParsedContent;

      switch (activeMethod) {
        case 'paste':
          if (!pastedContent.trim()) {
            throw new Error('Please enter some content');
          }
          parsed = await parseContent(pastedContent, 'html');
          break;

        case 'upload':
          if (!selectedFile) {
            throw new Error('Please select a file');
          }

          const fileExt = selectedFile.name.split('.').pop()?.toLowerCase();
          if (fileExt === 'pdf') {
            parsed = await parseContent(selectedFile, 'pdf');
          } else if (fileExt === 'docx') {
            parsed = await parseContent(selectedFile, 'docx');
          } else if (fileExt === 'html' || fileExt === 'htm') {
            const text = await selectedFile.text();
            parsed = await parseContent(text, 'html');
          } else {
            throw new Error('Unsupported file type. Please use PDF, DOCX, or HTML files.');
          }
          break;

        case 'url':
          if (!urlInput.trim()) {
            throw new Error('Please enter a URL');
          }
          // Validate URL format
          try {
            new URL(urlInput);
          } catch {
            throw new Error('Please enter a valid URL');
          }
          parsed = await parseContent(urlInput, 'url');
          break;

        default:
          throw new Error('Invalid input method');
      }

      setParsedContent(parsed);
      setEditedTitle(parsed.title);
      setEditedCategory(parsed.category);
      setEditedTags(parsed.tags);
      setProcessingState('success');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to process content');
      setProcessingState('error');
    }
  };

  const handleAddTag = () => {
    if (newTag.trim() && !editedTags.includes(newTag.trim().toLowerCase())) {
      setEditedTags([...editedTags, newTag.trim().toLowerCase()]);
      setNewTag('');
    }
  };

  const handleRemoveTag = (tag: string) => {
    setEditedTags(editedTags.filter(t => t !== tag));
  };

  const handleSave = async () => {
    if (!parsedContent) return;

    const article = {
      id: `article-${Date.now()}`,
      title: editedTitle,
      content: parsedContent.content,
      summary: parsedContent.rawText.substring(0, 200) + '...',
      category: editedCategory,
      tags: editedTags,
      source: parsedContent.source,
      createdAt: new Date(),
      updatedAt: new Date(),
      isRead: false,
      isStarter: false,
    };

    await addArticle(article);
    navigate(`/knowledge/${article.id}`);
  };

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
          Add Content
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          Import content from Confluence, Okta docs, or other sources
        </p>
      </div>

      {!parsedContent ? (
        <>
          {/* Method Selector */}
          <div className="flex gap-4 mb-6">
            <button
              onClick={() => setActiveMethod('paste')}
              className={`flex-1 p-4 rounded-lg border-2 transition-all ${
                activeMethod === 'paste'
                  ? 'border-okta-blue bg-okta-light dark:bg-okta-blue/10'
                  : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
              <FileText className="w-8 h-8 mx-auto mb-2 text-okta-blue" />
              <div className="font-semibold text-gray-900 dark:text-white">Paste Text</div>
            </button>

            <button
              onClick={() => setActiveMethod('upload')}
              className={`flex-1 p-4 rounded-lg border-2 transition-all ${
                activeMethod === 'upload'
                  ? 'border-okta-blue bg-okta-light dark:bg-okta-blue/10'
                  : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
              <Upload className="w-8 h-8 mx-auto mb-2 text-okta-blue" />
              <div className="font-semibold text-gray-900 dark:text-white">Upload File</div>
            </button>

            <button
              onClick={() => setActiveMethod('url')}
              className={`flex-1 p-4 rounded-lg border-2 transition-all ${
                activeMethod === 'url'
                  ? 'border-okta-blue bg-okta-light dark:bg-okta-blue/10'
                  : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
              <LinkIcon className="w-8 h-8 mx-auto mb-2 text-okta-blue" />
              <div className="font-semibold text-gray-900 dark:text-white">Fetch URL</div>
            </button>
          </div>

          {/* Content Area */}
          <div className="card p-6">
            {activeMethod === 'paste' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Paste your content here
                </label>
                <RichTextEditor
                  content={pastedContent}
                  onChange={setPastedContent}
                  placeholder="Paste HTML, Markdown, or plain text from Confluence or Okta docs..."
                />
              </div>
            )}

            {activeMethod === 'upload' && (
              <div>
                <div
                  onDrop={handleDrop}
                  onDragOver={(e) => e.preventDefault()}
                  className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-12 text-center"
                >
                  <Upload className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                  {selectedFile ? (
                    <div>
                      <p className="text-gray-900 dark:text-white font-medium mb-2">
                        {selectedFile.name}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {(selectedFile.size / 1024).toFixed(2)} KB
                      </p>
                    </div>
                  ) : (
                    <>
                      <p className="text-gray-600 dark:text-gray-400 mb-2">
                        Drop files here or click to browse
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-500">
                        Supports PDF, DOCX, HTML files
                      </p>
                    </>
                  )}
                  <input
                    ref={fileInputRef}
                    type="file"
                    onChange={handleFileSelect}
                    accept=".pdf,.docx,.html,.htm"
                    className="hidden"
                  />
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="btn-secondary mt-4"
                  >
                    Choose File
                  </button>
                </div>
              </div>
            )}

            {activeMethod === 'url' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Enter URL
                </label>
                <input
                  type="url"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  className="input mb-4"
                  placeholder="https://help.okta.com/..."
                />
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Note: Some sites may block automatic fetching due to CORS policies. If this fails, try copying the content and using the Paste method instead.
                </p>
              </div>
            )}

            {error && (
              <div className="mt-4 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-center gap-2">
                <AlertCircle className="w-5 h-5 text-red-500" />
                <p className="text-red-700 dark:text-red-400">{error}</p>
              </div>
            )}

            <div className="mt-6 flex gap-3">
              <button
                onClick={handleProcess}
                disabled={processingState === 'processing'}
                className="btn-primary flex items-center gap-2"
              >
                {processingState === 'processing' ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Processing...
                  </>
                ) : (
                  'Process Content'
                )}
              </button>
              <button onClick={resetState} className="btn-secondary">
                Clear
              </button>
            </div>
          </div>
        </>
      ) : (
        /* Preview and Edit */
        <div className="space-y-6">
          {/* Success Message */}
          <div className="card p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 flex items-center gap-3">
            <CheckCircle className="w-6 h-6 text-green-500" />
            <div>
              <p className="font-medium text-green-900 dark:text-green-100">
                Content processed successfully!
              </p>
              <p className="text-sm text-green-700 dark:text-green-300">
                Review and edit the details below, then save.
              </p>
            </div>
          </div>

          {/* Edit Form */}
          <div className="card p-6">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
              Article Details
            </h2>

            <div className="space-y-4">
              {/* Title */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Title
                </label>
                <input
                  type="text"
                  value={editedTitle}
                  onChange={(e) => setEditedTitle(e.target.value)}
                  className="input"
                />
              </div>

              {/* Category */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Category
                </label>
                <select
                  value={editedCategory}
                  onChange={(e) => setEditedCategory(e.target.value as ArticleCategory)}
                  className="input"
                >
                  {Object.entries(CATEGORY_LABELS).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </div>

              {/* Tags */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Tags
                </label>
                <div className="flex flex-wrap gap-2 mb-2">
                  {editedTags.map((tag) => (
                    <span
                      key={tag}
                      className="px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full flex items-center gap-2"
                    >
                      {tag}
                      <button
                        onClick={() => handleRemoveTag(tag)}
                        className="text-gray-500 hover:text-gray-700 dark:hover:text-gray-200"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={newTag}
                    onChange={(e) => setNewTag(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleAddTag()}
                    placeholder="Add a tag..."
                    className="input flex-1"
                  />
                  <button onClick={handleAddTag} className="btn-secondary">
                    Add Tag
                  </button>
                </div>
              </div>

              {/* Source */}
              {parsedContent.source && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Source
                  </label>
                  <p className="text-gray-600 dark:text-gray-400 text-sm">
                    {parsedContent.source}
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Content Preview */}
          <div className="card p-6">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
              Content Preview
            </h2>
            <div
              className="prose prose-sm dark:prose-invert max-w-none"
              dangerouslySetInnerHTML={{ __html: parsedContent.content }}
            />
          </div>

          {/* Actions */}
          <div className="flex gap-3">
            <button onClick={handleSave} className="btn-primary">
              Save Article
            </button>
            <button onClick={resetState} className="btn-secondary">
              Start Over
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
