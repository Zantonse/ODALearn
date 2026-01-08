import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  BookOpen,
  GitBranch,
  HelpCircle,
  FolderInput,
  Settings,
  Layers
} from 'lucide-react';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/knowledge', icon: BookOpen, label: 'Knowledge Base' },
  { to: '/diagrams', icon: GitBranch, label: 'Diagrams' },
  { to: '/quiz', icon: HelpCircle, label: 'Quiz & Flashcards' },
  { to: '/content', icon: FolderInput, label: 'Add Content' },
  { to: '/settings', icon: Settings, label: 'Settings' },
];

export function Sidebar() {
  return (
    <aside className="w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-okta-blue rounded-lg flex items-center justify-center">
            <Layers className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="font-bold text-gray-900 dark:text-white">Okta Learning</h1>
            <p className="text-xs text-gray-500 dark:text-gray-400">Device Access</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4">
        <ul className="space-y-1">
          {navItems.map(({ to, icon: Icon, label }) => (
            <li key={to}>
              <NavLink
                to={to}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                    isActive
                      ? 'bg-okta-light text-okta-blue dark:bg-okta-blue/20'
                      : 'text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`
                }
              >
                <Icon className="w-5 h-5" />
                <span className="font-medium">{label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-gray-200 dark:border-gray-700">
        <p className="text-xs text-gray-500 dark:text-gray-400 text-center">
          Built with AI-powered learning
        </p>
      </div>
    </aside>
  );
}
