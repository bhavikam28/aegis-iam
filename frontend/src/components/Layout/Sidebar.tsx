import React from 'react';
import { Shield, Search, BarChart3 } from 'lucide-react';

interface SidebarProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
  onReturnHome: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ activeSection, onSectionChange, onReturnHome }) => {
  const sections = [
    {
      id: 'generate',
      title: 'Generate',
      icon: Shield,
    },
    {
      id: 'validate',
      title: 'Validate',
      icon: Search,
    },
    {
      id: 'analyze',
      title: 'Analyze',
      icon: BarChart3,
    }
  ];

  const getActiveClasses = (isActive: boolean) => {
    if (isActive) {
      return 'bg-gradient-to-r from-orange-500/10 via-pink-500/10 to-purple-500/10 border-purple-500/30 text-purple-400';
    }
    return 'bg-slate-800/30 border-slate-700/50 text-slate-400 hover:bg-gradient-to-r hover:from-slate-800/50 hover:via-purple-900/20 hover:to-slate-800/50 hover:text-white hover:border-purple-600/30';
  };

  return (
    <div className="w-64 bg-slate-900/50 backdrop-blur-xl border-r border-purple-500/10 flex flex-col py-8 px-6">
      {/* Logo with Premium Gradient - Clickable */}
      <button 
        onClick={onReturnHome}
        className="flex items-center space-x-3 mb-12 pb-6 border-b border-purple-500/20 w-full text-left hover:opacity-80 transition-opacity group"
      >
        <div className="relative flex-shrink-0">
          {/* Glow Effect */}
          <div className="absolute inset-0 bg-gradient-to-br from-orange-600 via-pink-500 to-purple-600 rounded-xl blur-lg opacity-50 group-hover:opacity-70 transition-opacity"></div>
          {/* Logo */}
          <div className="relative w-12 h-12 bg-gradient-to-br from-orange-600 via-pink-500 to-purple-600 rounded-xl flex items-center justify-center shadow-lg shadow-purple-500/20 border border-purple-500/20 group-hover:shadow-purple-500/40 transition-shadow">
            <Shield className="w-6 h-6 text-white" />
          </div>
        </div>
        <div>
          <h1 className="text-xl font-bold bg-gradient-to-r from-orange-400 via-pink-400 to-purple-400 bg-clip-text text-transparent">Aegis IAM</h1>
          <p className="text-xs text-slate-400">AI Security Shield</p>
        </div>
      </button>

      {/* Navigation */}
      <div className="flex-1 space-y-3">
        {sections.map((section) => {
          const Icon = section.icon;
          const isActive = activeSection === section.id;
          
          return (
            <button
              key={section.id}
              onClick={() => onSectionChange(section.id)}
              className={`
                w-full px-4 py-3 rounded-xl border transition-all duration-200
                flex items-center space-x-3 group
                ${getActiveClasses(isActive)}
              `}
            >
              <Icon className="w-5 h-5 flex-shrink-0" />
              <span className="font-medium">{section.title}</span>
            </button>
          );
        })}
      </div>

      {/* Status Indicator with Purple Accent */}
      <div className="pt-6 border-t border-purple-500/20 flex items-center space-x-2">
        <div className="w-2 h-2 bg-purple-400 rounded-full animate-pulse"></div>
        <span className="text-xs text-slate-400">System Active</span>
      </div>
    </div>
  );
};

export default Sidebar;