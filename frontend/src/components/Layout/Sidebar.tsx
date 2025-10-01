import React from 'react';
import { Shield, Search, BarChart3 } from 'lucide-react';

interface SidebarProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
}

const Sidebar: React.FC<SidebarProps> = ({ activeSection, onSectionChange }) => {
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
      return 'bg-blue-500/10 border-blue-500/30 text-blue-400';
    }
    return 'bg-slate-800/30 border-slate-700/50 text-slate-400 hover:bg-slate-800/50 hover:text-white hover:border-slate-600/50';
  };

  return (
    <div className="w-64 bg-slate-900/50 backdrop-blur-xl border-r border-slate-800/50 flex flex-col py-8 px-6">
      {/* Logo with Name */}
      <div className="flex items-center space-x-3 mb-12 pb-6 border-b border-slate-800/50">
        <div className="relative flex-shrink-0">
          <div className="w-12 h-12 bg-gradient-to-br from-blue-600 to-blue-800 rounded-xl flex items-center justify-center shadow-lg shadow-blue-500/20 border border-blue-500/20">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div className="absolute -inset-0.5 bg-gradient-to-br from-blue-600 to-blue-800 rounded-xl blur opacity-20"></div>
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">Aegis IAM</h1>
          <p className="text-xs text-slate-400">AI Security Shield</p>
        </div>
      </div>

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

      {/* Status Indicator */}
      <div className="pt-6 border-t border-slate-800/50 flex items-center space-x-2">
        <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
        <span className="text-xs text-slate-400">System Active</span>
      </div>
    </div>
  );
};

export default Sidebar;