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
      color: 'orange'
    },
    {
      id: 'validate',
      title: 'Validate',
      icon: Search,
      color: 'blue'
    },
    {
      id: 'analyze',
      title: 'Analyze',
      icon: BarChart3,
      color: 'purple'
    }
  ];

  const getColorClasses = (color: string, isActive: boolean) => {
    if (isActive) {
      const activeColors = {
        orange: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
        blue: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
        purple: 'bg-purple-500/10 border-purple-500/30 text-purple-400'
      };
      return activeColors[color as keyof typeof activeColors];
    }
    return 'bg-slate-800/30 border-slate-700/50 text-slate-400 hover:bg-slate-800/50 hover:text-white';
  };

  return (
    <div className="w-20 bg-slate-900/50 backdrop-blur-xl border-r border-slate-800/50 flex flex-col items-center py-8 space-y-4">
      {/* Logo */}
      <div className="w-12 h-12 bg-gradient-to-br from-orange-500 to-red-600 rounded-xl flex items-center justify-center mb-8 shadow-lg shadow-orange-500/30">
        <Shield className="w-6 h-6 text-white" />
      </div>

      {/* Navigation */}
      <div className="flex-1 flex flex-col space-y-3">
        {sections.map((section) => {
          const Icon = section.icon;
          const isActive = activeSection === section.id;
          
          return (
            <button
              key={section.id}
              onClick={() => onSectionChange(section.id)}
              className={`
                w-14 h-14 rounded-xl border transition-all duration-200
                flex items-center justify-center group relative
                ${getColorClasses(section.color, isActive)}
              `}
              title={section.title}
            >
              <Icon className="w-6 h-6" />
              
              {/* Tooltip */}
              <div className="absolute left-full ml-4 px-3 py-2 bg-slate-800 text-white text-sm rounded-lg opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none">
                {section.title}
              </div>
            </button>
          );
        })}
      </div>

      {/* Status Indicator */}
      <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
    </div>
  );
};

export default Sidebar;