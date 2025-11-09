import React from 'react';
import { Shield, Search, Scan } from 'lucide-react';

interface SidebarProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
  onReturnHome: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ activeSection, onSectionChange, onReturnHome }) => {
  const sections = [
    {
      id: 'generate',
      title: 'Generate Policy',
      icon: Shield,
    },
    {
      id: 'validate',
      title: 'Validate Policy',
      icon: Search,
    },
    {
      id: 'audit',
      title: 'Audit Account',
      icon: Scan,
    }
  ];

  const getActiveClasses = (isActive: boolean) => {
    if (isActive) {
      return 'bg-gradient-to-r from-blue-500/20 via-purple-500/20 to-pink-500/20 border-blue-300 text-blue-700 font-semibold shadow-md';
    }
    return 'bg-white/60 backdrop-blur-sm border-slate-200 text-slate-600 hover:bg-gradient-to-r hover:from-blue-50 hover:via-purple-50 hover:to-pink-50 hover:text-slate-900 hover:border-blue-300 hover:shadow-md';
  };

  return (
    <div className="w-64 bg-white/90 backdrop-blur-xl border-r border-slate-200/50 flex flex-col py-8 px-6 shadow-xl">
      {/* Logo with Premium Gradient - Clickable */}
      <button 
        onClick={onReturnHome}
        className="flex items-center space-x-3 mb-12 pb-6 border-b border-slate-200/50 w-full text-left hover:opacity-80 transition-opacity group"
      >
        <div className="relative flex-shrink-0">
          {/* Glow Effect */}
          <div className="absolute inset-0 bg-gradient-to-br from-blue-500 via-purple-500 to-pink-500 rounded-xl blur-lg opacity-30 group-hover:opacity-50 transition-opacity"></div>
          {/* Logo */}
          <div className="relative w-12 h-12 bg-gradient-to-br from-blue-600 via-purple-600 to-pink-600 rounded-xl flex items-center justify-center shadow-lg border border-purple-200/50 group-hover:shadow-xl transition-shadow">
            <Shield className="w-6 h-6 text-white" />
          </div>
        </div>
        <div>
          <h1 className="text-xl font-bold bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">Aegis IAM</h1>
          <p className="text-xs text-slate-500 font-medium">AI Security Shield</p>
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
                w-full px-4 py-3 rounded-xl border-2 transition-all duration-300
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

      {/* Status Indicator - Premium Light */}
      <div className="pt-6 border-t border-slate-200/50 flex items-center space-x-2">
        <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse shadow-lg shadow-emerald-500/50"></div>
        <span className="text-xs text-slate-600 font-medium">System Active</span>
      </div>
    </div>
  );
};

export default Sidebar;