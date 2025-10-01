import React from 'react';
import { Shield, FileText, Search, BarChart3, CheckCircle } from 'lucide-react';

interface SidebarProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
}

const Sidebar: React.FC<SidebarProps> = ({ activeSection, onSectionChange }) => {
  const sections = [
    {
      id: 'generate',
      title: 'Generate Policy',
      subtitle: 'AI Co-Pilot',
      icon: Shield,
      description: 'Create secure, least-privilege IAM policies'
    },
    {
      id: 'validate',
      title: 'Validate Policy',
      subtitle: 'Security Analyst',
      icon: Search,
      description: 'Analyze existing policies for security risks'
    },
    {
      id: 'analyze',
      title: 'Analyze History',
      subtitle: 'Usage Optimizer',
      icon: BarChart3,
      description: 'Right-size permissions based on usage'
    }
  ];

  return (
    <div className="w-80 bg-slate-900 border-r border-slate-700 flex flex-col h-full">
      {/* Header */}
      <div className="p-6 border-b border-slate-700">
        <div className="flex items-center space-x-3 mb-2">
          <div className="w-10 h-10 bg-gradient-to-br from-orange-500 to-orange-600 rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Aegis IAM</h1>
            <p className="text-sm text-slate-400">The AI Security Shield</p>
          </div>
        </div>
        <div className="flex items-center space-x-2 text-xs">
          <CheckCircle className="w-3 h-3 text-green-400" />
          <span className="text-green-400">Security Mode Active</span>
        </div>
      </div>

      {/* Navigation */}
      <div className="flex-1 p-4 space-y-2">
        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4 px-2">
          AI Security Agents
        </div>
        {sections.map((section) => {
          const Icon = section.icon;
          const isActive = activeSection === section.id;
          
          return (
            <button
              key={section.id}
              onClick={() => onSectionChange(section.id)}
              className={`w-full text-left p-3 rounded-lg transition-all duration-200 group ${
                isActive
                  ? 'bg-orange-500/10 border border-orange-500/20 text-orange-400'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-white border border-transparent'
              }`}
            >
              <div className="flex items-start space-x-3">
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${
                  isActive
                    ? 'bg-orange-500/20 text-orange-400'
                    : 'bg-slate-700 text-slate-400 group-hover:bg-slate-600 group-hover:text-slate-300'
                }`}>
                  <Icon className="w-4 h-4" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center space-x-2">
                    <h3 className="font-medium text-sm">{section.title}</h3>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${
                      isActive
                        ? 'bg-orange-500/20 text-orange-300'
                        : 'bg-slate-700 text-slate-400'
                    }`}>
                      {section.subtitle}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-1">{section.description}</p>
                </div>
              </div>
            </button>
          );
        })}
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-slate-700">
        <div className="bg-slate-800 rounded-lg p-3">
          <div className="flex items-center space-x-2 mb-2">
            <Shield className="w-4 h-4 text-green-400" />
            <span className="text-sm font-medium text-white">Security Status</span>
          </div>
          <div className="text-xs text-slate-400">
            All operations are performed with least-privilege principles and comprehensive security analysis.
          </div>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;