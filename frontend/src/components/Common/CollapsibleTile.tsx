import React, { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

interface CollapsibleTileProps {
  title: string;
  subtitle?: string;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
  defaultExpanded?: boolean;
  children: React.ReactNode;
  className?: string;
  headerClassName?: string;
  contentClassName?: string;
  variant?: 'default' | 'success' | 'warning' | 'error' | 'info';
}

const CollapsibleTile: React.FC<CollapsibleTileProps> = ({
  title,
  subtitle,
  icon,
  badge,
  defaultExpanded = false,
  children,
  className = '',
  headerClassName = '',
  contentClassName = '',
  variant = 'default',
}) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  const variantStyles = {
    default: 'bg-white/80 backdrop-blur-xl border-2 border-slate-200/50',
    success: 'bg-white/80 backdrop-blur-xl border-2 border-green-200/50',
    warning: 'bg-white/80 backdrop-blur-xl border-2 border-amber-200/50',
    error: 'bg-white/80 backdrop-blur-xl border-2 border-red-200/50',
    info: 'bg-white/80 backdrop-blur-xl border-2 border-blue-200/50',
  };

  return (
    <div className={`${variantStyles[variant]} rounded-2xl shadow-xl hover:shadow-2xl transition-all duration-300 ${className}`}>
      {/* Header - Always Visible */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className={`w-full px-6 py-4 flex items-center justify-between hover:bg-slate-50/50 transition-colors duration-200 rounded-t-2xl ${headerClassName}`}
      >
        <div className="flex items-center space-x-3 flex-1 min-w-0">
          {icon && <div className="flex-shrink-0">{icon}</div>}
          <div className="flex-1 min-w-0 text-left">
            <div className="flex items-center space-x-2">
              <h4 className="text-slate-900 font-bold text-lg truncate">{title}</h4>
              {badge && <div className="flex-shrink-0">{badge}</div>}
            </div>
            {subtitle && (
              <p className="text-xs text-slate-500 font-medium mt-1 truncate">{subtitle}</p>
            )}
          </div>
        </div>
        <div className="flex-shrink-0 ml-4">
          {isExpanded ? (
            <ChevronUp className="w-5 h-5 text-slate-400 hover:text-slate-600 transition-colors" />
          ) : (
            <ChevronDown className="w-5 h-5 text-slate-400 hover:text-slate-600 transition-colors" />
          )}
        </div>
      </button>

      {/* Content - Collapsible */}
      {isExpanded && (
        <div className={`px-6 pb-6 pt-2 border-t border-slate-200/50 ${contentClassName}`}>
          {children}
        </div>
      )}
    </div>
  );
};

export default CollapsibleTile;

