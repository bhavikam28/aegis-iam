import React from 'react';
import { Shield } from 'lucide-react';
import SecurityTips from './SecurityTips';

interface LoadingScreenProps {
  title: string;
  subtitle: string;
  steps: Array<{ label: string; active: boolean; completed: boolean }>;
  rotationInterval?: number; // Optional: override default rotation interval for SecurityTips
}

const LoadingScreen: React.FC<LoadingScreenProps> = ({ 
  title, 
  subtitle, 
  steps,
  rotationInterval = 4000
}) => {
  return (
    <div className="min-h-screen flex items-center justify-center relative overflow-hidden">
      {/* Animated Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 right-0 w-[800px] h-[800px] bg-gradient-to-br from-blue-400/8 via-purple-400/6 to-pink-400/4 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 left-0 w-[700px] h-[700px] bg-gradient-to-tr from-amber-400/6 via-orange-400/4 to-red-400/3 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '2s' }}></div>
      </div>

      <div className="relative z-10 max-w-2xl mx-auto px-4 text-center">
        {/* Central Shield Icon with Animation */}
        <div className="relative mb-8 flex justify-center">
          <div className="relative">
            <Shield className="w-24 h-24 text-blue-500/20" />
            <div className="absolute inset-0 flex items-center justify-center">
              <Shield className="w-16 h-16 text-blue-600" strokeWidth={2} />
            </div>
            {/* Rotating Ring */}
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="w-28 h-28 border-4 border-transparent border-t-pink-500 border-r-purple-500 rounded-full animate-spin"></div>
            </div>
          </div>
        </div>

        {/* Title */}
        <h1 className="text-4xl sm:text-5xl font-extrabold bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent mb-4">
          {title}
        </h1>

        {/* Subtitle */}
        <p className="text-lg text-slate-600 mb-12 font-medium">
          {subtitle}
        </p>

        {/* Progress Steps */}
        <div className="space-y-4 mb-12">
          {steps.map((step, index) => (
            <div key={index} className="flex items-center justify-center gap-4">
              <div className={`w-3 h-3 rounded-full transition-all duration-500 ${
                step.completed 
                  ? 'bg-emerald-500 shadow-lg shadow-emerald-500/50' 
                  : step.active 
                  ? 'bg-blue-500 animate-pulse shadow-lg shadow-blue-500/50' 
                  : 'bg-slate-300'
              }`}></div>
              <span className={`text-sm font-medium transition-colors duration-500 ${
                step.completed 
                  ? 'text-emerald-600' 
                  : step.active 
                  ? 'text-blue-600' 
                  : 'text-slate-400'
              }`}>
                {step.label}
              </span>
            </div>
          ))}
        </div>

        {/* Rotating Security Tips - Replaces static best practice */}
        <div className="mb-4">
          <SecurityTips rotationInterval={rotationInterval} />
        </div>
      </div>
    </div>
  );
};

export default LoadingScreen;

