import React from 'react';
import { AlertCircle, Github, Download } from 'lucide-react';

/**
 * Banner component to inform users that full functionality requires local installation
 * Shows only on production (Vercel) deployment, not on localhost
 */
const LocalOnlyBanner: React.FC = () => {
  // Check if running on localhost
  const isLocalhost = window.location.hostname === 'localhost' || 
                     window.location.hostname === '127.0.0.1';

  // Don't show banner on localhost
  if (isLocalhost) {
    return null;
  }

  return (
    <div className="relative z-50 bg-gradient-to-r from-amber-500 via-orange-500 to-red-500 text-white shadow-lg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3">
        <div className="flex items-center justify-between flex-wrap gap-3">
          {/* Left side - Warning message */}
          <div className="flex items-center gap-3 flex-1 min-w-0">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold">
                Demo Mode
              </p>
              <p className="text-xs opacity-90">
                For full functionality and maximum security, run Aegis IAM locally. Your AWS credentials stay on your machine.
              </p>
            </div>
          </div>

          {/* Right side - Action buttons */}
          <div className="flex items-center gap-2">
            <a
              href="https://github.com/bhavikam28/aegis-iam#-run-locally-recommended-for-full-functionality"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-4 py-2 bg-white text-orange-600 rounded-lg text-sm font-semibold hover:bg-orange-50 transition-colors shadow-md"
            >
              <Download className="w-4 h-4" />
              <span className="hidden sm:inline">Setup Guide</span>
              <span className="sm:hidden">Setup</span>
            </a>
            <a
              href="https://github.com/bhavikam28/aegis-iam"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-4 py-2 bg-white/10 backdrop-blur-sm text-white rounded-lg text-sm font-semibold hover:bg-white/20 transition-colors border border-white/20"
            >
              <Github className="w-4 h-4" />
              <span className="hidden sm:inline">GitHub</span>
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LocalOnlyBanner;

