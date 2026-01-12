import React, { useState, useEffect } from 'react';
import LandingPage from './components/Layout/LandingPage';
import AWSSetupWizard from './components/Modals/AWSSetupWizard';
import LocalOnlyBanner from './components/Common/LocalOnlyBanner';
import { AWSCredentials, loadCredentialsFromSession, saveCredentialsToSession, clearCredentialsFromSession } from './utils/awsCredentials';

function App() {
  // App-level credential state (shared across all pages)
  // Load credentials from sessionStorage on mount (persists across page refreshes)
  const [awsCredentials, setAwsCredentials] = useState<AWSCredentials | null>(() => {
    // Load from sessionStorage on initial mount
    return loadCredentialsFromSession();
  });
  const [showSetupWizard, setShowSetupWizard] = useState(false);
  const [hasEnteredApp, setHasEnteredApp] = useState(false);
  const [demoMode, setDemoMode] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Save credentials to sessionStorage whenever they change
  useEffect(() => {
    if (awsCredentials) {
      saveCredentialsToSession(awsCredentials);
    } else {
      // Clear from sessionStorage if credentials are cleared
      clearCredentialsFromSession();
    }
  }, [awsCredentials]);

  // Error boundary for production
  useEffect(() => {
    const handleError = (event: ErrorEvent) => {
      console.error('Global error caught:', event.error);
      setError(event.error);
    };
    window.addEventListener('error', handleError);
    return () => window.removeEventListener('error', handleError);
  }, []);

  // Show setup wizard when user first enters the app (after landing page)
  // BUT NOT if they're in demo mode
  useEffect(() => {
    if (hasEnteredApp && !awsCredentials && !demoMode) {
      // Small delay to ensure Dashboard renders first on mobile
      const timer = setTimeout(() => {
        setShowSetupWizard(true); // Go directly to CLI-based wizard
      }, 150);
      return () => clearTimeout(timer);
    }
  }, [hasEnteredApp, awsCredentials, demoMode]);

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-white to-blue-50/30 p-4">
        <div className="bg-white rounded-2xl shadow-xl border-2 border-red-200 p-8 max-w-md">
          <h2 className="text-2xl font-bold text-red-600 mb-4">Error Loading Application</h2>
          <p className="text-slate-700 mb-4">{error.message}</p>
          <button
            onClick={() => window.location.reload()}
            className="px-6 py-3 bg-blue-600 text-white rounded-xl font-semibold hover:bg-blue-700 transition-colors"
          >
            Reload Page
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="App">
      <LandingPage 
        awsCredentials={awsCredentials}
        onCredentialsChange={setAwsCredentials}
        onOpenCredentialsModal={() => setShowSetupWizard(true)}
        onEnterApp={(isDemo?: boolean) => {
          setDemoMode(isDemo ?? false);
          setHasEnteredApp(true);
        }}
      />

      {/* AWS Setup Wizard */}
      <AWSSetupWizard
        isOpen={showSetupWizard}
        onClose={() => setShowSetupWizard(false)}
        onComplete={(credentials) => {
          setAwsCredentials(credentials);
          setShowSetupWizard(false);
        }}
      />
    </div>
  );
}

export default App;