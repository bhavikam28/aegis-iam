import React, { useState, useEffect } from 'react';
import LandingPage from './components/Layout/LandingPage';
import AWSConfigModal from './components/Modals/AWSConfigModal';
import { AWSCredentials } from './utils/awsCredentials';

function App() {
  // App-level credential state (shared across all pages)
  // SECURITY: Stored only in React state (memory), never persisted
  const [awsCredentials, setAwsCredentials] = useState<AWSCredentials | null>(null);
  const [showCredentialsModal, setShowCredentialsModal] = useState(false);
  const [hasEnteredApp, setHasEnteredApp] = useState(false);
  const [demoMode, setDemoMode] = useState(false);

  // Show credentials modal when user first enters the app (after landing page)
  // BUT NOT if they're in demo mode
  useEffect(() => {
    if (hasEnteredApp && !awsCredentials && !demoMode) {
      // Small delay to ensure Dashboard renders first on mobile
      const timer = setTimeout(() => {
        setShowCredentialsModal(true);
      }, 150);
      return () => clearTimeout(timer);
    }
  }, [hasEnteredApp, awsCredentials, demoMode]);

  return (
    <div className="App">
      <LandingPage 
        awsCredentials={awsCredentials}
        onCredentialsChange={setAwsCredentials}
        onOpenCredentialsModal={() => setShowCredentialsModal(true)}
        onEnterApp={(isDemo?: boolean) => {
          setDemoMode(isDemo ?? false);
          setHasEnteredApp(true);
        }}
      />
      
      {/* App-level AWS Credentials Modal */}
      <AWSConfigModal
        isOpen={showCredentialsModal && !demoMode}
        onClose={() => setShowCredentialsModal(false)}
        onSave={(credentials) => {
          setAwsCredentials(credentials);
          setShowCredentialsModal(false);
        }}
        currentCredentials={awsCredentials}
      />
    </div>
  );
}

export default App;