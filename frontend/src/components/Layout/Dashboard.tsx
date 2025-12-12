import React, { useState } from 'react';
import TopNavbar from './TopNavbar';
import GeneratePolicy from '../Pages/GeneratePolicy';
import ValidatePolicy from '../Pages/ValidatePolicy';
import AuditAccount from '../Pages/AuditAccount';
import CICDIntegration from '../Pages/CICDIntegration';
import { AWSCredentials } from '../../utils/awsCredentials';

interface DashboardProps {
  onReturnHome: () => void;
  awsCredentials: AWSCredentials | null;
  onCredentialsChange: (credentials: AWSCredentials | null) => void;
  onOpenCredentialsModal: () => void;
}

const Dashboard: React.FC<DashboardProps> = ({ 
  onReturnHome, 
  awsCredentials, 
  onCredentialsChange,
  onOpenCredentialsModal 
}) => {
  const [activeSection, setActiveSection] = useState('generate');

  const renderActiveSection = () => {
    switch (activeSection) {
      case 'generate':
        return (
          <GeneratePolicy 
            awsCredentials={awsCredentials}
            onOpenCredentialsModal={onOpenCredentialsModal}
            demoMode={demoMode}
          />
        );
      case 'validate':
        return (
          <ValidatePolicy 
            awsCredentials={awsCredentials}
            onOpenCredentialsModal={onOpenCredentialsModal}
            demoMode={demoMode}
          />
        );
      case 'audit':
        return (
          <AuditAccount 
            awsCredentials={awsCredentials}
            onOpenCredentialsModal={onOpenCredentialsModal}
            demoMode={demoMode}
          />
        );
      case 'cicd':
        return <CICDIntegration demoMode={demoMode} />; // CI/CD doesn't need AWS credentials (uses GitHub App)
      default:
        return (
          <GeneratePolicy 
            awsCredentials={awsCredentials}
            onOpenCredentialsModal={onOpenCredentialsModal}
            demoMode={demoMode}
          />
        );
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-slate-50 via-white to-blue-50/30">
      <TopNavbar 
        activeSection={activeSection} 
        onSectionChange={setActiveSection}
        onReturnHome={onReturnHome}
        awsCredentials={activeSection !== 'cicd' ? awsCredentials : null} // Hide AWS button on CI/CD page
        onOpenCredentialsModal={activeSection !== 'cicd' ? onOpenCredentialsModal : undefined} // Hide AWS button on CI/CD page
      />
        <main className="flex-1 overflow-auto">
          {renderActiveSection()}
        </main>
    </div>
  );
};

export default Dashboard;