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
          />
        );
      case 'validate':
        return (
          <ValidatePolicy 
            awsCredentials={awsCredentials}
            onOpenCredentialsModal={onOpenCredentialsModal}
          />
        );
      case 'audit':
        return (
          <AuditAccount 
            awsCredentials={awsCredentials}
            onOpenCredentialsModal={onOpenCredentialsModal}
          />
        );
      case 'cicd':
        return <CICDIntegration />; // CI/CD doesn't need credentials
      default:
        return (
          <GeneratePolicy 
            awsCredentials={awsCredentials}
            onOpenCredentialsModal={onOpenCredentialsModal}
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
      />
        <main className="flex-1 overflow-auto">
          {renderActiveSection()}
        </main>
    </div>
  );
};

export default Dashboard;