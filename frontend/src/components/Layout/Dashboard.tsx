import React, { useState } from 'react';
import Sidebar from './Sidebar';
import GeneratePolicy from '../Pages/GeneratePolicy';
import ValidatePolicy from '../Pages/ValidatePolicy';
import AuditAccount from '../Pages/AuditAccount';

const Dashboard: React.FC<{ onReturnHome: () => void }> = ({ onReturnHome }) => {
  const [activeSection, setActiveSection] = useState('generate');

  const renderActiveSection = () => {
    switch (activeSection) {
      case 'generate':
        return <GeneratePolicy />;
      case 'validate':
        return <ValidatePolicy />;
      case 'audit':
        return <AuditAccount />;
      default:
        return <GeneratePolicy />;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900 flex">
      <Sidebar 
        activeSection={activeSection} 
        onSectionChange={setActiveSection}
        onReturnHome={onReturnHome}
      />
      <div className="flex-1 flex flex-col overflow-hidden">
        <main className="flex-1 overflow-auto">
          {renderActiveSection()}
        </main>
      </div>
    </div>
  );
};

export default Dashboard;