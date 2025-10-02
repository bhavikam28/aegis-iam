import React, { useState } from 'react';
import Sidebar from './Sidebar';
import GeneratePolicy from '../Pages/GeneratePolicy';
import ValidatePolicy from '../Pages/ValidatePolicy';
import AnalyzeHistory from '../Pages/AnalyzeHistory';

const Dashboard: React.FC<{ onReturnHome: () => void }> = ({ onReturnHome }) => {
  const [activeSection, setActiveSection] = useState('generate');

  const renderActiveSection = () => {
    switch (activeSection) {
      case 'generate':
        return <GeneratePolicy />;
      case 'validate':
        return <ValidatePolicy />;
      case 'analyze':
        return <AnalyzeHistory />;
      default:
        return <GeneratePolicy />;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex">
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