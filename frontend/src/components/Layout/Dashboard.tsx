import React, { useState } from 'react';
import Sidebar from './Sidebar';
import GeneratePolicy from '../Pages/GeneratePolicy';
import ValidatePolicy from '../Pages/ValidatePolicy';
import AnalyzeHistory from '../Pages/AnalyzeHistory';

const Dashboard: React.FC = () => {
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
    <div className="min-h-screen bg-slate-950 flex">
      <Sidebar 
        activeSection={activeSection} 
        onSectionChange={setActiveSection} 
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