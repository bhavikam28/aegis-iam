import React, { useState, useEffect } from 'react';
import { Shield, Search, Scan, Menu, X, Home } from 'lucide-react';
import PremiumLogo from '../UI/PremiumLogo';

interface TopNavbarProps {
  activeSection: string;
  onSectionChange: (section: string) => void;
  onReturnHome: () => void;
}

const TopNavbar: React.FC<TopNavbarProps> = ({ activeSection, onSectionChange, onReturnHome }) => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 10);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const sections = [
    {
      id: 'generate',
      title: 'Generate Policy',
      icon: Shield,
    },
    {
      id: 'validate',
      title: 'Validate Policy',
      icon: Search,
    },
    {
      id: 'audit',
      title: 'Audit Account',
      icon: Scan,
    }
  ];

  const handleSectionChange = (sectionId: string) => {
    onSectionChange(sectionId);
    setIsMobileMenuOpen(false);
  };

  return (
    <>
      {/* Premium Top Navigation Bar */}
      <nav className={`fixed top-0 left-0 right-0 z-50 transition-all duration-500 ${
        isScrolled 
          ? 'bg-white/98 backdrop-blur-2xl shadow-xl border-b border-slate-200/60' 
          : 'bg-white/90 backdrop-blur-xl border-b border-slate-200/40'
      }`}>
        <div className="w-full">
          <div className="flex items-center justify-between h-20 sm:h-24 px-4 sm:px-6 lg:px-8">
            {/* Premium Logo & Brand - Left */}
            <button
              onClick={onReturnHome}
              className="flex items-center space-x-3 sm:space-x-4 group flex-shrink-0 hover:opacity-90 transition-opacity"
            >
              {/* Simple Shield Logo */}
              <PremiumLogo size={56} className="w-14 h-14 sm:w-16 sm:h-16 lg:w-20 lg:h-20 group-hover:scale-105 transition-transform duration-300 flex-shrink-0" />
              
              {/* Brand Name & Tagline - Exact match to LandingPage */}
              <div className="flex flex-col items-start">
                <h1 className="text-xl sm:text-2xl lg:text-3xl font-bold bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent leading-tight tracking-tight">
                  Aegis IAM
                </h1>
                <p className="text-xs sm:text-sm font-semibold text-slate-600 tracking-wide">
                  Enterprise IAM Security Platform
                </p>
              </div>
            </button>

            {/* Desktop Navigation - Center */}
            <div className="hidden lg:flex items-center space-x-1 flex-1 justify-center max-w-2xl mx-auto">
              {sections.map((section) => {
                const Icon = section.icon;
                const isActive = activeSection === section.id;
                
                return (
                  <button
                    key={section.id}
                    onClick={() => handleSectionChange(section.id)}
                    className={`
                      relative px-6 py-3 rounded-xl font-bold text-sm
                      transition-all duration-300 flex items-center space-x-2.5 group
                      ${isActive
                        ? 'bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 text-white shadow-2xl shadow-purple-500/40 scale-105'
                        : 'text-slate-700 hover:text-slate-900 hover:bg-gradient-to-r hover:from-blue-50/80 hover:via-purple-50/80 hover:to-pink-50/80'
                      }
                    `}
                  >
                    {isActive && (
                      <div className="absolute inset-0 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 rounded-xl blur-md opacity-50 -z-10"></div>
                    )}
                    <Icon className={`w-5 h-5 ${isActive ? 'text-white' : 'text-slate-600 group-hover:text-purple-600'} transition-colors`} />
                    <span className="font-semibold">{section.title}</span>
                  </button>
                );
              })}
            </div>

            {/* Right Side Actions */}
            <div className="flex items-center space-x-2 sm:space-x-3 -mr-4 sm:-mr-6 lg:-mr-8">
              {/* Home Button - Premium Styled */}
              <button
                onClick={onReturnHome}
                className="group relative p-3 sm:p-3.5 bg-gradient-to-br from-slate-50 to-white border-2 border-slate-200 rounded-xl text-slate-700 hover:text-slate-900 hover:border-blue-300 hover:shadow-lg transition-all duration-300 hover:scale-110"
                aria-label="Return to home"
              >
                <Home className="w-5 h-5 sm:w-6 sm:h-6 group-hover:text-blue-600 transition-colors" />
              </button>

              {/* Mobile Menu Button */}
              <button
                onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                className="lg:hidden p-3 sm:p-3.5 bg-gradient-to-br from-slate-50 to-white border-2 border-slate-200 rounded-xl text-slate-700 hover:text-slate-900 hover:border-blue-300 hover:shadow-lg transition-all duration-300"
                aria-label="Toggle menu"
              >
                {isMobileMenuOpen ? (
                  <X className="w-5 h-5 sm:w-6 sm:h-6" />
                ) : (
                  <Menu className="w-5 h-5 sm:w-6 sm:h-6" />
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Premium Mobile Menu */}
        {isMobileMenuOpen && (
          <div className="lg:hidden border-t border-slate-200/60 bg-white/98 backdrop-blur-2xl animate-fadeIn shadow-xl">
            <div className="px-4 py-6 space-y-2">
              {sections.map((section) => {
                const Icon = section.icon;
                const isActive = activeSection === section.id;
                
                return (
                  <button
                    key={section.id}
                    onClick={() => handleSectionChange(section.id)}
                    className={`
                      w-full px-5 py-4 rounded-xl font-bold text-base
                      transition-all duration-300 flex items-center space-x-3 group
                      ${isActive
                        ? 'bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 text-white shadow-2xl shadow-purple-500/40'
                        : 'text-slate-700 hover:text-slate-900 hover:bg-gradient-to-r hover:from-blue-50/80 hover:via-purple-50/80 hover:to-pink-50/80 border-2 border-slate-200'
                      }
                    `}
                  >
                    {isActive && (
                      <div className="absolute inset-0 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 rounded-xl blur-md opacity-50 -z-10"></div>
                    )}
                    <Icon className={`w-6 h-6 ${isActive ? 'text-white' : 'text-slate-600 group-hover:text-purple-600'} transition-colors`} />
                    <span className="font-semibold">{section.title}</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </nav>

      {/* Spacer to prevent content from going under fixed navbar */}
      <div className="h-20 sm:h-24"></div>
    </>
  );
};

export default TopNavbar;
