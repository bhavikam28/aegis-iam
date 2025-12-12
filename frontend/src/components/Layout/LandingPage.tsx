import React, { useState, useEffect, useRef } from 'react';
import { Shield, Zap, Lock, ChevronRight, CheckCircle, Search, BarChart3, Code, Sparkles, ArrowRight, Star, TrendingUp, Users, Globe, Brain, Cpu, Activity, Target, Award, Rocket, Layers, FileCheck, Play, XCircle, AlertTriangle, Database, Eye, Settings, Cloud, Server, Key, Fingerprint, Network, ShieldCheck, Bot, GitBranch } from 'lucide-react';
import Dashboard from './Dashboard';
import PremiumLogo from '../UI/PremiumLogo';
import { AWSCredentials } from '../../utils/awsCredentials';

interface LandingPageProps {
  awsCredentials: AWSCredentials | null;
  onCredentialsChange: (credentials: AWSCredentials | null) => void;
  onOpenCredentialsModal: () => void;
  onEnterApp: () => void;
}

const LandingPage: React.FC<LandingPageProps> = ({ 
  awsCredentials, 
  onCredentialsChange, 
  onOpenCredentialsModal,
  onEnterApp 
}) => {
  const [showDashboard, setShowDashboard] = useState(false);
  
  const handleGetStarted = () => {
    setShowDashboard(true);
    onEnterApp(); // Trigger credential modal if not set
  };
  const [scrollY, setScrollY] = useState(0);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const heroRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleScroll = () => setScrollY(window.scrollY);
    const handleMouseMove = (e: MouseEvent) => {
      setMousePosition({ x: e.clientX, y: e.clientY });
    };

    window.addEventListener('scroll', handleScroll);
    window.addEventListener('mousemove', handleMouseMove);
    return () => {
      window.removeEventListener('scroll', handleScroll);
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, []);

  if (showDashboard) {
    return (
      <Dashboard 
        onReturnHome={() => setShowDashboard(false)}
        awsCredentials={awsCredentials}
        onCredentialsChange={onCredentialsChange}
        onOpenCredentialsModal={onOpenCredentialsModal}
      />
    );
  }

  return (
    <div className="min-h-screen relative overflow-hidden bg-gradient-to-br from-slate-50 via-white to-blue-50/30">
      {/* Premium Animated Background - Light Theme with Glowing Gradients */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
        {/* Primary gradient orbs with enhanced glow */}
        <div 
          className="absolute top-0 right-0 w-[900px] h-[900px] bg-gradient-to-br from-blue-500/12 via-purple-500/10 to-pink-500/8 rounded-full blur-3xl animate-pulse transition-transform duration-1000"
          style={{ 
            transform: `translate(${mousePosition.x * 0.02}px, ${mousePosition.y * 0.02}px)`,
          }}
        ></div>
        <div 
          className="absolute bottom-0 left-0 w-[800px] h-[800px] bg-gradient-to-tr from-purple-500/10 via-pink-500/8 to-orange-500/6 rounded-full blur-3xl animate-pulse transition-transform duration-1000"
          style={{ 
            animationDelay: '2s',
            transform: `translate(${-mousePosition.x * 0.015}px, ${-mousePosition.y * 0.015}px)`,
          }}
        ></div>
        <div 
          className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] bg-gradient-to-br from-cyan-500/8 via-blue-500/6 to-purple-500/5 rounded-full blur-3xl animate-pulse transition-transform duration-1000"
          style={{
            animationDelay: '4s',
            transform: `translate(${-mousePosition.x * 0.01}px, ${-mousePosition.y * 0.01}px)`,
          }}
        ></div>
        
        {/* Subtle diagonal lines for depth */}
        <div className="absolute inset-0 opacity-5">
          <div className="absolute top-0 left-0 w-full h-full" style={{
            backgroundImage: `linear-gradient(45deg, transparent 30%, rgba(99, 102, 241, 0.1) 50%, transparent 70%)`,
            backgroundSize: '100px 100px'
        }}></div>
        </div>
      </div>

      {/* Header/Navigation */}
      <div className="relative z-20 border-b border-slate-200/50 bg-white/80 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3 sm:space-x-4 group">
              <PremiumLogo size={56} className="w-12 h-12 sm:w-14 sm:h-14 lg:w-16 lg:h-16 group-hover:scale-105 transition-transform duration-300 flex-shrink-0" />
              <div className="flex flex-col items-start">
                <h1 className="text-xl sm:text-2xl lg:text-3xl font-bold bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent leading-tight tracking-tight">
                  Aegis IAM
                </h1>
                <p className="text-xs sm:text-sm font-semibold text-slate-600 tracking-wide">
                  Enterprise IAM Security Platform
                </p>
              </div>
            </div>
            <button
              onClick={handleGetStarted}
              className="group relative overflow-hidden bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white px-6 py-3 rounded-xl font-bold text-sm sm:text-base shadow-lg hover:shadow-xl transition-all duration-300 flex items-center space-x-2 transform hover:scale-105"
            >
              <span className="relative z-10">Get Started</span>
              <ArrowRight className="w-4 h-4 sm:w-5 sm:h-5 relative z-10 group-hover:translate-x-1 transition-transform" />
            </button>
          </div>
          </div>
        </div>

      <div className="relative z-10">
        {/* Hero Section - Premium Light Theme with Dashboard Mockup */}
        <section className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-16 sm:pt-20 lg:pt-24 pb-12 sm:pb-16">
          <div className="text-center mb-12 sm:mb-16 animate-fadeIn">
            {/* Category Badge */}
            <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-pink-500/10 border border-blue-200/50 rounded-full px-4 sm:px-6 py-2 mb-6 sm:mb-8 backdrop-blur-sm">
              <Shield className="w-4 h-4 text-blue-600" />
              <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent text-xs sm:text-sm font-semibold uppercase tracking-wide">
                AI-Powered IAM Security Platform
              </span>
            </div>

            {/* Main Headline */}
            <h2 className="text-5xl sm:text-6xl lg:text-7xl xl:text-8xl font-extrabold mb-6 sm:mb-8 leading-tight tracking-tight">
              <span className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
                Securing AWS IAM
              </span>
              <br />
              <span
                className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent"
                style={{
                  backgroundPosition: `${mousePosition.x * 0.01}% ${mousePosition.y * 0.01}%`,
                }}
              >
                Made Simple
              </span>
            </h2>

            {/* Sub-headline */}
            <p className="text-lg sm:text-xl lg:text-2xl text-slate-600 max-w-3xl mx-auto mb-10 sm:mb-12 leading-relaxed font-medium">
              Prioritize and remediate IAM risks in your AWS account faster with the Aegis IAM Security Platform. 
              Generate secure policies, validate compliance, and autonomously audit your entire infrastructure—all powered by agentic AI.
            </p>
 
            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-12 sm:mb-16">
              <button
                onClick={handleGetStarted}
                className="group relative overflow-hidden bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white px-8 sm:px-10 lg:px-12 py-4 sm:py-5 rounded-2xl font-bold text-base sm:text-lg lg:text-xl shadow-xl hover:shadow-2xl transition-all duration-300 flex items-center space-x-3 transform hover:scale-105 touch-manipulation"
                style={{ minHeight: '44px' }}
              >
                <span className="relative z-10">Try It Now</span>
                <ArrowRight className="w-5 h-5 sm:w-6 sm:h-6 relative z-10 group-hover:translate-x-1 transition-transform" />
                <div className="absolute inset-0 bg-white/10 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-700"></div>
              </button>

              <button
                onClick={handleGetStarted}
                className="group px-8 sm:px-10 py-4 sm:py-5 bg-white/90 backdrop-blur-sm border-2 border-slate-200 rounded-2xl text-slate-700 hover:text-slate-900 font-bold text-base sm:text-lg hover:border-blue-300 hover:shadow-lg transition-all inline-flex items-center space-x-2 hover:scale-105"
              >
                <Play className="w-5 h-5 sm:w-6 sm:h-6" />
                <span>Demo Mode</span>
              </button>

              <a
                href="https://github.com/bhavikam28/aegis-iam"
                target="_blank"
                rel="noopener noreferrer"
                className="group px-8 sm:px-10 py-4 sm:py-5 bg-white/80 backdrop-blur-sm border-2 border-slate-200 rounded-2xl text-slate-700 hover:text-slate-900 font-bold text-base sm:text-lg hover:border-blue-300 hover:shadow-lg transition-all inline-flex items-center space-x-2 hover:scale-105"
              >
                <span>View on GitHub</span>
                <ChevronRight className="w-5 h-5 sm:w-6 sm:h-6 group-hover:translate-x-1 transition-transform" />
              </a>
            </div>
        </div>

          {/* Dashboard Mockup - Premium Light Theme - Matches Actual Feature Pages */}
          <div className="relative mb-20 animate-fadeIn" style={{ animationDelay: '0.2s' }}>
            <div className="absolute inset-0 bg-gradient-to-r from-blue-500/5 via-purple-500/5 to-pink-500/5 rounded-3xl blur-3xl"></div>
            <div className="relative bg-white/90 backdrop-blur-xl border-2 border-slate-200/50 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-2xl hover:shadow-3xl transition-all duration-500 overflow-hidden">
              {/* Security Score Box - Matching Audit Account Design */}
              <div className="mb-8">
                <div className="relative bg-white/90 backdrop-blur-2xl border-2 border-blue-200/60 rounded-3xl p-6 shadow-xl overflow-hidden">
                  <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500"></div>
                  <div className="flex items-center justify-between gap-6 mb-4">
                    <div className="text-slate-700 text-xs font-black uppercase tracking-widest">Security Score</div>
                    <div className="flex items-baseline gap-3 flex-1 justify-center">
                      <span 
                        className="text-6xl font-bold leading-none"
                        style={{
                          background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
                          WebkitBackgroundClip: 'text',
                          WebkitTextFillColor: 'transparent',
                          backgroundClip: 'text',
                        }}
                      >
                        78
                      </span>
                      <span className="text-2xl text-slate-400 font-semibold">/100</span>
                    </div>
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold bg-blue-100 text-blue-800 shadow-md">
                      <span>Grade B</span>
                      <span className="opacity-50">•</span>
                      <span className="text-xs">Good</span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between gap-6 pt-4 border-t-2 border-slate-200/60">
                    <div className="text-slate-600 text-xs font-semibold uppercase">Security Level</div>
                    <div className="flex-1 max-w-md">
                      <div className="w-full bg-slate-100 rounded-full h-2.5 overflow-hidden">
                        <div 
                          className="h-full bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 rounded-full"
                          style={{ width: '78%' }}
                        ></div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 text-xs">
                      <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
                      <span className="text-red-600 font-black text-lg">22</span>
                      <span className="text-slate-400">/100</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* What We Audited Cards - Matching Audit Account Design */}
              <div className="grid grid-cols-3 gap-4 mb-6">
                {[
                  { icon: Users, label: 'IAM Roles', value: '5', gradient: 'from-blue-500 to-cyan-500', desc: 'Analyzed' },
                  { icon: Activity, label: 'CloudTrail', value: '50', gradient: 'from-pink-500 to-orange-500', desc: 'Events' },
                  { icon: Shield, label: 'SCPs', value: '3', gradient: 'from-amber-500 to-yellow-500', desc: 'Checked' },
                ].map((item, idx) => (
                  <div 
                    key={idx}
                    className="bg-white/80 backdrop-blur-xl border-2 border-slate-200/50 rounded-2xl p-5 hover:shadow-xl transition-all"
                  >
                    <div className="flex items-center justify-between mb-3">
                      <div className={`w-10 h-10 bg-gradient-to-br ${item.gradient} rounded-xl flex items-center justify-center`}>
                        <item.icon className="w-5 h-5 text-white" />
                      </div>
                      <div className="text-3xl font-black text-slate-900">{item.value}</div>
                    </div>
                    <div className="text-slate-900 font-bold text-sm mb-1">{item.label}</div>
                    <div className="text-slate-500 text-xs font-medium">{item.desc}</div>
                  </div>
                ))}
              </div>

              {/* Policy Cards - Matching Generate Policy Design */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                <div className="bg-gradient-to-br from-white to-slate-50/50 border-2 border-blue-200/50 rounded-2xl p-5">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-2">
                      <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-500 rounded-lg flex items-center justify-center">
                        <Shield className="w-4 h-4 text-white" />
                      </div>
                      <span className="text-slate-900 font-bold text-sm">Permissions Policy</span>
                    </div>
                    <span className="px-2 py-1 bg-blue-500/10 text-blue-700 rounded text-xs font-semibold">Score: 85</span>
                  </div>
                  <div className="text-xs text-slate-600 font-medium">Least-privilege enforced</div>
                </div>
                <div className="bg-gradient-to-br from-white to-slate-50/50 border-2 border-purple-200/50 rounded-2xl p-5">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-2">
                      <div className="w-8 h-8 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center">
                        <Lock className="w-4 h-4 text-white" />
                      </div>
                      <span className="text-slate-900 font-bold text-sm">Trust Policy</span>
                    </div>
                    <span className="px-2 py-1 bg-purple-500/10 text-purple-700 rounded text-xs font-semibold">Score: 90</span>
                  </div>
                  <div className="text-xs text-slate-600 font-medium">Principal restrictions applied</div>
                </div>
              </div>

              {/* Findings List - Matching Validate Policy Design */}
              <div className="space-y-3">
                <h4 className="text-slate-900 font-bold text-sm mb-3">Security Findings</h4>
                {[
                  { title: 'Over-privileged Lambda Role', severity: 'Critical', score: 8.5 },
                  { title: 'Public S3 Bucket Access', severity: 'High', score: 7.2 },
                  { title: 'Missing MFA Enforcement', severity: 'Medium', score: 5.8 },
                ].map((item, idx) => (
                  <div key={idx} className="bg-white/80 backdrop-blur-xl border-2 border-slate-200/50 rounded-xl p-4 hover:shadow-lg transition-all">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-slate-900 font-bold text-sm">{item.title}</span>
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${
                        item.severity === 'Critical' ? 'bg-red-500/10 text-red-700' :
                        item.severity === 'High' ? 'bg-orange-500/10 text-orange-700' :
                        'bg-yellow-500/10 text-yellow-700'
                      }`}>
                        {item.severity}
                      </span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="flex-1 bg-slate-100 rounded-full h-1.5">
                        <div 
                          className="bg-gradient-to-r from-blue-500 to-purple-500 h-1.5 rounded-full"
                          style={{ width: `${item.score * 10}%` }}
                        ></div>
                      </div>
                      <span className="text-xs font-bold text-slate-600">{item.score}/10</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Trust Signals Section - Seamlessly Integrated */}
        <section className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 sm:py-20">
          <div className="text-center mb-12">
            <h3 className="text-3xl sm:text-4xl font-extrabold mb-4">
              <span className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
                Trusted by Developers
              </span>
            </h3>
            <p className="text-lg text-slate-600 font-medium max-w-2xl mx-auto">
              Built with security, privacy, and transparency at the core
            </p>
          </div>

          {/* Premium Trust Cards - Horizontal Layout */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
            {/* Zero Cost */}
            <div className="group relative bg-white/90 backdrop-blur-xl border-2 border-slate-200/50 rounded-2xl p-6 hover:shadow-2xl hover:-translate-y-1 transition-all duration-300">
              <div className="flex items-start space-x-4">
                <div className="w-14 h-14 bg-gradient-to-br from-emerald-500 to-green-500 rounded-xl flex items-center justify-center shadow-lg flex-shrink-0 group-hover:scale-110 transition-transform">
                  <span className="text-2xl">💰</span>
                </div>
                <div className="flex-1">
                  <h4 className="text-lg font-bold text-slate-900 mb-2">Zero Cost for You</h4>
                  <p className="text-sm text-slate-600 font-medium leading-relaxed">
                    Use your AWS credentials. All Bedrock/AWS costs go to <span className="font-bold text-emerald-600">your AWS account</span>, not ours.
                  </p>
                </div>
              </div>
            </div>

            {/* Privacy First */}
            <div className="group relative bg-white/90 backdrop-blur-xl border-2 border-slate-200/50 rounded-2xl p-6 hover:shadow-2xl hover:-translate-y-1 transition-all duration-300">
              <div className="flex items-start space-x-4">
                <div className="w-14 h-14 bg-gradient-to-br from-blue-500 to-purple-500 rounded-xl flex items-center justify-center shadow-lg flex-shrink-0 group-hover:scale-110 transition-transform">
                  <Lock className="w-7 h-7 text-white" />
                </div>
                <div className="flex-1">
                  <h4 className="text-lg font-bold text-slate-900 mb-2">Privacy First</h4>
                  <p className="text-sm text-slate-600 font-medium leading-relaxed">
                    <span className="font-bold text-blue-600">Zero storage.</span> Your credentials live only in memory during your session.
                  </p>
                </div>
              </div>
            </div>

            {/* Open Source */}
            <div className="group relative bg-white/90 backdrop-blur-xl border-2 border-slate-200/50 rounded-2xl p-6 hover:shadow-2xl hover:-translate-y-1 transition-all duration-300">
              <div className="flex items-start space-x-4">
                <div className="w-14 h-14 bg-gradient-to-br from-pink-500 to-orange-500 rounded-xl flex items-center justify-center shadow-lg flex-shrink-0 group-hover:scale-110 transition-transform">
                  <Globe className="w-7 h-7 text-white" />
                </div>
                <div className="flex-1">
                  <h4 className="text-lg font-bold text-slate-900 mb-2">100% Open Source</h4>
                  <p className="text-sm text-slate-600 font-medium leading-relaxed">
                    Fully transparent. Audit our code on <a href="https://github.com/bhavikam28/aegis-iam" target="_blank" rel="noopener noreferrer" className="font-bold text-pink-600 underline hover:text-pink-700">GitHub</a>.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Feature Badges - Compact Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { icon: Brain, label: 'AI-Powered', desc: 'Claude 3.7 Sonnet', gradient: 'from-blue-500 to-purple-500' },
              { icon: ShieldCheck, label: 'Enterprise Ready', desc: 'Multi-Compliance', gradient: 'from-purple-500 to-pink-500' },
              { icon: Activity, label: 'Real-Time', desc: 'Live Analysis', gradient: 'from-pink-500 to-orange-500' },
              { icon: Users, label: 'Community', desc: 'Open Source', gradient: 'from-amber-500 to-yellow-500' },
            ].map((item, idx) => (
              <div key={idx} className="bg-white/90 backdrop-blur-xl border-2 border-slate-200/50 rounded-xl p-4 hover:shadow-xl hover:border-blue-300 transition-all text-center">
                <div className={`w-12 h-12 bg-gradient-to-br ${item.gradient} rounded-xl flex items-center justify-center mx-auto mb-3 shadow-md`}>
                  <item.icon className="w-6 h-6 text-white" />
                </div>
                <div className="text-xs font-bold text-slate-900">{item.label}</div>
                <div className="text-xs text-slate-500 mt-1">{item.desc}</div>
              </div>
            ))}
          </div>
        </section>

        {/* Feature Section 1: Autonomous Account Auditing */}
        <section className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-center">
            {/* Left Content */}
            <div className="animate-fadeIn" style={{ animationDelay: '0.3s' }}>
              <h3 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold mb-6 leading-tight">
                <span className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
                  Autonomous Account
                </span>
                <br />
                <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
                  Auditing with AI
                </span>
              </h3>
              <p className="text-lg sm:text-xl text-slate-600 mb-8 leading-relaxed font-medium">
                Deploy an autonomous AI agent that comprehensively scans your AWS account, analyzing all IAM policies, 
                roles, and permissions. Identifies vulnerabilities, validates compliance, and delivers actionable security insights—all completely hands-free.
              </p>
              <ul className="space-y-4 mb-8">
                {[
                  'Autonomously scan your entire AWS account for IAM vulnerabilities',
                  'Multi-framework compliance validation (PCI DSS, HIPAA, SOX, GDPR, CIS)',
                  'Intelligent risk prioritization with actionable remediation steps',
                ].map((item, idx) => (
                  <li key={idx} className="flex items-start space-x-3">
                    <CheckCircle className="w-6 h-6 text-emerald-500 mt-0.5 flex-shrink-0" />
                    <span className="text-slate-700 font-medium text-base">{item}</span>
              </li>
                ))}
            </ul>
              <div className="flex items-center space-x-4">
                <button
                  onClick={handleGetStarted}
                  className="group bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white px-6 py-3 rounded-xl font-bold shadow-lg hover:shadow-xl transition-all inline-flex items-center space-x-2 transform hover:scale-105"
                >
                  <span>Try It Now</span>
                  <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                </button>
                <a
                  href="https://github.com/bhavikam28/aegis-iam"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group px-6 py-3 bg-white/80 backdrop-blur-sm border-2 border-slate-200 rounded-xl text-slate-700 hover:text-slate-900 font-semibold hover:border-blue-300 hover:shadow-lg transition-all inline-flex items-center space-x-2"
                >
                  <span>View on GitHub</span>
                  <ChevronRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                </a>
              </div>
            </div>

            {/* Right Visual - Audit Findings */}
            <div className="relative animate-fadeIn" style={{ animationDelay: '0.4s' }}>
              <div className="absolute inset-0 bg-gradient-to-r from-blue-500/5 via-purple-500/5 to-pink-500/5 rounded-3xl blur-2xl"></div>
              <div className="relative bg-white/90 backdrop-blur-xl border-2 border-slate-200/50 rounded-3xl p-6 shadow-2xl">
                <div className="space-y-4">
                  {[
                    { title: 'Over-privileged Lambda Role', severity: 'Critical', score: 8.5 },
                    { title: 'Public S3 Bucket Access', severity: 'High', score: 7.2 },
                    { title: 'Missing MFA Enforcement', severity: 'Medium', score: 5.8 },
                    { title: 'Unused IAM Permissions', severity: 'Low', score: 3.2 },
                  ].map((item, idx) => (
                    <div key={idx} className="bg-gradient-to-br from-white to-slate-50/50 border-2 border-slate-200/50 rounded-xl p-4 hover:shadow-lg transition-all">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-slate-900 font-bold text-sm">{item.title}</span>
                        <span className={`px-2 py-1 rounded text-xs font-semibold ${
                          item.severity === 'Critical' ? 'bg-red-500/10 text-red-700' :
                          item.severity === 'High' ? 'bg-orange-500/10 text-orange-700' :
                          item.severity === 'Medium' ? 'bg-yellow-500/10 text-yellow-700' :
                          'bg-green-500/10 text-green-700'
                        }`}>
                          {item.severity}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <div className="flex-1 bg-slate-100 rounded-full h-2">
                          <div 
                            className="bg-gradient-to-r from-blue-500 to-purple-500 h-2 rounded-full"
                            style={{ width: `${item.score * 10}%` }}
                          ></div>
                        </div>
                        <span className="text-xs font-bold text-slate-600">{item.score}/10</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Feature Section 2: Unify cloud security in a single platform */}
        <section className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24 bg-gradient-to-br from-white via-slate-50/30 to-blue-50/20 rounded-3xl my-12">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-center">
            {/* Left Visual - Matching Image 1 */}
            <div className="relative animate-fadeIn" style={{ animationDelay: '0.5s' }}>
              <div className="absolute inset-0 bg-gradient-to-r from-purple-500/5 via-pink-500/5 to-orange-500/5 rounded-3xl blur-2xl"></div>
              <div className="relative bg-white rounded-2xl p-6 shadow-lg">
                <div className="space-y-3">
                  {[
                    { service: 'IAM Policy Generator', status: 'Active', icon: Shield },
                    { service: 'Security Validator', status: 'Active', icon: Search },
                    { service: 'Autonomous Auditor', status: 'Active', icon: Activity },
                    { service: 'Compliance Checker', status: 'Active', icon: CheckCircle },
                  ].map((item, idx) => (
                    <div key={idx} className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-blue-500 rounded-lg flex items-center justify-center">
                          <item.icon className="w-5 h-5 text-white" />
                        </div>
                        <span className="text-slate-900 font-semibold text-sm">{item.service}</span>
                      </div>
                      <span className="px-3 py-1 bg-green-100 text-green-700 rounded-lg text-xs font-semibold">
                        {item.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Right Content */}
            <div className="animate-fadeIn" style={{ animationDelay: '0.6s' }}>
              <h3 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold mb-6 leading-tight">
                <span className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
                  Unify IAM security
                </span>
                <br />
                <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
                  in a single platform
                </span>
              </h3>
              <p className="text-lg sm:text-xl text-slate-600 mb-8 leading-relaxed font-medium">
                Three powerful features in one platform: Generate secure IAM policies from natural language, 
                validate existing policies for security issues, and autonomously audit your entire AWS account—all powered by agentic AI.
              </p>
              <ul className="space-y-4 mb-8">
                {[
                  'Generate IAM policies from plain English with AI-powered natural language processing',
                  'Validate existing policies against security best practices and compliance frameworks',
                  'Autonomously audit your AWS account with intelligent vulnerability detection',
                ].map((item, idx) => (
                  <li key={idx} className="flex items-start space-x-3">
                    <CheckCircle className="w-6 h-6 text-emerald-500 mt-0.5 flex-shrink-0" />
                    <span className="text-slate-700 font-medium text-base">{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>

        {/* Feature Section 3: CI/CD Integration */}
        <section className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24 bg-gradient-to-br from-slate-50/50 via-white to-blue-50/30 rounded-3xl">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-center">
            {/* Left Visual */}
            <div className="relative animate-fadeIn" style={{ animationDelay: '0.5s' }}>
              <div className="absolute inset-0 bg-gradient-to-r from-blue-500/5 via-purple-500/5 to-pink-500/5 rounded-3xl blur-2xl"></div>
              <div className="relative bg-white/90 backdrop-blur-xl border-2 border-slate-200/50 rounded-2xl p-6 shadow-xl">
                {/* GitHub PR Comment Preview */}
                <div className="space-y-4">
                  <div className="flex items-center space-x-3 mb-4">
                    <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-xl flex items-center justify-center">
                      <Bot className="w-5 h-5 text-white" />
                    </div>
                    <div>
                      <div className="text-sm font-bold text-slate-900">aegis-iam bot</div>
                      <div className="text-xs text-slate-500">commented 2 hours ago</div>
                    </div>
                  </div>
                  <div className="bg-slate-50 rounded-xl p-4 border-l-4 border-blue-500">
                    <div className="flex items-center space-x-2 mb-2">
                      <Shield className="w-4 h-4 text-blue-600" />
                      <span className="text-sm font-bold text-slate-900">IAM Policy Security Analysis</span>
                    </div>
                    <p className="text-xs text-slate-600 mb-3">
                      🔒 Security Review Recommended: 2 high and 1 medium severity issues found.
                    </p>
                    <div className="space-y-2">
                      <div className="flex items-center space-x-2 text-xs">
                        <div className="w-2 h-2 rounded-full bg-orange-500"></div>
                        <span className="text-slate-700">Wildcard Permissions Detected</span>
                      </div>
                      <div className="flex items-center space-x-2 text-xs">
                        <div className="w-2 h-2 rounded-full bg-amber-500"></div>
                        <span className="text-slate-700">Unused Permissions Found</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2 text-xs text-slate-500">
                    <CheckCircle className="w-4 h-4 text-emerald-500" />
                    <span>Automatically analyzed on PR #42</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Right Content */}
            <div className="animate-fadeIn" style={{ animationDelay: '0.6s' }}>
              <h3 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold mb-6 leading-tight">
                <span className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
                  CI/CD Integration
                </span>
                <br />
                <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
                  Automated PR Reviews
                </span>
              </h3>
              <p className="text-lg sm:text-xl text-slate-600 mb-8 leading-relaxed font-medium">
                Catch IAM security issues before they're merged. Our GitHub App automatically analyzes IAM policies in pull requests and provides actionable security feedback—zero configuration required.
              </p>
              <ul className="space-y-4 mb-8">
                {[
                  'One-click GitHub App installation—no YAML files or secrets needed',
                  'Automatic analysis on every PR and push to main/master',
                  'CloudTrail usage comparison to detect unused permissions',
                  'Supports Terraform, CloudFormation, CDK, and raw JSON',
                ].map((item, idx) => (
                  <li key={idx} className="flex items-start space-x-3">
                    <CheckCircle className="w-6 h-6 text-emerald-500 mt-0.5 flex-shrink-0" />
                    <span className="text-slate-700 font-medium text-base">{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>

        {/* Feature Section 4: AI-Powered Policy Generation & Validation */}
        <section className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 items-center">
            {/* Left Content */}
            <div className="animate-fadeIn" style={{ animationDelay: '0.7s' }}>
              <h3 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold mb-6 leading-tight">
                <span className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
                  AI-Powered Policy
                </span>
                <br />
                <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
                  Generation & Validation
                </span>
              </h3>
              <p className="text-lg sm:text-xl text-slate-600 mb-8 leading-relaxed font-medium">
                Transform your permission requirements into production-ready IAM policies using natural language. 
                Our AI automatically enforces least-privilege principles and validates policies against security best practices and compliance frameworks.
              </p>
              <ul className="space-y-4 mb-8">
                {[
                  'Generate secure IAM policies from plain English in seconds',
                  'Interactive refinement through conversational AI chatbot',
                  'Automatic security scoring and compliance validation',
                ].map((item, idx) => (
                  <li key={idx} className="flex items-start space-x-3">
                    <CheckCircle className="w-6 h-6 text-emerald-500 mt-0.5 flex-shrink-0" />
                    <span className="text-slate-700 font-medium text-base">{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Right Visual - Policy Cards Matching Generate Policy Feature */}
            <div className="relative animate-fadeIn" style={{ animationDelay: '0.8s' }}>
              <div className="absolute inset-0 bg-gradient-to-r from-pink-500/5 via-orange-500/5 to-amber-500/5 rounded-3xl blur-2xl"></div>
              <div className="relative bg-white rounded-2xl p-6 shadow-lg">
                {/* Policy Cards */}
                <div className="space-y-4">
                  <div className="bg-gradient-to-br from-white to-slate-50/50 border-2 border-blue-200/50 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-500 rounded-lg flex items-center justify-center">
                          <Shield className="w-4 h-4 text-white" />
                        </div>
                        <span className="text-slate-900 font-bold text-sm">Permissions Policy</span>
                      </div>
                      <span className="px-2 py-1 bg-blue-500/10 text-blue-700 rounded text-xs font-semibold">Score: 85</span>
                    </div>
                    <div className="text-xs text-slate-600 font-medium">Least-privilege enforced</div>
                  </div>
                  <div className="bg-gradient-to-br from-white to-slate-50/50 border-2 border-purple-200/50 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <div className="w-8 h-8 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center">
                          <Lock className="w-4 h-4 text-white" />
                        </div>
                        <span className="text-slate-900 font-bold text-sm">Trust Policy</span>
                      </div>
                      <span className="px-2 py-1 bg-purple-500/10 text-purple-700 rounded text-xs font-semibold">Score: 90</span>
                    </div>
                    <div className="text-xs text-slate-600 font-medium">Principal restrictions applied</div>
                  </div>
                  {/* Chatbot Preview */}
                  <div className="bg-slate-50 rounded-xl p-3 border border-slate-200">
                    <div className="flex items-center space-x-2 mb-2">
                      <Bot className="w-4 h-4 text-blue-600" />
                      <span className="text-xs font-semibold text-slate-700">AI Assistant</span>
                    </div>
                    <div className="text-xs text-slate-600 font-medium">Ready to refine your policies</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Explore Aegis IAM Solutions Section */}
        <section className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24">
          <div className="text-center mb-12 sm:mb-16">
            <h2 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold mb-6">
              <span className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
                Explore Aegis IAM
              </span>
              <br />
              <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
                Security Solutions
              </span>
            </h2>
            <p className="text-lg sm:text-xl text-slate-600 max-w-2xl mx-auto font-medium">
              Comprehensive IAM security solutions powered by agentic AI
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              { icon: Shield, title: 'IAM Policy Generation', desc: 'Generate secure IAM policies from plain English using AI-powered natural language processing.' },
              { icon: Search, title: 'Security Policy Validation', desc: 'Validate existing IAM policies against security best practices and compliance frameworks.' },
              { icon: Activity, title: 'Autonomous Account Auditing', desc: 'Automatically scan your entire AWS account for IAM vulnerabilities and compliance issues.' },
              { icon: GitBranch, title: 'CI/CD Integration', desc: 'Automatically analyze IAM policies in pull requests with GitHub App integration—zero configuration.' },
              { icon: CheckCircle, title: 'Multi-Framework Compliance', desc: 'Ensure compliance with PCI DSS, HIPAA, SOX, GDPR, and CIS Benchmarks.' },
              { icon: BarChart3, title: 'CloudTrail Analysis', desc: 'Analyze CloudTrail logs to identify unused permissions and optimize IAM policies.' },
            ].map((solution, idx) => (
              <div 
                key={idx}
                className="group relative bg-white/90 backdrop-blur-xl border-2 border-slate-200/50 rounded-2xl p-6 sm:p-8 shadow-xl hover:shadow-2xl hover:-translate-y-2 transition-all duration-300 cursor-pointer"
              >
                <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-purple-500/5 to-pink-500/5 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
                <div className="relative">
                  <div className="w-14 h-14 bg-gradient-to-br from-blue-500 to-purple-500 rounded-xl flex items-center justify-center mb-4 shadow-lg group-hover:scale-125 group-hover:rotate-6 transition-all duration-300">
                    <solution.icon className="w-7 h-7 text-white" />
                  </div>
                  <h4 className="text-xl font-bold text-slate-900 mb-3 group-hover:text-blue-600 transition-colors">
                    {solution.title}
                  </h4>
                  <p className="text-slate-600 text-sm leading-relaxed font-medium mb-4">
                    {solution.desc}
                  </p>
                  <div className="flex items-center text-blue-600 font-semibold text-sm group-hover:translate-x-2 transition-transform">
                    <span>Learn more</span>
                    <ChevronRight className="w-4 h-4 ml-1" />
                  </div>
                </div>
              </div>
            ))}
        </div>
        </section>

        {/* Final CTA Section */}
        <section className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24 mb-12">
        <div className="relative">
            <div className="absolute inset-0 bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-pink-500/10 rounded-3xl blur-3xl"></div>
            <div className="relative bg-gradient-to-br from-white via-slate-50/50 to-blue-50/30 backdrop-blur-xl border-2 border-slate-200/50 rounded-3xl p-12 sm:p-16 text-center shadow-2xl">
              <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-200/50 rounded-full px-4 py-2 mb-6">
                <Sparkles className="w-4 h-4 text-blue-600" />
                <span className="text-blue-700 text-sm font-semibold">See Aegis IAM in Action</span>
              </div>
              <h3 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold mb-6">
                <span className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
                  Ready to Secure
                </span>
                <br />
                <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
                  Your AWS IAM?
                </span>
              </h3>
              <p className="text-lg sm:text-xl text-slate-600 mb-10 max-w-2xl mx-auto font-medium leading-relaxed">
                Get started with Aegis IAM today. Generate secure policies, validate compliance, 
                and autonomously audit your AWS account—all powered by agentic AI.
              </p>
              <button
                onClick={handleGetStarted}
                className="group relative overflow-hidden bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white px-10 py-5 rounded-2xl font-bold text-lg sm:text-xl shadow-xl hover:shadow-2xl transition-all inline-flex items-center space-x-3 transform hover:scale-105"
              >
                <span className="relative z-10">Try It Now</span>
                <ArrowRight className="w-6 h-6 relative z-10 group-hover:translate-x-1 transition-transform" />
                <div className="absolute inset-0 bg-white/10 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-700"></div>
              </button>
            </div>
          </div>
        </section>
      </div>

      {/* Footer - Minimal */}
      <footer className="relative z-20 border-t border-slate-200/50 bg-white/80 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center space-x-3">
              <PremiumLogo size={40} className="w-10 h-10" />
              <div>
                <h4 className="text-lg font-bold bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
                  Aegis IAM
                </h4>
                <p className="text-xs text-slate-500 font-medium">Enterprise IAM Security</p>
              </div>
            </div>
            <div className="flex items-center space-x-6">
              <a
                href="https://github.com/bhavikam28/aegis-iam"
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-600 hover:text-blue-600 font-medium text-sm transition-colors"
              >
                GitHub
              </a>
              <span className="text-slate-400">•</span>
              <p className="text-sm text-slate-500 font-medium">
                © {new Date().getFullYear()} Aegis IAM
              </p>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;
