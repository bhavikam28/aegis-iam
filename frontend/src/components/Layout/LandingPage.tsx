import React, { useState } from 'react';
import { Shield, Zap, Lock, ChevronRight, CheckCircle, Search, BarChart3, Code, AlertTriangle, Target } from 'lucide-react';
import Dashboard from './Dashboard';

const LandingPage: React.FC = () => {
  const [showDashboard, setShowDashboard] = useState(false);

  if (showDashboard) {
    return <Dashboard />;
  }

  return (
    <div className="min-h-screen bg-slate-950 relative overflow-hidden">
      {/* Professional Background with Network Pattern */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {/* Cybersecurity Network Pattern */}
        <div 
          className="absolute inset-0 opacity-[0.04]"
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23f97316' fill-opacity='0.4'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`
          }}
        />
        
        {/* Grid Lines */}
        <div 
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: `
              linear-gradient(to right, rgb(249, 115, 22) 1px, transparent 1px),
              linear-gradient(to bottom, rgb(249, 115, 22) 1px, transparent 1px)
            `,
            backgroundSize: '100px 100px'
          }}
        />

        {/* Gradient Orbs - Orange Theme */}
        <div className="absolute top-0 right-0 w-[900px] h-[900px] bg-orange-500/8 rounded-full blur-3xl animate-pulse-slow"></div>
        <div className="absolute bottom-0 left-0 w-[700px] h-[700px] bg-red-500/6 rounded-full blur-3xl animate-pulse-slow" style={{ animationDelay: '2s' }}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-orange-600/5 rounded-full blur-3xl animate-pulse-slow" style={{ animationDelay: '4s' }}></div>
        
        {/* Security Shield Pattern */}
        <div className="absolute inset-0 opacity-[0.02]" style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg width='80' height='80' viewBox='0 0 80 80' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M40 10 L50 15 L50 30 C50 40, 40 48, 40 50 C40 48, 30 40, 30 30 L30 15 Z' fill='%23f97316' fill-opacity='0.15'/%3E%3C/svg%3E")`,
          backgroundSize: '120px 120px'
        }}></div>

        {/* Hexagon Tech Pattern */}
        <div className="absolute inset-0 opacity-[0.02]" style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg width='80' height='80' viewBox='0 0 80 80' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M14 16H9v-2h5V9.87a4 4 0 1 1 2 0V14h5v2h-5v15.95A10 10 0 0 0 23.66 27l-3.46-2 8.2-2.2-2.9 5a12 12 0 0 1-21 0l-2.89-5 8.2 2.2-3.47 2A10 10 0 0 0 14 31.95V16zm40 40h-5v-2h5v-4.13a4 4 0 1 1 2 0V54h5v2h-5v15.95A10 10 0 0 0 63.66 67l-3.47-2 8.2-2.2-2.88 5a12 12 0 0 1-21.02 0l-2.88-5 8.2 2.2-3.47 2A10 10 0 0 0 54 71.95V56zm-39 6a2 2 0 1 1 0-4 2 2 0 0 1 0 4zm40-40a2 2 0 1 1 0-4 2 2 0 0 1 0 4zM15 8a2 2 0 1 0 0-4 2 2 0 0 0 0 4zm40 40a2 2 0 1 0 0-4 2 2 0 0 0 0 4z' fill='%23f97316' fill-opacity='0.15' fill-rule='evenodd'/%3E%3C/svg%3E")`,
          backgroundSize: '160px 160px'
        }}></div>
      </div>

      <style>{`
        @keyframes pulse-slow {
          0%, 100% { opacity: 0.08; transform: scale(1); }
          50% { opacity: 0.12; transform: scale(1.05); }
        }
        .animate-pulse-slow {
          animation: pulse-slow 8s ease-in-out infinite;
        }
      `}</style>

      <div className="relative max-w-7xl mx-auto px-8 py-16">
        {/* Header/Logo */}
        <div className="flex items-center space-x-4 mb-16">
          <div className="relative">
            <div className="w-16 h-16 bg-gradient-to-br from-orange-600 to-red-600 rounded-2xl flex items-center justify-center shadow-2xl shadow-orange-500/30 border border-orange-500/30">
              <Shield className="w-9 h-9 text-white" />
            </div>
            <div className="absolute -inset-1 bg-gradient-to-br from-orange-600 to-red-600 rounded-2xl blur opacity-30"></div>
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white">
              Aegis IAM
            </h1>
            <p className="text-slate-400 text-sm">AI Security Shield for AWS</p>
          </div>
        </div>

        {/* Hero Section */}
        <div className="text-center mb-20">
          <div className="inline-flex items-center space-x-2 bg-orange-500/10 border border-orange-500/30 rounded-full px-6 py-2 mb-8 backdrop-blur-sm">
            <Shield className="w-4 h-4 text-orange-400" />
            <span className="text-orange-300 text-sm font-medium">AI-Powered Security Platform</span>
          </div>

          <h2 className="text-7xl font-bold mb-6 leading-tight">
            <span className="text-white">Secure Your AWS</span>
            <br />
            <span className="bg-gradient-to-r from-orange-400 via-red-400 to-orange-500 bg-clip-text text-transparent">
              Infrastructure with AI
            </span>
          </h2>

          <p className="text-xl text-slate-400 max-w-3xl mx-auto mb-12 leading-relaxed">
            Simply describe your permissions in plain English, and our AI instantly generates secure, 
            least-privilege IAM policies. Validate existing policies and optimize usage patterns—all in seconds, not hours.
          </p>

          {/* CTA Buttons */}
          <div className="flex items-center justify-center space-x-4 mb-16">
            <button
              onClick={() => setShowDashboard(true)}
              className="group bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 text-white px-8 py-4 rounded-xl font-semibold text-lg shadow-lg shadow-orange-500/30 hover:shadow-xl hover:shadow-orange-500/50 transition-all flex items-center space-x-2"
            >
              <span>Launch Aegis IAM</span>
              <ChevronRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </button>
            
            <button className="border border-slate-700 text-white px-8 py-4 rounded-xl font-semibold text-lg hover:bg-slate-800/50 hover:border-slate-600 transition-all">
              View GitHub Repo
            </button>
          </div>

          {/* Trust Badges */}
          <div className="flex items-center justify-center space-x-12 text-slate-400">
            <div className="flex items-center space-x-2">
              <CheckCircle className="w-5 h-5 text-orange-400" />
              <span>AWS Certified</span>
            </div>
            <div className="flex items-center space-x-2">
              <Lock className="w-5 h-5 text-orange-400" />
              <span>Zero Trust</span>
            </div>
            <div className="flex items-center space-x-2">
              <Shield className="w-5 h-5 text-orange-400" />
              <span>AI-Powered</span>
            </div>
            <div className="flex items-center space-x-2">
              <Target className="w-5 h-5 text-orange-400" />
              <span>Least Privilege</span>
            </div>
          </div>
        </div>

        {/* Security Visualization */}
        <div className="relative mb-20">
          <div className="absolute inset-0 bg-gradient-to-r from-orange-500/8 via-red-500/6 to-orange-500/8 rounded-3xl blur-xl"></div>
          <div className="relative bg-slate-900/50 backdrop-blur-xl border border-slate-800/50 rounded-3xl p-12">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              {/* Security Icon Visual */}
              <div className="col-span-1 flex items-center justify-center">
                <div className="relative">
                  <div className="w-48 h-48 bg-gradient-to-br from-orange-600/20 to-red-600/20 rounded-full flex items-center justify-center backdrop-blur-sm border border-orange-500/30">
                    <Shield className="w-24 h-24 text-orange-400" />
                  </div>
                  {/* Static Indicators */}
                  <div className="absolute -top-4 -right-4 w-12 h-12 bg-orange-500/20 rounded-lg flex items-center justify-center border border-orange-500/40">
                    <Lock className="w-6 h-6 text-orange-400" />
                  </div>
                  <div className="absolute -bottom-4 -left-4 w-12 h-12 bg-red-500/20 rounded-lg flex items-center justify-center border border-red-500/40">
                    <Code className="w-6 h-6 text-red-400" />
                  </div>
                </div>
              </div>

              {/* Features Grid */}
              <div className="col-span-2 grid grid-cols-2 gap-6">
                <div className="bg-slate-800/30 backdrop-blur-sm border border-slate-700/50 rounded-2xl p-6 hover:border-orange-500/40 hover:bg-slate-800/50 transition-all">
                  <div className="w-12 h-12 bg-orange-500/10 rounded-xl flex items-center justify-center mb-4 border border-orange-500/30">
                    <Shield className="w-6 h-6 text-orange-400" />
                  </div>
                  <h4 className="text-white font-semibold mb-2">Generate Policies</h4>
                  <p className="text-slate-400 text-sm">AI creates secure IAM policies from plain English descriptions</p>
                </div>

                <div className="bg-slate-800/30 backdrop-blur-sm border border-slate-700/50 rounded-2xl p-6 hover:border-orange-500/40 hover:bg-slate-800/50 transition-all">
                  <div className="w-12 h-12 bg-orange-500/10 rounded-xl flex items-center justify-center mb-4 border border-orange-500/30">
                    <Search className="w-6 h-6 text-orange-400" />
                  </div>
                  <h4 className="text-white font-semibold mb-2">Validate Security</h4>
                  <p className="text-slate-400 text-sm">Analyze existing policies for vulnerabilities and compliance</p>
                </div>

                <div className="bg-slate-800/30 backdrop-blur-sm border border-slate-700/50 rounded-2xl p-6 hover:border-orange-500/40 hover:bg-slate-800/50 transition-all">
                  <div className="w-12 h-12 bg-orange-500/10 rounded-xl flex items-center justify-center mb-4 border border-orange-500/30">
                    <BarChart3 className="w-6 h-6 text-orange-400" />
                  </div>
                  <h4 className="text-white font-semibold mb-2">Optimize Usage</h4>
                  <p className="text-slate-400 text-sm">Right-size permissions based on CloudTrail usage data</p>
                </div>

                <div className="bg-slate-800/30 backdrop-blur-sm border border-slate-700/50 rounded-2xl p-6 hover:border-orange-500/40 hover:bg-slate-800/50 transition-all">
                  <div className="w-12 h-12 bg-orange-500/10 rounded-xl flex items-center justify-center mb-4 border border-orange-500/30">
                    <CheckCircle className="w-6 h-6 text-orange-400" />
                  </div>
                  <h4 className="text-white font-semibold mb-2">Compliance Ready</h4>
                  <p className="text-slate-400 text-sm">Built-in support for PCI DSS, HIPAA, SOX, and GDPR</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Features Section */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-20">
          <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800/50 rounded-2xl p-8 hover:border-orange-500/40 transition-all group">
            <div className="w-16 h-16 bg-orange-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform border border-orange-500/30">
              <Shield className="w-8 h-8 text-orange-400" />
            </div>
            <h3 className="text-2xl font-bold text-white mb-4">AI Co-Pilot</h3>
            <p className="text-slate-300 leading-relaxed mb-4">
              Conversational AI that understands your security requirements and generates policies that follow AWS best practices automatically.
            </p>
            <ul className="space-y-2 text-slate-400 text-sm">
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                <span>Natural language processing</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                <span>Iterative refinement through chat</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                <span>Least-privilege enforcement</span>
              </li>
            </ul>
          </div>

          <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800/50 rounded-2xl p-8 hover:border-orange-500/40 transition-all group">
            <div className="w-16 h-16 bg-orange-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform border border-orange-500/30">
              <Search className="w-8 h-8 text-orange-400" />
            </div>
            <h3 className="text-2xl font-bold text-white mb-4">Security Analyst</h3>
            <p className="text-slate-300 leading-relaxed mb-4">
              Deep security analysis of existing IAM policies, identifying vulnerabilities and providing actionable remediation steps.
            </p>
            <ul className="space-y-2 text-slate-400 text-sm">
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                <span>Vulnerability detection</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                <span>Compliance checking</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                <span>Risk scoring</span>
              </li>
            </ul>
          </div>

          <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800/50 rounded-2xl p-8 hover:border-orange-500/40 transition-all group">
            <div className="w-16 h-16 bg-orange-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform border border-orange-500/30">
              <BarChart3 className="w-8 h-8 text-orange-400" />
            </div>
            <h3 className="text-2xl font-bold text-white mb-4">Usage Optimizer</h3>
            <p className="text-slate-300 leading-relaxed mb-4">
              Analyze CloudTrail logs to identify unused permissions and generate right-sized policies based on actual usage patterns.
            </p>
            <ul className="space-y-2 text-slate-400 text-sm">
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                <span>CloudTrail analysis</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                <span>Permission optimization</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                <span>Risk reduction metrics</span>
              </li>
            </ul>
          </div>
        </div>

        {/* CTA Section */}
        <div className="bg-gradient-to-r from-slate-800/50 via-orange-900/20 to-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-3xl p-12 text-center">
          <h3 className="text-4xl font-bold text-white mb-4">Ready to Secure Your AWS Infrastructure?</h3>
          <p className="text-xl text-slate-300 mb-8 max-w-2xl mx-auto">
            Start automating your IAM policy management with AI-powered security. 
            Generate, validate, and optimize policies in seconds.
          </p>
          <button
            onClick={() => setShowDashboard(true)}
            className="bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 text-white px-10 py-5 rounded-xl font-bold text-lg shadow-lg shadow-orange-500/30 hover:shadow-xl hover:shadow-orange-500/50 transition-all inline-flex items-center space-x-3"
          >
            <span>Get Started Free</span>
            <ChevronRight className="w-6 h-6" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default LandingPage;