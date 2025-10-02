import React, { useState } from 'react';
import { Shield, Zap, Lock, ChevronRight, CheckCircle, Search, BarChart3, Code } from 'lucide-react';
import Dashboard from './Dashboard';

const LandingPage: React.FC = () => {
  const [showDashboard, setShowDashboard] = useState(false);

  if (showDashboard) {
    return <Dashboard onReturnHome={() => setShowDashboard(false)} />;
  }

  return (
    <div className="min-h-screen bg-slate-950 relative overflow-hidden">
      {/* Premium Animated Background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {/* Cyber Grid Pattern */}
        <div 
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: `
              linear-gradient(to right, rgb(168, 85, 247) 1px, transparent 1px),
              linear-gradient(to bottom, rgb(168, 85, 247) 1px, transparent 1px)
            `,
            backgroundSize: '80px 80px'
          }}
        />

        {/* Glowing Gradient Orbs */}
        <div className="absolute top-0 right-0 w-[800px] h-[800px] bg-gradient-to-br from-orange-500/20 via-purple-500/20 to-pink-500/10 rounded-full blur-3xl animate-pulse-slow"></div>
        <div className="absolute bottom-0 left-0 w-[700px] h-[700px] bg-gradient-to-tr from-purple-600/15 via-pink-500/15 to-orange-500/10 rounded-full blur-3xl animate-pulse-slow" style={{ animationDelay: '2s' }}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-br from-pink-500/10 via-purple-500/15 to-orange-500/10 rounded-full blur-3xl animate-pulse-slow" style={{ animationDelay: '4s' }}></div>
        
        {/* Scan Lines Effect */}
        <div className="absolute inset-0 opacity-[0.02]" style={{
          backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgb(168, 85, 247) 2px, rgb(168, 85, 247) 4px)',
        }}></div>

        {/* Floating Particles */}
        <div className="absolute top-20 left-10 w-2 h-2 bg-purple-400 rounded-full animate-ping" style={{ animationDuration: '3s' }}></div>
        <div className="absolute top-40 right-20 w-2 h-2 bg-orange-400 rounded-full animate-ping" style={{ animationDuration: '4s', animationDelay: '1s' }}></div>
        <div className="absolute bottom-40 left-1/4 w-2 h-2 bg-pink-400 rounded-full animate-ping" style={{ animationDuration: '5s', animationDelay: '2s' }}></div>
      </div>

      <style>{`
        @keyframes pulse-slow {
          0%, 100% { opacity: 0.15; transform: scale(1); }
          50% { opacity: 0.25; transform: scale(1.05); }
        }
        .animate-pulse-slow {
          animation: pulse-slow 8s ease-in-out infinite;
        }
      `}</style>

      <div className="relative max-w-7xl mx-auto px-8 py-16">
        {/* Header/Logo with Glow */}
        <div className="flex items-center space-x-4 mb-16">
          <div className="relative">
            <div className="absolute inset-0 bg-gradient-to-br from-orange-600 to-purple-600 rounded-2xl blur-xl opacity-50"></div>
            <div className="relative w-16 h-16 bg-gradient-to-br from-orange-600 via-pink-500 to-purple-600 rounded-2xl flex items-center justify-center shadow-2xl border border-orange-500/30">
              <Shield className="w-9 h-9 text-white" />
            </div>
          </div>
          <div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-orange-400 via-pink-400 to-purple-400 bg-clip-text text-transparent">
              Aegis IAM
            </h1>
            <p className="text-slate-400 text-sm">AI Security Shield for AWS</p>
          </div>
        </div>

        {/* Hero Section */}
        <div className="text-center mb-20">
          <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-orange-500/10 via-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-full px-6 py-2 mb-8 backdrop-blur-sm">
            <Shield className="w-4 h-4 text-purple-400" />
            <span className="bg-gradient-to-r from-orange-400 to-purple-400 bg-clip-text text-transparent text-sm font-medium">AI-Powered Security Platform</span>
          </div>

          <h2 className="text-7xl font-bold mb-6 leading-tight">
            <span className="text-white">Secure Your AWS</span>
            <br />
            <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-500 bg-clip-text text-transparent">
              Infrastructure with AI
            </span>
          </h2>

          <p className="text-xl text-slate-400 max-w-3xl mx-auto mb-12 leading-relaxed">
            Simply describe your permissions in plain English, and our AI instantly generates secure, 
            least-privilege IAM policies. Validate existing policies and optimize usage patterns—all in seconds, not hours.
          </p>

          {/* CTA Buttons with Premium Gradients */}
          <div className="flex items-center justify-center space-x-4 mb-16">
            <button
              onClick={() => setShowDashboard(true)}
              className="group relative overflow-hidden bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 text-white px-8 py-4 rounded-xl font-semibold text-lg shadow-2xl shadow-purple-500/50 hover:shadow-purple-500/70 transition-all flex items-center space-x-2"
            >
              <span className="relative z-10">Launch Aegis IAM</span>
              <ChevronRight className="w-5 h-5 relative z-10 group-hover:translate-x-1 transition-transform" />
              <div className="absolute inset-0 bg-gradient-to-r from-orange-700 via-pink-600 to-purple-700 opacity-0 group-hover:opacity-100 transition-opacity"></div>
            </button>
            
            <a 
              href="https://github.com/bhavikam28/aegis-iam" 
              target="_blank" 
              rel="noopener noreferrer"
              className="border border-slate-700 text-white px-8 py-4 rounded-xl font-semibold text-lg hover:bg-slate-800/50 hover:border-purple-500/50 transition-all inline-block backdrop-blur-sm"
            >
              View GitHub Repo
            </a>
          </div>

          {/* Trust Badges with Premium Colors */}
          <div className="flex items-center justify-center space-x-12 text-slate-400">
            <div className="flex items-center space-x-2">
              <CheckCircle className="w-5 h-5 text-purple-400" />
              <span>Least Privilege</span>
            </div>
            <div className="flex items-center space-x-2">
              <Lock className="w-5 h-5 text-pink-400" />
              <span>AWS Compliant</span>
            </div>
            <div className="flex items-center space-x-2">
              <Shield className="w-5 h-5 text-orange-400" />
              <span>AI-Powered</span>
            </div>
            <div className="flex items-center space-x-2">
              <Zap className="w-5 h-5 text-purple-400" />
              <span>Security First</span>
            </div>
          </div>
        </div>

        {/* Security Visualization with Glassmorphism */}
        <div className="relative mb-20">
          <div className="absolute inset-0 bg-gradient-to-r from-orange-500/10 via-purple-500/10 to-pink-500/10 rounded-3xl blur-2xl"></div>
          <div className="relative bg-slate-900/50 backdrop-blur-2xl border border-purple-500/20 rounded-3xl p-12 shadow-2xl">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              {/* Security Icon Visual */}
              <div className="col-span-1 flex items-center justify-center">
                <div className="relative">
                  <div className="absolute inset-0 bg-gradient-to-br from-orange-600/30 via-pink-500/30 to-purple-600/30 rounded-full blur-2xl"></div>
                  <div className="relative w-48 h-48 bg-gradient-to-br from-orange-600/20 via-pink-500/20 to-purple-600/20 rounded-full flex items-center justify-center backdrop-blur-sm border border-purple-500/30">
                    <Shield className="w-24 h-24 text-purple-400" />
                  </div>
                  {/* Orbiting Indicators */}
                  <div className="absolute -top-4 -right-4 w-12 h-12 bg-gradient-to-br from-orange-500/30 to-pink-500/30 rounded-lg flex items-center justify-center border border-orange-500/40 backdrop-blur-sm">
                    <Lock className="w-6 h-6 text-orange-400" />
                  </div>
                  <div className="absolute -bottom-4 -left-4 w-12 h-12 bg-gradient-to-br from-purple-500/30 to-pink-500/30 rounded-lg flex items-center justify-center border border-purple-500/40 backdrop-blur-sm">
                    <Code className="w-6 h-6 text-purple-400" />
                  </div>
                </div>
              </div>

              {/* Features Grid with Premium Gradients */}
              <div className="col-span-2 grid grid-cols-2 gap-6">
                <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 backdrop-blur-sm border border-purple-500/20 rounded-2xl p-6 hover:border-purple-500/40 hover:shadow-lg hover:shadow-purple-500/20 transition-all">
                  <div className="w-12 h-12 bg-gradient-to-br from-orange-500/20 to-pink-500/20 rounded-xl flex items-center justify-center mb-4 border border-orange-500/30">
                    <Shield className="w-6 h-6 text-orange-400" />
                  </div>
                  <h4 className="text-white font-semibold mb-2">Generate Policies</h4>
                  <p className="text-slate-400 text-sm">AI creates secure IAM policies from plain English descriptions</p>
                </div>

                <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 backdrop-blur-sm border border-purple-500/20 rounded-2xl p-6 hover:border-purple-500/40 hover:shadow-lg hover:shadow-purple-500/20 transition-all">
                  <div className="w-12 h-12 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-xl flex items-center justify-center mb-4 border border-purple-500/30">
                    <Search className="w-6 h-6 text-purple-400" />
                  </div>
                  <h4 className="text-white font-semibold mb-2">Validate Security</h4>
                  <p className="text-slate-400 text-sm">Analyze existing policies for vulnerabilities and compliance</p>
                </div>

                <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 backdrop-blur-sm border border-purple-500/20 rounded-2xl p-6 hover:border-purple-500/40 hover:shadow-lg hover:shadow-purple-500/20 transition-all">
                  <div className="w-12 h-12 bg-gradient-to-br from-pink-500/20 to-purple-500/20 rounded-xl flex items-center justify-center mb-4 border border-pink-500/30">
                    <BarChart3 className="w-6 h-6 text-pink-400" />
                  </div>
                  <h4 className="text-white font-semibold mb-2">Optimize Usage</h4>
                  <p className="text-slate-400 text-sm">Right-size permissions based on CloudTrail usage data</p>
                </div>

                <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 backdrop-blur-sm border border-purple-500/20 rounded-2xl p-6 hover:border-purple-500/40 hover:shadow-lg hover:shadow-purple-500/20 transition-all">
                  <div className="w-12 h-12 bg-gradient-to-br from-orange-500/20 to-purple-500/20 rounded-xl flex items-center justify-center mb-4 border border-orange-500/30">
                    <CheckCircle className="w-6 h-6 text-orange-400" />
                  </div>
                  <h4 className="text-white font-semibold mb-2">Compliance Ready</h4>
                  <p className="text-slate-400 text-sm">Built-in support for PCI DSS, HIPAA, SOX, and GDPR</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Features Section with Premium Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-20">
          <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8 hover:border-purple-500/40 hover:shadow-2xl hover:shadow-purple-500/20 transition-all group">
            <div className="w-16 h-16 bg-gradient-to-br from-orange-500/20 via-pink-500/20 to-purple-500/20 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform border border-purple-500/30">
              <Shield className="w-8 h-8 text-purple-400" />
            </div>
            <h3 className="text-2xl font-bold bg-gradient-to-r from-orange-400 to-purple-400 bg-clip-text text-transparent mb-4">AI Co-Pilot</h3>
            <p className="text-slate-300 leading-relaxed mb-4">
              Conversational AI that understands your security requirements and generates policies that follow AWS best practices automatically.
            </p>
            <ul className="space-y-2 text-slate-400 text-sm">
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                <span>Natural language processing</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                <span>Iterative refinement through chat</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                <span>Least-privilege enforcement</span>
              </li>
            </ul>
          </div>

          <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8 hover:border-purple-500/40 hover:shadow-2xl hover:shadow-purple-500/20 transition-all group">
            <div className="w-16 h-16 bg-gradient-to-br from-pink-500/20 via-purple-500/20 to-orange-500/20 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform border border-pink-500/30">
              <Search className="w-8 h-8 text-pink-400" />
            </div>
            <h3 className="text-2xl font-bold bg-gradient-to-r from-pink-400 to-purple-400 bg-clip-text text-transparent mb-4">Security Analyst</h3>
            <p className="text-slate-300 leading-relaxed mb-4">
              Deep security analysis of existing IAM policies and roles. Identify vulnerabilities, 
              check compliance, and get actionable remediation steps.
            </p>
            <ul className="space-y-2 text-slate-400 text-sm">
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-pink-400 mt-0.5 flex-shrink-0" />
                <span>Vulnerability detection</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-pink-400 mt-0.5 flex-shrink-0" />
                <span>Compliance checking</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-pink-400 mt-0.5 flex-shrink-0" />
                <span>Risk scoring</span>
              </li>
            </ul>
          </div>

          <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8 hover:border-purple-500/40 hover:shadow-2xl hover:shadow-purple-500/20 transition-all group">
            <div className="w-16 h-16 bg-gradient-to-br from-purple-500/20 via-pink-500/20 to-orange-500/20 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform border border-purple-500/30">
              <BarChart3 className="w-8 h-8 text-purple-400" />
            </div>
            <h3 className="text-2xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent mb-4">Usage Optimizer</h3>
            <p className="text-slate-300 leading-relaxed mb-4">
              Analyze CloudTrail logs to identify unused permissions and generate right-sized policies based on actual usage patterns.
            </p>
            <ul className="space-y-2 text-slate-400 text-sm">
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                <span>CloudTrail analysis</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                <span>Permission optimization</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                <span>Risk reduction metrics</span>
              </li>
            </ul>
          </div>
        </div>

        {/* CTA Section with Premium Gradient */}
        <div className="relative">
          <div className="absolute inset-0 bg-gradient-to-r from-orange-500/10 via-purple-500/10 to-pink-500/10 rounded-3xl blur-2xl"></div>
          <div className="relative bg-gradient-to-r from-slate-800/50 via-purple-900/30 to-slate-800/50 backdrop-blur-xl border border-purple-500/30 rounded-3xl p-12 text-center">
            <h3 className="text-4xl font-bold text-white mb-4">Ready to Secure Your AWS Infrastructure?</h3>
            <p className="text-xl text-slate-300 mb-8 max-w-2xl mx-auto">
              Start automating your IAM policy management with AI-powered security. 
              Generate, validate, and optimize policies in seconds.
            </p>
            <button
              onClick={() => setShowDashboard(true)}
              className="bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 hover:from-orange-700 hover:via-pink-600 hover:to-purple-700 text-white px-10 py-5 rounded-xl font-bold text-lg shadow-2xl shadow-purple-500/50 hover:shadow-purple-500/70 transition-all inline-flex items-center space-x-3"
            >
              <span>Get Started Free</span>
              <ChevronRight className="w-6 h-6" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LandingPage;