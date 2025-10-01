import React, { useState } from 'react';
import { Shield, Zap, Lock, ChevronRight, CheckCircle, Search, BarChart3 } from 'lucide-react';
import Dashboard from './Dashboard';

const LandingPage: React.FC = () => {
  const [showDashboard, setShowDashboard] = useState(false);

  if (showDashboard) {
    return <Dashboard />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-purple-950/20 to-slate-950 relative overflow-hidden">
      {/* Animated Background Elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-20 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl animate-pulse-slow"></div>
        <div className="absolute bottom-20 left-20 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl animate-pulse-slow" style={{ animationDelay: '1s' }}></div>
        <div className="absolute top-1/2 left-1/2 w-96 h-96 bg-orange-500/10 rounded-full blur-3xl animate-pulse-slow" style={{ animationDelay: '2s' }}></div>
        
        {/* Circuit Board Pattern */}
        <div className="absolute inset-0 opacity-5" style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%239C92AC' fill-opacity='0.4'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`
        }}></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-8 py-16">
        {/* Header/Logo */}
        <div className="flex items-center space-x-4 mb-16">
          <div className="relative">
            <div className="w-16 h-16 bg-gradient-to-br from-orange-500 via-purple-600 to-blue-600 rounded-2xl flex items-center justify-center shadow-2xl shadow-purple-500/50">
              <Shield className="w-9 h-9 text-white" />
            </div>
            <div className="absolute -inset-1 bg-gradient-to-br from-orange-500 via-purple-600 to-blue-600 rounded-2xl blur opacity-30 animate-pulse-slow"></div>
          </div>
          <div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-white via-purple-200 to-blue-200 bg-clip-text text-transparent">
              Aegis IAM
            </h1>
            <p className="text-slate-400 text-sm">AI Security Shield for AWS</p>
          </div>
        </div>

        {/* Hero Section */}
        <div className="text-center mb-20">
          <div className="inline-flex items-center space-x-2 bg-purple-500/10 border border-purple-500/30 rounded-full px-6 py-2 mb-8 backdrop-blur-sm">
            <Zap className="w-4 h-4 text-purple-400" />
            <span className="text-purple-300 text-sm font-medium">AI-Powered Security Platform</span>
          </div>

          <h2 className="text-7xl font-bold mb-6 leading-tight">
            <span className="text-white">Secure Your AWS</span>
            <br />
            <span className="bg-gradient-to-r from-orange-400 via-purple-400 to-blue-400 bg-clip-text text-transparent">
              Infrastructure with AI
            </span>
          </h2>

          <p className="text-xl text-slate-300 max-w-3xl mx-auto mb-12 leading-relaxed">
            Aegis IAM uses advanced AI to generate, validate, and optimize AWS IAM policies. 
            Achieve least-privilege security with zero-trust architecture in seconds, not hours.
          </p>

          {/* CTA Buttons */}
          <div className="flex items-center justify-center space-x-4 mb-16">
            <button
              onClick={() => setShowDashboard(true)}
              className="group bg-gradient-to-r from-orange-500 via-purple-600 to-blue-600 text-white px-8 py-4 rounded-xl font-semibold text-lg hover:shadow-2xl hover:shadow-purple-500/50 transition-all flex items-center space-x-2"
            >
              <span>Launch Aegis IAM</span>
              <ChevronRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </button>
            
            <button className="border border-slate-700 text-white px-8 py-4 rounded-xl font-semibold text-lg hover:bg-slate-800/50 transition-all">
              View Documentation
            </button>
          </div>

          {/* Trust Badges */}
          <div className="flex items-center justify-center space-x-12 text-slate-400">
            <div className="flex items-center space-x-2">
              <Shield className="w-5 h-5 text-green-400" />
              <span>AWS Certified</span>
            </div>
            <div className="flex items-center space-x-2">
              <Lock className="w-5 h-5 text-blue-400" />
              <span>Zero Trust</span>
            </div>
            <div className="flex items-center space-x-2">
              <Zap className="w-5 h-5 text-purple-400" />
              <span>AI-Powered</span>
            </div>
            <div className="flex items-center space-x-2">
              <CheckCircle className="w-5 h-5 text-orange-400" />
              <span>Least Privilege</span>
            </div>
          </div>
        </div>

        {/* Security Visualization */}
        <div className="relative mb-20">
          <div className="absolute inset-0 bg-gradient-to-r from-purple-500/20 via-blue-500/20 to-orange-500/20 rounded-3xl blur-3xl"></div>
          <div className="relative bg-slate-900/30 backdrop-blur-xl border border-slate-700/50 rounded-3xl p-12">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              {/* Security Icon Visual */}
              <div className="col-span-1 flex items-center justify-center">
                <div className="relative">
                  <div className="w-48 h-48 bg-gradient-to-br from-purple-600/30 via-blue-600/30 to-orange-600/30 rounded-full flex items-center justify-center backdrop-blur-sm border border-slate-700/50">
                    <Shield className="w-24 h-24 text-purple-400" />
                  </div>
                  {/* Orbiting Elements */}
                  <div className="absolute top-0 right-0 w-12 h-12 bg-blue-500/20 rounded-full flex items-center justify-center border border-blue-500/50 animate-orbit">
                    <Lock className="w-6 h-6 text-blue-400" />
                  </div>
                  <div className="absolute bottom-0 left-0 w-12 h-12 bg-orange-500/20 rounded-full flex items-center justify-center border border-orange-500/50 animate-orbit-reverse">
                    <Zap className="w-6 h-6 text-orange-400" />
                  </div>
                </div>
              </div>

              {/* Features Grid */}
              <div className="col-span-2 grid grid-cols-2 gap-6">
                <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-2xl p-6 hover:border-purple-500/50 transition-all">
                  <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center mb-4">
                    <Shield className="w-6 h-6 text-purple-400" />
                  </div>
                  <h4 className="text-white font-semibold mb-2">Generate Policies</h4>
                  <p className="text-slate-400 text-sm">AI creates secure IAM policies from plain English descriptions</p>
                </div>

                <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-2xl p-6 hover:border-blue-500/50 transition-all">
                  <div className="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center mb-4">
                    <Search className="w-6 h-6 text-blue-400" />
                  </div>
                  <h4 className="text-white font-semibold mb-2">Validate Security</h4>
                  <p className="text-slate-400 text-sm">Analyze existing policies for vulnerabilities and compliance</p>
                </div>

                <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-2xl p-6 hover:border-orange-500/50 transition-all">
                  <div className="w-12 h-12 bg-orange-500/20 rounded-xl flex items-center justify-center mb-4">
                    <BarChart3 className="w-6 h-6 text-orange-400" />
                  </div>
                  <h4 className="text-white font-semibold mb-2">Optimize Usage</h4>
                  <p className="text-slate-400 text-sm">Right-size permissions based on CloudTrail usage data</p>
                </div>

                <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-2xl p-6 hover:border-green-500/50 transition-all">
                  <div className="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center mb-4">
                    <CheckCircle className="w-6 h-6 text-green-400" />
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
          <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-8 hover:border-purple-500/50 transition-all group">
            <div className="w-16 h-16 bg-gradient-to-br from-purple-500/20 to-purple-600/20 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
              <Shield className="w-8 h-8 text-purple-400" />
            </div>
            <h3 className="text-2xl font-bold text-white mb-4">AI Co-Pilot</h3>
            <p className="text-slate-300 leading-relaxed mb-4">
              Conversational AI that understands your security requirements and generates policies that follow AWS best practices automatically.
            </p>
            <ul className="space-y-2 text-slate-400 text-sm">
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                <span>Natural language processing</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                <span>Iterative refinement through chat</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                <span>Least-privilege enforcement</span>
              </li>
            </ul>
          </div>

          <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-8 hover:border-blue-500/50 transition-all group">
            <div className="w-16 h-16 bg-gradient-to-br from-blue-500/20 to-blue-600/20 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
              <Search className="w-8 h-8 text-blue-400" />
            </div>
            <h3 className="text-2xl font-bold text-white mb-4">Security Analyst</h3>
            <p className="text-slate-300 leading-relaxed mb-4">
              Deep security analysis of existing IAM policies, identifying vulnerabilities and providing actionable remediation steps.
            </p>
            <ul className="space-y-2 text-slate-400 text-sm">
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                <span>Vulnerability detection</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                <span>Compliance checking</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                <span>Risk scoring</span>
              </li>
            </ul>
          </div>

          <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-8 hover:border-orange-500/50 transition-all group">
            <div className="w-16 h-16 bg-gradient-to-br from-orange-500/20 to-orange-600/20 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
              <BarChart3 className="w-8 h-8 text-orange-400" />
            </div>
            <h3 className="text-2xl font-bold text-white mb-4">Usage Optimizer</h3>
            <p className="text-slate-300 leading-relaxed mb-4">
              Analyze CloudTrail logs to identify unused permissions and generate right-sized policies based on actual usage patterns.
            </p>
            <ul className="space-y-2 text-slate-400 text-sm">
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                <span>CloudTrail analysis</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                <span>Permission optimization</span>
              </li>
              <li className="flex items-start space-x-2">
                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                <span>Risk reduction metrics</span>
              </li>
            </ul>
          </div>
        </div>

        {/* CTA Section */}
        <div className="bg-gradient-to-r from-purple-900/30 via-blue-900/30 to-orange-900/30 backdrop-blur-xl border border-slate-700/50 rounded-3xl p-12 text-center">
          <h3 className="text-4xl font-bold text-white mb-4">Ready to Secure Your AWS Infrastructure?</h3>
          <p className="text-xl text-slate-300 mb-8 max-w-2xl mx-auto">
            Join organizations using Aegis IAM to automate IAM policy management and achieve least-privilege security at scale.
          </p>
          <button
            onClick={() => setShowDashboard(true)}
            className="bg-gradient-to-r from-orange-500 via-purple-600 to-blue-600 text-white px-10 py-5 rounded-xl font-bold text-lg hover:shadow-2xl hover:shadow-purple-500/50 transition-all inline-flex items-center space-x-3"
          >
            <span>Get Started Free</span>
            <ChevronRight className="w-6 h-6" />
          </button>
        </div>
      </div>

      <style jsx>{`
        @keyframes pulse-slow {
          0%, 100% { opacity: 0.3; transform: scale(1); }
          50% { opacity: 0.5; transform: scale(1.05); }
        }

        @keyframes orbit {
          from { transform: rotate(0deg) translateX(100px) rotate(0deg); }
          to { transform: rotate(360deg) translateX(100px) rotate(-360deg); }
        }

        @keyframes orbit-reverse {
          from { transform: rotate(0deg) translateX(100px) rotate(0deg); }
          to { transform: rotate(-360deg) translateX(100px) rotate(360deg); }
        }

        .animate-pulse-slow {
          animation: pulse-slow 4s ease-in-out infinite;
        }

        .animate-orbit {
          animation: orbit 20s linear infinite;
        }

        .animate-orbit-reverse {
          animation: orbit-reverse 15s linear infinite;
        }
      `}</style>
    </div>
  );
};

export default LandingPage;