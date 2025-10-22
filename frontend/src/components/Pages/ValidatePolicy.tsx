import React, { useState } from 'react';
import { Search, AlertTriangle, XCircle, CheckCircle, Info, AlertCircle, Shield, Sparkles, Copy, Download, RefreshCw, Zap, Bot, ChevronDown, ChevronUp, Send, TrendingUp, Target, Clock, Share2, Activity, Scan, FileSearch, Users, Database } from 'lucide-react';

// ============================================
// TYPE DEFINITIONS
// ============================================

interface SecurityFinding {
  id: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  type: string;
  title: string;
  description: string;
  recommendation: string;
  affectedStatement?: number;
  code_snippet?: string;
}

interface ComplianceFramework {
  name: string;
  status: 'Compliant' | 'NonCompliant' | 'Partial';
  gaps?: string[];
  violations?: Array<{
    requirement: string;
    description: string;
    fix: string;
  }>;
}

interface AuditSummary {
  total_roles: number;
  roles_analyzed: number;
  total_policies: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
}

interface ValidatePolicyResponse {
  findings: SecurityFinding[];
  risk_score: number;
  security_issues: string[];
  recommendations: string[];
  compliance_status: Record<string, ComplianceFramework>;
  quick_wins?: string[];
  audit_summary?: AuditSummary | null;
  top_risks?: string[];
  agent_reasoning?: string;
}

interface EnhancementMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

// Mock API removed - using real API calls from backend

// ============================================
// MAIN COMPONENT
// ============================================

const ValidatePolicy: React.FC = () => {
  // Category selection: 'validate' or 'audit'
  const [activeCategory, setActiveCategory] = useState<'validate' | 'audit'>('validate');
  
  // Validate category state
  const [inputType, setInputType] = useState<'policy' | 'arn'>('policy');
  const [inputValue, setInputValue] = useState('');
  const [response, setResponse] = useState<ValidatePolicyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showInitialForm, setShowInitialForm] = useState(true);
  
  // Audit category state
  const [auditMode, setAuditMode] = useState<'full' | 'cloudtrail'>('full');
  const [auditResponse, setAuditResponse] = useState<any>(null);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditProgress, setAuditProgress] = useState<string>('');
  const [showAuditForm, setShowAuditForm] = useState(true);
  
  // Enhancement chat state
  const [enhancementChat, setEnhancementChat] = useState<EnhancementMessage[]>([]);
  const [enhancementInput, setEnhancementInput] = useState('');
  const [enhancementLoading, setEnhancementLoading] = useState(false);
  
  // Expandable sections
  const [showScoreExplanation, setShowScoreExplanation] = useState(false);
  const [showAgentReasoning, setShowAgentReasoning] = useState(true);
  const [showAllFindings, setShowAllFindings] = useState(false);

  const handleValidation = async () => {
    setLoading(true);
    setError(null);
    setShowInitialForm(false);
    
    try {
      // Real API call to backend
      const response = await fetch('http://localhost:8000/api/validate/quick', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input_type: inputType,
          input_value: inputValue,
          compliance_frameworks: ['pci_dss', 'hipaa', 'sox', 'gdpr']
        })
      });
      
      const data = await response.json();
      setResponse(data);
    } catch (err) {
      setError('Failed to validate policy. Please try again.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };
  
  const handleAudit = async () => {
    setAuditLoading(true);
    setShowAuditForm(false);
    setAuditProgress('Initializing autonomous audit agent...');
    
    try {
      // Real API call to backend
      const response = await fetch('http://localhost:8000/api/audit/account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: auditMode,
          compliance_frameworks: ['pci_dss', 'hipaa', 'sox', 'gdpr', 'cis']
        })
      });
      
      const data = await response.json();
      setAuditResponse(data);
    } catch (err) {
      setError('Failed to run audit. Please try again.');
      console.error(err);
    } finally {
      setAuditLoading(false);
      setAuditProgress('');
    }
  };

  const handleEnhancementSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!enhancementInput.trim()) return;
    
    const userMessage: EnhancementMessage = {
      role: 'user',
      content: enhancementInput,
      timestamp: new Date().toISOString()
    };
    
    setEnhancementChat([...enhancementChat, userMessage]);
    setEnhancementInput('');
    setEnhancementLoading(true);
    
    // Simulate AI response
    setTimeout(() => {
      const aiMessage: EnhancementMessage = {
        role: 'assistant',
        content: `I've updated your policy to ${enhancementInput}. The new risk score is 20/100 (improved from 50/100). Key changes:\n\n• Replaced wildcards with specific actions\n• Added resource-level ARNs\n• Included MFA condition for sensitive operations\n\nWould you like to review the updated policy?`,
        timestamp: new Date().toISOString()
      };
      setEnhancementChat(prev => [...prev, aiMessage]);
      setEnhancementLoading(false);
    }, 1500);
  };

  const handleQuickActionClick = (action: string) => {
    setEnhancementInput(action);
  };

  const getSeverityColor = (severity: SecurityFinding['severity']) => {
    switch (severity) {
      case 'Critical': return 'from-red-500/20 to-pink-500/20 border-red-500/30';
      case 'High': return 'from-orange-500/20 to-pink-500/20 border-orange-500/30';
      case 'Medium': return 'from-yellow-500/20 to-purple-500/10 border-yellow-500/30';
      case 'Low': return 'from-blue-500/20 to-purple-500/10 border-blue-500/30';
    }
  };

  const getSeverityTextColor = (severity: SecurityFinding['severity']) => {
    switch (severity) {
      case 'Critical': return 'text-red-400';
      case 'High': return 'text-orange-400';
      case 'Medium': return 'text-yellow-400';
      case 'Low': return 'text-blue-400';
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score <= 30) return 'text-green-400';
    if (score <= 60) return 'text-yellow-400';
    if (score <= 80) return 'text-orange-400';
    return 'text-red-400';
  };

  const getRiskGrade = (score: number) => {
    if (score <= 30) return { grade: 'A', label: 'Excellent', color: 'green' };
    if (score <= 60) return { grade: 'B', label: 'Good', color: 'yellow' };
    if (score <= 80) return { grade: 'C', label: 'Moderate Risk', color: 'orange' };
    return { grade: 'F', label: 'High Risk', color: 'red' };
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900">
      {/* Background Effects */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-20 w-[500px] h-[500px] bg-purple-500/15 rounded-full blur-3xl"></div>
        <div className="absolute bottom-20 left-20 w-[500px] h-[500px] bg-pink-500/12 rounded-full blur-3xl"></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-8 py-12 sm:py-16">
        {/* ============================================ */}
        {/* INITIAL FORM */}
        {/* ============================================ */}
        {showInitialForm && !response && (
          <div className="max-w-4xl mx-auto">
            {/* Hero Section */}
            <div className="text-center mb-12">
              <div className="inline-flex items-center space-x-2 bg-purple-500/10 border border-purple-500/30 rounded-full px-4 py-2 mb-6">
                <Shield className="w-4 h-4 text-purple-400" />
                <span className="text-purple-300 text-sm font-medium">AI-Powered Security Analysis</span>
              </div>
              
              <h1 className="text-5xl font-black mb-4">
                <span className="text-white">Validate & </span>
                <span className="bg-gradient-to-r from-orange-400 via-pink-500 to-purple-500 text-transparent bg-clip-text">Audit Security</span>
              </h1>
              
              <p className="text-slate-400 text-lg max-w-2xl mx-auto">
                Comprehensive security analysis powered by AI agents and AWS best practices
              </p>
            </div>
            
            {/* CATEGORY TABS */}
            <div className="flex items-center space-x-4 bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-2 max-w-2xl mx-auto">
                <button
                  onClick={() => {
                    setActiveCategory('validate');
                    setShowInitialForm(true);
                    setShowAuditForm(true);
                    setResponse(null);
                    setAuditResponse(null);
                  }}
                  className={`flex-1 flex items-center justify-center space-x-3 px-6 py-4 rounded-xl font-semibold transition-all ${
                    activeCategory === 'validate'
                      ? 'bg-gradient-to-r from-purple-600 via-pink-500 to-purple-600 text-white shadow-lg'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <FileSearch className="w-5 h-5" />
                  <div className="text-left">
                    <div className="text-sm font-bold">VALIDATE</div>
                    <div className="text-xs opacity-80">Quick Analysis</div>
                  </div>
                </button>
                
                <button
                  onClick={() => {
                    setActiveCategory('audit');
                    setShowInitialForm(true);
                    setShowAuditForm(true);
                    setResponse(null);
                    setAuditResponse(null);
                  }}
                  className={`flex-1 flex items-center justify-center space-x-3 px-6 py-4 rounded-xl font-semibold transition-all ${
                    activeCategory === 'audit'
                      ? 'bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 text-white shadow-lg'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <Scan className="w-5 h-5" />
                  <div className="text-left">
                    <div className="text-sm font-bold">AUDIT</div>
                    <div className="text-xs opacity-80">Account Scan</div>
                  </div>
                </button>
            </div>
          </div>
        )}
        
        {/* ============================================ */}
        {/* VALIDATE FORM */}
        {/* ============================================ */}
        {activeCategory === 'validate' && showInitialForm && !response && (
          <div className="max-w-4xl mx-auto">
            <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-3xl p-8 shadow-2xl">
              <div className="mb-8">
                <div className="flex items-center space-x-3 mb-4">
                  <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center border border-purple-500/30">
                    <FileSearch className="w-6 h-6 text-purple-400" />
                  </div>
                  <div>
                    <h3 className="text-white text-2xl font-bold">Quick Validation</h3>
                    <p className="text-slate-400 text-sm">Analyze a single IAM policy for security issues</p>
                  </div>
                </div>
              </div>
              
              <div className="mb-8">
                <label className="block text-white text-lg font-semibold mb-4">Input Type</label>
                <div className="grid grid-cols-2 gap-4">
                  <button
                    onClick={() => setInputType('policy')}
                    className={`px-6 py-4 rounded-2xl font-medium transition-all ${
                      inputType === 'policy'
                        ? 'bg-gradient-to-r from-purple-600 via-pink-500 to-purple-600 text-white shadow-lg'
                        : 'bg-slate-800/50 text-slate-400 hover:text-white border border-slate-700/50'
                    }`}
                  >
                    <Shield className="w-5 h-5 mx-auto mb-1" />
                    <span>Policy JSON</span>
                  </button>
                  <button
                    onClick={() => setInputType('arn')}
                    className={`px-6 py-4 rounded-2xl font-medium transition-all ${
                      inputType === 'arn'
                        ? 'bg-gradient-to-r from-purple-600 via-pink-500 to-purple-600 text-white shadow-lg'
                        : 'bg-slate-800/50 text-slate-400 hover:text-white border border-slate-700/50'
                    }`}
                  >
                    <Zap className="w-5 h-5 mx-auto mb-1" />
                    <span>Role ARN</span>
                  </button>
                </div>
              </div>

              {inputType === 'policy' ? (
                <div className="mb-8">
                  <label className="block text-white text-lg font-semibold mb-4">IAM Policy JSON</label>
                  <textarea
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    placeholder='{\n  "Version": "2012-10-17",\n  "Statement": [{\n    "Effect": "Allow",\n    "Action": "*:*",\n    "Resource": "*"\n  }]\n}'
                    className="w-full h-64 px-6 py-5 bg-slate-800/50 border border-slate-600/50 rounded-2xl text-white placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none resize-none font-mono text-base leading-relaxed"
                  />
                </div>
              ) : (
                <div className="mb-8">
                  <label className="block text-white text-lg font-semibold mb-4">IAM Role ARN</label>
                  <input
                    type="text"
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    placeholder="arn:aws:iam::123456789012:role/MyRole"
                    className="w-full px-6 py-5 bg-slate-800/50 border border-slate-600/50 rounded-2xl text-white placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none font-mono text-base"
                  />
                </div>
              )}

              <button
                onClick={handleValidation}
                disabled={loading || !inputValue.trim()}
                className="w-full bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 text-white py-5 px-8 rounded-2xl font-semibold text-lg hover:from-orange-700 hover:via-pink-600 hover:to-purple-700 disabled:opacity-50 transition-all shadow-lg flex items-center justify-center space-x-3"
              >
                <Search className="w-6 h-6" />
                <span>Analyze Security</span>
                <Shield className="w-5 h-5" />
              </button>
            </div>
          </div>
        )}
        
        {/* ============================================ */}
        {/* AUDIT FORM */}
        {/* ============================================ */}
        {activeCategory === 'audit' && showAuditForm && !auditResponse && (
          <div className="max-w-4xl mx-auto">
            <div className="bg-slate-900/50 backdrop-blur-xl border border-orange-500/20 rounded-3xl p-8 shadow-2xl">
              <div className="mb-8">
                <div className="flex items-center space-x-3 mb-4">
                  <div className="w-12 h-12 bg-orange-500/20 rounded-xl flex items-center justify-center border border-orange-500/30">
                    <Scan className="w-6 h-6 text-orange-400" />
                  </div>
                  <div>
                    <h3 className="text-white text-2xl font-bold">Autonomous Account Audit</h3>
                    <p className="text-slate-400 text-sm">AI agent scans your entire AWS account for security issues</p>
                  </div>
                </div>
              </div>
              
              {/* Info boxes */}
              <div className="mb-8 space-y-4">
                <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-4">
                  <div className="flex items-start space-x-3">
                    <Bot className="w-5 h-5 text-purple-400 mt-0.5" />
                    <div>
                      <h4 className="text-purple-300 font-semibold text-sm mb-1">Autonomous AI Agent</h4>
                      <p className="text-slate-400 text-sm leading-relaxed">
                        The agent will autonomously discover all IAM roles, analyze policies, detect patterns, and identify security issues across your entire AWS account.
                      </p>
                    </div>
                  </div>
                </div>
                
                <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4">
                  <div className="flex items-start space-x-3">
                    <Info className="w-5 h-5 text-slate-400 mt-0.5" />
                    <div>
                      <h4 className="text-slate-300 font-semibold text-sm mb-1">What Gets Analyzed</h4>
                      <ul className="text-slate-400 text-sm space-y-1">
                        <li>• All IAM roles and their inline policies</li>
                        <li>• Attached managed policies</li>
                        <li>• Cross-role security patterns</li>
                        <li>• Privilege escalation risks</li>
                        <li>• Compliance violations (PCI DSS, HIPAA, SOX, GDPR, CIS)</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <button
                onClick={handleAudit}
                disabled={auditLoading}
                className="w-full bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 text-white py-5 px-8 rounded-2xl font-semibold text-lg hover:from-orange-700 hover:via-pink-600 hover:to-purple-700 disabled:opacity-50 transition-all shadow-lg flex items-center justify-center space-x-3"
              >
                <Scan className="w-6 h-6" />
                <span>Start Autonomous Audit</span>
                <Bot className="w-5 h-5" />
              </button>
            </div>
          </div>
        )}

        {/* ============================================ */}
        {/* LOADING STATE - VALIDATE */}
        {/* ============================================ */}
        {loading && activeCategory === 'validate' && (
          <div className="fixed inset-0 flex items-center justify-center bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900 z-50">
            <div className="text-center">
              <div className="w-32 h-32 mb-8 relative mx-auto">
                <div className="absolute inset-0 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-full animate-ping"></div>
                <div className="absolute inset-0 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full opacity-20 animate-pulse"></div>
                <Shield className="w-16 h-16 text-purple-400 absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 animate-pulse" />
              </div>
              <h2 className="text-5xl font-bold text-white mb-4">Deep Security Analysis</h2>
              <p className="text-xl text-slate-300 mb-8">Scanning for vulnerabilities and compliance issues...</p>
              <div className="flex items-center justify-center space-x-2">
                <div className="w-3 h-3 bg-orange-400 rounded-full animate-bounce"></div>
                <div className="w-3 h-3 bg-pink-400 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
                <div className="w-3 h-3 bg-purple-400 rounded-full animate-bounce" style={{animationDelay: '0.4s'}}></div>
              </div>
            </div>
          </div>
        )}

        {/* ============================================ */}
        {/* LOADING STATE - AUDIT */}
        {/* ============================================ */}
        {auditLoading && activeCategory === 'audit' && (
          <div className="fixed inset-0 flex items-center justify-center bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900 z-50">
            <div className="text-center max-w-2xl mx-auto px-4">
              <div className="w-32 h-32 mb-8 relative mx-auto">
                <div className="absolute inset-0 bg-gradient-to-br from-orange-500/20 to-pink-500/20 rounded-full animate-ping"></div>
                <div className="absolute inset-0 bg-gradient-to-br from-orange-500 to-pink-500 rounded-full opacity-20 animate-pulse"></div>
                <Bot className="w-16 h-16 text-orange-400 absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 animate-pulse" />
              </div>
              
              <h2 className="text-5xl font-bold text-white mb-4">Autonomous Security Audit</h2>
              <p className="text-xl text-slate-300 mb-8">AI agent is scanning your entire AWS account...</p>
              
              {/* Live Progress */}
              {auditProgress && (
                <div className="bg-orange-500/10 border border-orange-500/30 rounded-xl p-6 mb-8">
                  <div className="flex items-center space-x-3 mb-3">
                    <Activity className="w-5 h-5 text-orange-400 animate-pulse" />
                    <span className="text-orange-300 font-semibold">Agent Status</span>
                  </div>
                  <p className="text-slate-300 text-sm">{auditProgress}</p>
                </div>
              )}
              
              <div className="flex items-center justify-center space-x-2">
                <div className="w-3 h-3 bg-orange-400 rounded-full animate-bounce"></div>
                <div className="w-3 h-3 bg-pink-400 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
                <div className="w-3 h-3 bg-purple-400 rounded-full animate-bounce" style={{animationDelay: '0.4s'}}></div>
              </div>
            </div>
          </div>
        )}

        {/* ============================================ */}
        {/* RESULTS - PREMIUM DESIGN */}
        {/* ============================================ */}
        {!loading && response && (
          <div className="max-w-[1800px] mx-auto">
            {/* Compact Header */}
            <div className="flex items-center justify-between mb-16">
              <div className="inline-flex items-center space-x-3 bg-gradient-to-r from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-full px-6 py-3">
                <CheckCircle className="w-5 h-5 text-green-400" />
                <span className="text-green-300 text-base font-semibold">Analysis Complete</span>
              </div>
              <button
                onClick={() => {
                  setResponse(null);
                  setInputValue('');
                  setShowInitialForm(true);
                  setEnhancementChat([]);
                }}
                className="group px-8 py-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white rounded-2xl transition-all shadow-xl shadow-purple-500/30 hover:shadow-purple-500/50 hover:scale-105 flex items-center space-x-3"
              >
                <RefreshCw className="w-5 h-5 group-hover:rotate-180 transition-transform duration-500" />
                <span className="font-bold text-lg">New Analysis</span>
              </button>
            </div>

            {/* RISK SCORE HERO - PROFESSIONAL SIZE */}
            <div className="mb-12">
              <div className="relative bg-gradient-to-br from-slate-900/90 via-slate-800/90 to-slate-900/90 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-10 overflow-hidden shadow-xl">
                {/* Subtle gradient orbs */}
                <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-br from-purple-500/5 to-pink-500/5 rounded-full blur-3xl"></div>
                <div className="absolute bottom-0 left-0 w-96 h-96 bg-gradient-to-tr from-blue-500/5 to-purple-500/5 rounded-full blur-3xl"></div>
                
                <div className="relative z-10">
                  <div className="flex items-center justify-between">
                    {/* Left: Score Circle */}
                    <div className="flex items-center space-x-8">
                      <div className="relative">
                        {/* Subtle glow */}
                        <div className={`absolute inset-0 rounded-full blur-xl opacity-30 ${
                          response.risk_score <= 30 ? 'bg-green-500' :
                          response.risk_score <= 60 ? 'bg-yellow-500' :
                          response.risk_score <= 80 ? 'bg-orange-500' :
                          'bg-red-500'
                        }`} style={{width: '180px', height: '180px'}}></div>
                        
                        {/* Score circle - SMALLER */}
                        <div className={`relative w-44 h-44 rounded-full flex items-center justify-center border-4 ${
                          response.risk_score <= 30 ? 'border-green-500/30 bg-green-500/5' :
                          response.risk_score <= 60 ? 'border-yellow-500/30 bg-yellow-500/5' :
                          response.risk_score <= 80 ? 'border-orange-500/30 bg-orange-500/5' :
                          'border-red-500/30 bg-red-500/5'
                        }`}>
                          <div className="text-center">
                            <div className={`text-6xl font-black leading-none ${
                              response.risk_score <= 30 ? 'text-green-400' :
                              response.risk_score <= 60 ? 'text-yellow-400' :
                              response.risk_score <= 80 ? 'text-orange-400' :
                              'text-red-400'
                            }`}>
                              {response.risk_score}
                            </div>
                            <div className="text-slate-500 text-sm font-semibold mt-1">/ 100</div>
                          </div>
                        </div>
                      </div>
                      
                      {/* Grade and Info */}
                      <div>
                        <div className="flex items-center space-x-4 mb-3">
                          <div className={`w-16 h-16 rounded-xl flex items-center justify-center font-black text-3xl ${
                            response.risk_score <= 30 ? 'bg-green-500/10 text-green-400 border-2 border-green-500/30' :
                            response.risk_score <= 60 ? 'bg-yellow-500/10 text-yellow-400 border-2 border-yellow-500/30' :
                            response.risk_score <= 80 ? 'bg-orange-500/10 text-orange-400 border-2 border-orange-500/30' :
                            'bg-red-500/10 text-red-400 border-2 border-red-500/30'
                          }`}>
                            {getRiskGrade(response.risk_score).grade}
                          </div>
                          <div>
                            <div className={`font-black text-3xl ${
                              response.risk_score <= 30 ? 'text-green-400' :
                              response.risk_score <= 60 ? 'text-yellow-400' :
                              response.risk_score <= 80 ? 'text-orange-400' :
                              'text-red-400'
                            }`}>
                              {getRiskGrade(response.risk_score).label}
                            </div>
                            <div className="text-slate-400 text-sm">
                              {response.findings.length} security {response.findings.length === 1 ? 'finding' : 'findings'}
                            </div>
                          </div>
                        </div>
                        
                        {/* Progress Bar */}
                        <div className="w-96">
                          <div className="w-full bg-slate-800/50 rounded-full h-3 overflow-hidden">
                            <div
                              className={`h-3 rounded-full transition-all duration-1000 ${
                                response.risk_score <= 30 ? 'bg-gradient-to-r from-green-500 to-emerald-400' :
                                response.risk_score <= 60 ? 'bg-gradient-to-r from-yellow-500 to-orange-400' :
                                response.risk_score <= 80 ? 'bg-gradient-to-r from-orange-500 to-red-500' :
                                'bg-gradient-to-r from-red-500 to-pink-500'
                              }`}
                              style={{ width: `${response.risk_score}%` }}
                            ></div>
                          </div>
                        </div>
                      </div>
                    </div>
                    
                    {/* Right: Severity Breakdown - COMPACT */}
                    <div className="flex items-center space-x-6">
                      <div className="text-center">
                        <div className="text-4xl font-black text-red-400 mb-1">
                          {response.findings.filter(f => f.severity === 'Critical').length}
                        </div>
                        <div className="text-xs text-slate-500 font-semibold uppercase">Critical</div>
                      </div>
                      <div className="text-center">
                        <div className="text-4xl font-black text-orange-400 mb-1">
                          {response.findings.filter(f => f.severity === 'High').length}
                        </div>
                        <div className="text-xs text-slate-500 font-semibold uppercase">High</div>
                      </div>
                      <div className="text-center">
                        <div className="text-4xl font-black text-yellow-400 mb-1">
                          {response.findings.filter(f => f.severity === 'Medium').length}
                        </div>
                        <div className="text-xs text-slate-500 font-semibold uppercase">Medium</div>
                      </div>
                      <div className="text-center">
                        <div className="text-4xl font-black text-blue-400 mb-1">
                          {response.findings.filter(f => f.severity === 'Low').length}
                        </div>
                        <div className="text-xs text-slate-500 font-semibold uppercase">Low</div>
                      </div>
                    </div>
                  </div>

                  {/* Score Explanation - EXPANDABLE */}
                  <button
                    onClick={() => setShowScoreExplanation(!showScoreExplanation)}
                    className="w-full px-8 py-5 bg-gradient-to-r from-purple-500/10 to-pink-500/10 hover:from-purple-500/20 hover:to-pink-500/20 border-2 border-purple-500/30 hover:border-purple-500/50 rounded-2xl transition-all flex items-center justify-between group"
                  >
                    <div className="flex items-center space-x-3">
                      <Info className="w-6 h-6 text-purple-400 group-hover:scale-110 transition-transform" />
                      <span className="text-purple-300 font-bold text-lg">Why score of {response.risk_score}/100?</span>
                    </div>
                    {showScoreExplanation ? <ChevronUp className="w-6 h-6 text-purple-400" /> : <ChevronDown className="w-6 h-6 text-purple-400" />}
                  </button>

                  {showScoreExplanation && (
                    <div className="mt-6 bg-gradient-to-br from-slate-950/80 to-slate-900/80 rounded-2xl p-8 border-2 border-slate-700/50 backdrop-blur-xl">
                      <p className="text-slate-300 text-lg leading-relaxed mb-8">
                        Your policy has the following issues contributing to this score:
                      </p>

                      <div className="space-y-6 mb-8">
                        <div>
                          <h5 className="text-red-400 font-bold mb-3 text-lg">Critical Issues (Weight: 40 points)</h5>
                          <ul className="space-y-3 text-slate-300 text-base">
                            <li className="flex items-start space-x-3">
                              <span className="text-red-400 mt-1 text-lg">•</span>
                              <span>Universal Action Wildcard ("*:*") - Grants permission to perform ANY action across ALL AWS services</span>
                            </li>
                            <li className="flex items-start space-x-3">
                              <span className="text-red-400 mt-1 text-lg">•</span>
                              <span>Universal Resource Wildcard ("*") - Applies these permissions to ALL resources in AWS</span>
                            </li>
                          </ul>
                        </div>

                        <div>
                          <h5 className="text-yellow-400 font-bold mb-3 text-lg">Medium Issues (Weight: 10 points)</h5>
                          <ul className="space-y-3 text-slate-300 text-base">
                            <li className="flex items-start space-x-3">
                              <span className="text-yellow-400 mt-1 text-lg">•</span>
                              <span>No Conditions - Policy lacks IP restrictions, MFA requirements, or time-based controls</span>
                            </li>
                            <li className="flex items-start space-x-3">
                              <span className="text-yellow-400 mt-1 text-lg">•</span>
                              <span>No Resource Boundaries - Missing resource ARN specifications</span>
                            </li>
                          </ul>
                        </div>
                      </div>

                      <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border-2 border-purple-500/30 rounded-xl p-6">
                        <h5 className="text-purple-300 font-bold mb-3 text-lg">How the score is calculated:</h5>
                        <ul className="space-y-2 text-slate-400 text-base">
                          <li>• Base score starts at 0 (perfect security)</li>
                          <li>• Each wildcard in Action adds +20 points</li>
                          <li>• Each wildcard in Resource adds +20 points</li>
                          <li>• Missing conditions adds +10 points</li>
                          <li>• <span className="text-orange-400 font-bold">Score of {response.risk_score} = Moderate Risk (needs immediate attention)</span></li>
                        </ul>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* COMPLIANCE STATUS - FULL WIDTH */}
            {response.compliance_status && Object.keys(response.compliance_status).length > 0 && (
              <div className="mb-10">
                <h3 className="text-white text-2xl font-bold mb-6">Compliance Status</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  {Object.entries(response.compliance_status).map(([key, framework]: [string, any]) => (
                    <div key={key} className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-xl p-5 hover:border-slate-600/50 transition-all">
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-white text-base font-semibold">{framework.name}</span>
                        <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                          framework.status === 'Compliant' ? 'bg-green-500/20 text-green-400' :
                          framework.status === 'Partial' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-red-500/20 text-red-400'
                        }`}>
                          {framework.status}
                        </span>
                      </div>
                      {framework.gaps && framework.gaps.length > 0 && (
                        <p className="text-xs text-slate-500 leading-relaxed">
                          {framework.gaps[0]}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* QUICK WINS & RECOMMENDATIONS - SIDE BY SIDE */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-10">
              {/* Quick Wins */}
              {response.quick_wins && response.quick_wins.length > 0 && (
                <div className="bg-gradient-to-br from-green-500/5 to-emerald-500/5 backdrop-blur-xl border border-green-500/20 rounded-2xl p-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <Zap className="w-6 h-6 text-green-400" />
                    <h4 className="text-green-400 text-xl font-bold">Quick Wins</h4>
                  </div>
                  <p className="text-slate-400 text-sm mb-4">High-impact fixes that take minimal time</p>
                  <ul className="space-y-3">
                    {response.quick_wins.map((win, index) => (
                      <li key={index} className="text-slate-300 text-sm flex items-start space-x-3 leading-relaxed">
                        <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                        <span>{win}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Recommendations */}
              {response.recommendations && response.recommendations.length > 0 && (
                <div className="bg-gradient-to-br from-purple-500/5 to-pink-500/5 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <Shield className="w-6 h-6 text-purple-400" />
                    <h4 className="text-purple-400 text-xl font-bold">Recommendations</h4>
                  </div>
                  <ul className="space-y-3">
                    {response.recommendations.map((rec, index) => (
                      <li key={index} className="text-slate-300 text-sm flex items-start space-x-3 leading-relaxed">
                        <AlertCircle className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* WHAT'S NEXT - FULL WIDTH */}
            <div className="mb-10">
              <div className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 backdrop-blur-xl border border-purple-500/30 rounded-2xl p-8">
                <div className="flex items-center space-x-3 mb-6">
                  <TrendingUp className="w-7 h-7 text-purple-400" />
                  <h4 className="text-purple-400 text-2xl font-bold">What's Next?</h4>
                </div>
                <ol className="space-y-4 text-slate-300 text-base">
                  <li className="flex items-start space-x-4">
                    <span className="text-purple-400 font-black text-xl flex-shrink-0">1.</span>
                    <span>Use the enhancement chat below to fix issues interactively</span>
                  </li>
                  <li className="flex items-start space-x-4">
                    <span className="text-purple-400 font-black text-xl flex-shrink-0">2.</span>
                    <span>Test the updated policy in a non-production environment</span>
                  </li>
                  <li className="flex items-start space-x-4">
                    <span className="text-purple-400 font-black text-xl flex-shrink-0">3.</span>
                    <span>Monitor CloudWatch logs after deployment</span>
                  </li>
                  <li className="flex items-start space-x-4">
                    <span className="text-purple-400 font-black text-xl flex-shrink-0">4.</span>
                    <span>Schedule regular policy audits</span>
                  </li>
                </ol>
              </div>
            </div>

            {/* ALL SECURITY FINDINGS - FULL WIDTH */}
            <div className="mb-10">
              <h3 className="text-white text-3xl font-bold mb-6">Security Findings</h3>
              {response.findings.length === 0 ? (
                <div className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 border-2 border-green-500/30 rounded-2xl p-10 text-center">
                  <CheckCircle className="w-20 h-20 text-green-400 mx-auto mb-4" />
                  <h4 className="text-green-400 font-black text-2xl mb-2">No Security Issues Found!</h4>
                  <p className="text-slate-300 text-lg">This policy follows AWS security best practices.</p>
                </div>
              ) : (
                <div className="space-y-6">
                  {response.findings.map((finding, index) => (
                    <div key={index} className={`bg-gradient-to-br ${getSeverityColor(finding.severity)} backdrop-blur-xl border rounded-2xl p-6`}>
                      <div className="flex items-start space-x-4 mb-4">
                        <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                          finding.severity === 'Critical' ? 'bg-red-500/20 border border-red-500/30' :
                          finding.severity === 'High' ? 'bg-orange-500/20 border border-orange-500/30' :
                          finding.severity === 'Medium' ? 'bg-yellow-500/20 border border-yellow-500/30' :
                          'bg-blue-500/20 border border-blue-500/30'
                        }`}>
                          {finding.severity === 'Critical' ? <XCircle className="w-6 h-6 text-red-400" /> :
                           finding.severity === 'High' ? <AlertTriangle className="w-6 h-6 text-orange-400" /> :
                           finding.severity === 'Medium' ? <AlertCircle className="w-6 h-6 text-yellow-400" /> :
                           <Info className="w-6 h-6 text-blue-400" />}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <h4 className="text-white font-bold text-lg">{finding.title}</h4>
                            <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                              finding.severity === 'Critical' ? 'bg-red-500/20 text-red-400' :
                              finding.severity === 'High' ? 'bg-orange-500/20 text-orange-400' :
                              finding.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-blue-500/20 text-blue-400'
                            }`}>
                              {finding.severity}
                            </span>
                            <span className="text-xs font-mono text-slate-500">{finding.id}</span>
                          </div>
                          <p className="text-slate-300 text-base mb-4 leading-relaxed">
                            {finding.description}
                          </p>
                          {finding.code_snippet && (
                            <div className="bg-slate-950/50 rounded-xl p-4 mb-4 border border-slate-700/50">
                              <div className="text-xs text-slate-500 mb-2 font-semibold">Problematic Code:</div>
                              <pre className="text-sm text-red-300 font-mono leading-relaxed">
                                {finding.code_snippet}
                              </pre>
                            </div>
                          )}
                          <div className="bg-purple-500/10 border border-purple-500/20 rounded-xl p-4">
                            <div className="flex items-start space-x-3">
                              <Sparkles className="w-5 h-5 text-purple-400 mt-0.5 flex-shrink-0" />
                              <div className="flex-1">
                                <div className="text-purple-300 font-semibold text-sm mb-1">Recommendation</div>
                                <p className="text-slate-300 text-sm leading-relaxed">{finding.recommendation}</p>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* OLD SIDEBAR CODE REMOVED - All sections now displayed above in full-width layout */}

            {response.compliance_status && Object.keys(response.compliance_status).length > 0 && (
            <>
            {/* Compliance Framework Violations - Full Width */}
            <div className="mb-10">
              <h3 className="text-white text-2xl font-bold mb-6">Compliance Framework Violations</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {Object.entries(response.compliance_status).map(([key, framework]: [string, any]) => {
                  if (framework.status === 'Compliant') return null;
                  return (
                    <div key={key} className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-orange-500/30 rounded-2xl p-6">
                      <div className="flex items-center justify-between mb-4">
                        <h4 className="text-white font-bold text-lg">{framework.name}</h4>
                        <span className="px-3 py-1 rounded-full text-xs font-semibold bg-red-500/20 text-red-400">
                          {framework.status}
                        </span>
                      </div>
                      
                      {framework.violations && framework.violations.length > 0 && (
                        <div className="space-y-4">
                          {framework.violations.map((violation: any, idx: number) => (
                            <div key={idx} className="bg-slate-950/50 rounded-xl p-4 border border-slate-700/50">
                              <div className="text-orange-400 font-semibold text-sm mb-2">{violation.requirement}</div>
                              <p className="text-slate-400 text-sm mb-3 leading-relaxed">{violation.description}</p>
                              <div className="bg-green-500/5 border border-green-500/20 rounded-lg p-3">
                                <div className="text-green-400 text-xs font-semibold mb-1">How to Fix:</div>
                                <p className="text-slate-300 text-sm">{violation.fix}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
            </>
            )}

            {/* Enhance Your Policy - Chat Interface */}
            <div className="mt-8 bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-2xl p-8">
              <div className="flex items-center space-x-3 mb-6">
                <Sparkles className="w-6 h-6 text-purple-400" />
                <h3 className="text-2xl font-bold text-white">Enhance Your Policy</h3>
              </div>
              
              <p className="text-slate-300 text-base mb-6 leading-relaxed">
                Our AI can help you fix these security issues and create a more secure policy.
              </p>
              
              {/* Conversation History */}
              {enhancementChat.length > 0 && (
                <div className="bg-slate-900/50 rounded-xl p-6 max-h-96 overflow-y-auto mb-6 border border-slate-700/50">
                  <div className="space-y-4">
                    {enhancementChat.map((msg, idx) => (
                      <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                        <div className={`max-w-[80%] ${msg.role === 'user' ? 'bg-purple-500/20 border-purple-500/30' : 'bg-slate-800/80 border-slate-700/50'} border rounded-2xl p-4`}>
                          <div className="flex items-center space-x-2 mb-2">
                            <span className={`text-xs font-semibold ${msg.role === 'user' ? 'text-purple-300' : 'text-slate-400'}`}>
                              {msg.role === 'user' ? 'You' : 'Aegis AI'}
                            </span>
                          </div>
                          <p className="text-slate-200 text-base leading-relaxed whitespace-pre-line">{msg.content}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              {/* Quick Action Chips */}
              <div className="flex flex-wrap gap-2 mb-4">
                <button 
                  onClick={() => handleQuickActionClick('Remove wildcard permissions and use specific actions')}
                  className="px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 rounded-lg text-purple-300 text-sm transition-all"
                >
                  🔒 Remove wildcard permissions
                </button>
                <button 
                  onClick={() => handleQuickActionClick('Add specific resource ARNs for my S3 bucket')}
                  className="px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 rounded-lg text-purple-300 text-sm transition-all"
                >
                  🎯 Add specific resource ARNs
                </button>
                <button 
                  onClick={() => handleQuickActionClick('Add MFA condition for all actions')}
                  className="px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 rounded-lg text-purple-300 text-sm transition-all"
                >
                  🛡️ Add MFA condition
                </button>
                <button 
                  onClick={() => handleQuickActionClick('Restrict to IP range 203.0.113.0/24')}
                  className="px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 rounded-lg text-purple-300 text-sm transition-all"
                >
                  📍 Restrict to specific IP ranges
                </button>
              </div>
              
              {/* Input Box */}
              <form onSubmit={handleEnhancementSubmit} className="flex space-x-3">
                <input 
                  type="text"
                  value={enhancementInput}
                  onChange={(e) => setEnhancementInput(e.target.value)}
                  placeholder="Ask AI to improve your policy... (e.g., 'Remove wildcards and add S3 bucket restrictions')"
                  className="flex-1 px-6 py-4 bg-slate-800/50 border border-slate-600/50 rounded-xl text-white text-base placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none"
                  disabled={enhancementLoading}
                />
                <button 
                  type="submit"
                  disabled={enhancementLoading || !enhancementInput.trim()}
                  className="px-6 py-4 bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 rounded-xl disabled:opacity-50 transition-all"
                >
                  {enhancementLoading ? (
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  ) : (
                    <Send className="w-5 h-5 text-white" />
                  )}
                </button>
              </form>
            </div>

            {/* Export Analysis Report */}
            <div className="mt-8 bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6">
              <h4 className="text-white text-lg font-semibold mb-4">Export Analysis Report</h4>
              <div className="flex flex-wrap gap-3">
                <button className="px-6 py-3 bg-purple-600 hover:bg-purple-700 rounded-xl text-white font-medium transition-all flex items-center space-x-2">
                  <Download className="w-4 h-4" />
                  <span>Download JSON</span>
                </button>
                <button className="px-6 py-3 bg-slate-700 hover:bg-slate-600 rounded-xl text-white font-medium transition-all flex items-center space-x-2">
                  <Copy className="w-4 h-4" />
                  <span>Copy Text Report</span>
                </button>
                <button className="px-6 py-3 bg-slate-700 hover:bg-slate-600 rounded-xl text-white font-medium transition-all flex items-center space-x-2">
                  <Share2 className="w-4 h-4" />
                  <span>Share Link</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ValidatePolicy;