import React, { useState, useRef, useEffect } from 'react';
import { Search, AlertTriangle, XCircle, CheckCircle, Info, AlertCircle, Shield, Sparkles, Copy, Download, RefreshCw, Zap, Bot, ChevronDown, ChevronUp, Send, TrendingUp, Target, Clock, Share2, Activity, Scan, FileSearch, Users, Database, Lock, Eye, Settings, X, Minimize2, Maximize2 } from 'lucide-react';

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
  detailed_explanation?: string;
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

interface ValidatePolicyResponse {
  findings: SecurityFinding[];
  risk_score: number;
  security_issues: string[];
  recommendations: string[];
  compliance_status: Record<string, ComplianceFramework>;
  quick_wins?: string[];
  audit_summary?: any;
  top_risks?: string[];
  agent_reasoning?: string;
}

interface EnhancementMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

// Available compliance frameworks
const AVAILABLE_FRAMEWORKS = [
  { id: 'pci_dss', name: 'PCI DSS', description: 'Payment Card Industry Data Security Standard' },
  { id: 'hipaa', name: 'HIPAA', description: 'Health Insurance Portability and Accountability Act' },
  { id: 'sox', name: 'SOX', description: 'Sarbanes-Oxley Act' },
  { id: 'gdpr', name: 'GDPR', description: 'General Data Protection Regulation' },
  { id: 'cis', name: 'CIS', description: 'Center for Internet Security Benchmarks' },
  { id: 'hitrust', name: 'HITRUST', description: 'Health Information Trust Alliance' },
  { id: 'nist', name: 'NIST 800-53', description: 'National Institute of Standards and Technology' },
  { id: 'iso27001', name: 'ISO 27001', description: 'Information Security Management' }
];

const ValidatePolicy: React.FC = () => {
  // State management
  const [inputType, setInputType] = useState<'policy' | 'arn'>('policy');
  const [inputValue, setInputValue] = useState('');
  const [response, setResponse] = useState<ValidatePolicyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showInitialForm, setShowInitialForm] = useState(true);
  
  // Selected compliance frameworks (default ones checked)
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>(['pci_dss', 'hipaa', 'sox', 'gdpr']);
  const [showFrameworkSelector, setShowFrameworkSelector] = useState(false);
  
  // Enhancement chat state
  const [enhancementChat, setEnhancementChat] = useState<EnhancementMessage[]>([]);
  const [enhancementInput, setEnhancementInput] = useState('');
  const [enhancementLoading, setEnhancementLoading] = useState(false);
  const [isChatbotOpen, setIsChatbotOpen] = useState(false);
  const [isChatbotExpanded, setIsChatbotExpanded] = useState(false);
  
  // Expandable sections
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const [showScoreBreakdown, setShowScoreBreakdown] = useState(false);
  
  const chatEndRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [enhancementChat]);

  // Helper function for risk grade - MUST BE BEFORE handleValidation
  const getRiskGrade = (score: number) => {
    if (score <= 30) return { 
      grade: 'A', 
      label: 'Excellent', 
      color: 'emerald', 
      bgClass: 'from-emerald-500/20 to-green-500/20', 
      borderClass: 'border-emerald-500/30' 
    };
    if (score <= 60) return { 
      grade: 'B', 
      label: 'Good', 
      color: 'yellow', 
      bgClass: 'from-yellow-500/20 to-amber-500/20', 
      borderClass: 'border-yellow-500/30' 
    };
    if (score <= 80) return { 
      grade: 'C', 
      label: 'Moderate Risk', 
      color: 'orange', 
      bgClass: 'from-orange-500/20 to-red-500/20', 
      borderClass: 'border-orange-500/30' 
    };
    return { 
      grade: 'F', 
      label: 'High Risk', 
      color: 'red', 
      bgClass: 'from-red-500/20 to-rose-500/20', 
      borderClass: 'border-red-500/30' 
    };
  };

  const toggleFramework = (frameworkId: string) => {
    setSelectedFrameworks(prev => 
      prev.includes(frameworkId)
        ? prev.filter(id => id !== frameworkId)
        : [...prev, frameworkId]
    );
  };

  const handleValidation = async () => {
    console.log('🔍 handleValidation called');
    console.log('📝 inputType:', inputType);
    console.log('📝 inputValue length:', inputValue.length);
    console.log('📝 inputValue preview:', inputValue.substring(0, 100));
    
    // Clean the input - remove markdown code fences if present
    let cleanedInput = inputValue.trim();
    if (cleanedInput.startsWith('```json') || cleanedInput.startsWith('```')) {
      cleanedInput = cleanedInput.replace(/^```(json)?\n?/, '').replace(/```\s*$/, '').trim();
      console.log('✨ Removed markdown code fences');
    }
    
    // Validate JSON if it's a policy
    if (inputType === 'policy') {
      try {
        JSON.parse(cleanedInput);
      } catch (e) {
        setError('Invalid JSON format. Please paste valid IAM policy JSON (without markdown code fences).');
        return;
      }
    }
    
    setLoading(true);
    setError(null);
    setShowInitialForm(false);
    
    try {
      const response = await fetch('http://localhost:8000/api/validate/quick', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input_type: inputType,
          input_value: cleanedInput,
          compliance_frameworks: selectedFrameworks
        })
      });
      
      const data = await response.json();
      
      // Check for errors in response
      if (data.error || data.success === false || !data.risk_score) {
        setError(data.error || 'Validation failed. Please check your input and try again.');
        setShowInitialForm(true);
        return;
      }
      
      setResponse(data);
      
      // Auto-open chatbot with greeting
      setTimeout(() => {
        const greeting: EnhancementMessage = {
          role: 'assistant',
          content: `�️ **Analysis Complete!** I'm Aegis AI, your intelligent security assistant.

📊 **Your Policy Assessment:**
• Risk Score: **${data.risk_score}/100** (${getRiskGrade(data.risk_score).label})
• Total Findings: **${data.findings.length}** security ${data.findings.length === 1 ? 'issue' : 'issues'}
• Critical: **${data.findings.filter((f: SecurityFinding) => f.severity === 'Critical').length}** | High: **${data.findings.filter((f: SecurityFinding) => f.severity === 'High').length}** | Medium: **${data.findings.filter((f: SecurityFinding) => f.severity === 'Medium').length}** | Low: **${data.findings.filter((f: SecurityFinding) => f.severity === 'Low').length}**

🚀 **I can help you:**

🔥 **"Fix all critical issues"** - Automatically remediate high-risk vulnerabilities
🔒 **"Add MFA requirement"** - Enforce multi-factor authentication
✨ **"Remove wildcards"** - Replace * with specific permissions
🌍 **"Add IP restrictions"** - Limit access by source IP
📝 **"Rewrite this policy"** - Generate a secure version from scratch
💬 **"Explain finding IAM-001"** - Get detailed explanations

**Try one of the quick actions below or ask me anything!** 👇`,
          timestamp: new Date().toISOString()
        };
        setEnhancementChat([greeting]);
      }, 500);
    } catch (err) {
      setError('Failed to validate policy. Please try again.');
      setShowInitialForm(true);
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleEnhancementSubmit = async (e: React.FormEvent) => {
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
    
    // Check if user is asking for additional frameworks
    const askingForFrameworks = enhancementInput.toLowerCase().includes('framework') || 
                                  enhancementInput.toLowerCase().includes('hitrust') ||
                                  enhancementInput.toLowerCase().includes('nist') ||
                                  enhancementInput.toLowerCase().includes('iso');
    
    // Simulate AI response
    setTimeout(() => {
      let aiResponse = '';
      
      if (askingForFrameworks) {
        aiResponse = `I can validate your policy against additional compliance frameworks!\n\nAvailable frameworks:\n• HITRUST - Healthcare security framework\n• NIST 800-53 - Government security controls\n• ISO 27001 - International security standard\n\nWould you like me to run validation against any of these? Just let me know which ones!`;
      } else {
        aiResponse = `I've updated your policy based on your request: "${enhancementInput}"\n\nKey improvements:\n• Replaced wildcard permissions with specific actions\n• Added resource-level ARN restrictions\n• Included security conditions\n\nThe new risk score is estimated at 20/100 (improved from ${response?.risk_score}/100).\n\nWould you like me to show you the updated policy?`;
      }
      
      const aiMessage: EnhancementMessage = {
        role: 'assistant',
        content: aiResponse,
        timestamp: new Date().toISOString()
      };
      setEnhancementChat(prev => [...prev, aiMessage]);
      setEnhancementLoading(false);
    }, 1500);
  };

  const toggleFindingExpansion = (findingId: string) => {
    setExpandedFindings(prev => {
      const newSet = new Set(prev);
      if (newSet.has(findingId)) {
        newSet.delete(findingId);
      } else {
        newSet.add(findingId);
      }
      return newSet;
    });
  };

  // CHANGE 1: Fixed getSeverityColor with cyan/blue scheme
  const getSeverityColor = (severity: SecurityFinding['severity']) => {
    switch (severity) {
      case 'Critical': return { 
        bg: 'from-cyan-500/10 to-blue-500/10', 
        border: 'border-cyan-500/30', 
        icon: 'bg-cyan-500/20 border-cyan-500/30', 
        text: 'text-cyan-400' 
      };
      case 'High': return { 
        bg: 'from-blue-500/10 to-indigo-500/10', 
        border: 'border-blue-500/30', 
        icon: 'bg-blue-500/20 border-blue-500/30', 
        text: 'text-blue-400' 
      };
      case 'Medium': return { 
        bg: 'from-yellow-500/10 to-orange-500/10', 
        border: 'border-yellow-500/30', 
        icon: 'bg-yellow-500/20 border-yellow-500/30', 
        text: 'text-yellow-400' 
      };
      case 'Low': return { 
        bg: 'from-slate-500/10 to-slate-600/10', 
        border: 'border-slate-500/30', 
        icon: 'bg-slate-500/20 border-slate-500/30', 
        text: 'text-slate-400' 
      };
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900">
      {/* Animated Background Orbs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-purple-500/15 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-pink-500/12 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] bg-orange-500/8 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '2s' }}></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-8 py-12 sm:py-20">
        {/* ============================================ */}
        {/* INITIAL FORM */}
        {/* ============================================ */}
        {showInitialForm && !response && (
          <div className="relative">
            {/* Hero Section */}
            <div className="mb-16">
              <div className="inline-flex items-center space-x-2 bg-purple-500/10 border border-purple-500/30 rounded-full px-6 py-2 mb-6 backdrop-blur-xl">
                <Shield className="w-4 h-4 text-purple-400" />
                <span className="text-purple-400 text-sm font-medium">AI-Powered Security Analysis</span>
              </div>
              
              <h1 className="text-6xl font-black text-white mb-6 leading-tight">
                Validate IAM<br />
                <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-500 bg-clip-text text-transparent">
                  Security Policies
                </span>
              </h1>
              
              <p className="text-xl text-slate-300 max-w-3xl leading-relaxed">
                Deep security analysis powered by AI agents. Get instant risk assessment, 
                compliance validation, and actionable recommendations.
              </p>
            </div>

            {/* Main Input Form */}
            <div className="max-w-4xl mx-auto">
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-3xl p-10 shadow-2xl shadow-purple-500/10">
                {/* Input Type Selection */}
                <div className="mb-8">
                  <label className="block text-white text-lg font-bold mb-4">What would you like to validate?</label>
                  <div className="grid grid-cols-2 gap-4">
                    <button
                      onClick={() => setInputType('policy')}
                      className={`group px-6 py-6 rounded-2xl font-semibold transition-all duration-300 ${
                        inputType === 'policy'
                          ? 'bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 text-white shadow-lg shadow-purple-500/25'
                          : 'bg-slate-800/50 text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-700/50'
                      }`}
                    >
                      <Shield className="w-8 h-8 mx-auto mb-2 group-hover:scale-110 transition-transform duration-300" />
                      <span className="block text-base">Policy JSON</span>
                      <span className="block text-xs opacity-75 mt-1">Paste your IAM policy</span>
                    </button>
                    <button
                      onClick={() => setInputType('arn')}
                      className={`group px-6 py-6 rounded-2xl font-semibold transition-all duration-300 ${
                        inputType === 'arn'
                          ? 'bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 text-white shadow-lg shadow-purple-500/25'
                          : 'bg-slate-800/50 text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-700/50'
                      }`}
                    >
                      <Zap className="w-8 h-8 mx-auto mb-2 group-hover:scale-110 transition-transform duration-300" />
                      <span className="block text-base">Role ARN</span>
                      <span className="block text-xs opacity-75 mt-1">Fetch from AWS</span>
                    </button>
                  </div>
                </div>

                {/* Input Field */}
                {inputType === 'policy' ? (
                  <div className="mb-8">
                    <label className="block text-white text-lg font-bold mb-4">IAM Policy JSON</label>
                    <textarea
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      placeholder='{\n  "Version": "2012-10-17",\n  "Statement": [{\n    "Effect": "Allow",\n    "Action": "s3:GetObject",\n    "Resource": "arn:aws:s3:::my-bucket/*"\n  }]\n}'
                      className="w-full h-64 px-6 py-5 bg-slate-800/50 border border-slate-600/50 rounded-2xl text-white placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none resize-none font-mono text-sm leading-relaxed transition-all duration-300"
                    />
                  </div>
                ) : (
                  <div className="mb-8">
                    <label className="block text-white text-lg font-bold mb-4">IAM Role ARN</label>
                    <input
                      type="text"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      placeholder="arn:aws:iam::123456789012:role/MyRole"
                      className="w-full px-6 py-5 bg-slate-800/50 border border-slate-600/50 rounded-2xl text-white placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none font-mono text-base transition-all duration-300"
                    />
                  </div>
                )}

                {/* Compliance Framework Selector */}
                <div className="mb-8">
                  <div className="flex items-center justify-between mb-4">
                    <label className="text-white text-lg font-bold">Compliance Frameworks</label>
                    <button
                      onClick={() => setShowFrameworkSelector(!showFrameworkSelector)}
                      className="text-purple-400 hover:text-purple-300 text-sm font-medium flex items-center space-x-1 transition-colors"
                    >
                      <Settings className="w-4 h-4" />
                      <span>{showFrameworkSelector ? 'Hide' : 'Customize'}</span>
                    </button>
                  </div>
                  
                  {!showFrameworkSelector ? (
                    <div className="flex flex-wrap gap-2">
                      {AVAILABLE_FRAMEWORKS.filter(f => selectedFrameworks.includes(f.id)).map(framework => (
                        <div key={framework.id} className="px-4 py-2 bg-purple-500/20 border border-purple-500/30 rounded-full text-purple-300 text-sm font-medium">
                          {framework.name}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {AVAILABLE_FRAMEWORKS.map(framework => (
                        <label
                          key={framework.id}
                          className={`flex items-start space-x-3 p-4 rounded-xl cursor-pointer transition-all duration-300 ${
                            selectedFrameworks.includes(framework.id)
                              ? 'bg-purple-500/20 border-2 border-purple-500/40'
                              : 'bg-slate-800/30 border-2 border-slate-700/30 hover:border-slate-600/50'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={selectedFrameworks.includes(framework.id)}
                            onChange={() => toggleFramework(framework.id)}
                            className="w-5 h-5 mt-0.5 bg-slate-700 border-slate-600 rounded text-purple-500 focus:ring-purple-500 cursor-pointer"
                          />
                          <div className="flex-1">
                            <div className="text-white font-semibold text-sm">{framework.name}</div>
                            <div className="text-slate-400 text-xs mt-0.5">{framework.description}</div>
                          </div>
                        </label>
                      ))}
                    </div>
                  )}
                </div>

                {/* Submit Button */}
                <button
                  onClick={handleValidation}
                  disabled={loading || !inputValue.trim()}
                  className="w-full bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 hover:from-orange-700 hover:via-pink-600 hover:to-purple-700 text-white py-5 px-8 rounded-2xl font-bold text-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-2xl shadow-purple-500/25 hover:shadow-purple-500/40 hover:scale-[1.02] flex items-center justify-center space-x-3 group"
                >
                  <Search className="w-6 h-6" />
                  <span>Analyze Security</span>
                  <Shield className="w-5 h-5 group-hover:rotate-12 transition-transform duration-300" />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ============================================ */}
        {/* LOADING STATE */}
        {/* ============================================ */}
        {loading && (
          <div className="relative min-h-screen flex items-center justify-center">
            <div className="text-center px-8 max-w-3xl">
              <div className="inline-flex items-center justify-center w-32 h-32 mb-10 relative">
                <div className="absolute inset-0 border-4 border-transparent border-t-purple-500 border-r-pink-500 rounded-full animate-spin"></div>
                <div className="absolute inset-2 border-4 border-transparent border-t-pink-500 border-r-orange-500 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '2s' }}></div>
                <div className="absolute inset-0 bg-gradient-to-br from-purple-500/20 via-pink-500/20 to-orange-500/20 rounded-full animate-ping"></div>
                <Shield className="w-16 h-16 text-purple-400 relative z-10 animate-pulse" />
              </div>
              
              <h2 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-orange-400 mb-4 animate-pulse leading-tight pb-2">
                Deep Security Scan
              </h2>
              
              <p className="text-2xl text-slate-300 mb-8 leading-relaxed font-medium max-w-2xl mx-auto">
                Analyzing your IAM policy for vulnerabilities and compliance issues...
              </p>
              
              <div className="flex flex-col items-center space-y-4 mb-10">
                <div className="flex items-center space-x-3 px-6 py-3 bg-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-full">
                  <div className="w-2 h-2 bg-purple-400 rounded-full animate-pulse"></div>
                  <span className="text-sm font-semibold text-slate-300">Checking security controls...</span>
                </div>
                <div className="flex items-center space-x-3 px-6 py-3 bg-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-full">
                  <div className="w-2 h-2 bg-pink-400 rounded-full animate-pulse" style={{ animationDelay: '0.5s' }}></div>
                  <span className="text-sm font-semibold text-slate-300">Validating compliance...</span>
                </div>
                <div className="flex items-center space-x-3 px-6 py-3 bg-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-full">
                  <div className="w-2 h-2 bg-orange-400 rounded-full animate-pulse" style={{ animationDelay: '1s' }}></div>
                  <span className="text-sm font-semibold text-slate-300">Calculating risk score...</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ============================================ */}
        {/* RESULTS */}
        {/* ============================================ */}
        {!loading && response && (
          <div className="relative">
            {/* Compact Header */}
            <div className="flex items-center justify-between mb-12">
              <div className="inline-flex items-center space-x-3 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 rounded-full px-6 py-3 backdrop-blur-xl">
                <CheckCircle className="w-5 h-5 text-cyan-400" />
                <span className="text-cyan-300 text-base font-semibold">Analysis Complete</span>
              </div>
              <button
                onClick={() => {
                  setResponse(null);
                  setInputValue('');
                  setShowInitialForm(true);
                  setEnhancementChat([]);
                  setExpandedFindings(new Set());
                }}
                className="group relative px-8 py-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white rounded-2xl transition-all duration-300 shadow-2xl shadow-purple-500/25 hover:shadow-purple-500/40 hover:scale-105 flex items-center space-x-3"
              >
                <RefreshCw className="w-5 h-5 group-hover:rotate-180 transition-transform duration-500" />
                <span className="font-bold text-lg">New Analysis</span>
              </button>
            </div>

            {/* PREMIUM SCORE DISPLAY - Modern Card Design */}
            <div className="mb-16 grid grid-cols-1 lg:grid-cols-3 gap-8">
              {/* LEFT: Main Score Card */}
              <div className="lg:col-span-2">
                <div className="relative bg-gradient-to-br from-slate-900/90 via-slate-800/90 to-slate-900/90 backdrop-blur-xl border-2 border-purple-500/30 rounded-3xl p-10 overflow-hidden shadow-2xl shadow-purple-500/10 animate-in fade-in slide-in-from-left duration-700">
                  {/* Animated gradient background */}
                  <div className="absolute top-0 right-0 w-[400px] h-[400px] bg-gradient-to-br from-orange-500/10 via-pink-500/10 to-purple-500/10 rounded-full blur-3xl animate-pulse"></div>
                  <div className="absolute bottom-0 left-0 w-[300px] h-[300px] bg-gradient-to-tr from-purple-500/10 to-pink-500/10 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
                  
                  <div className="relative z-10">
                    <div className="flex items-center justify-between mb-8">
                      <div>
                        <h3 className="text-slate-400 text-sm font-bold uppercase tracking-wider mb-2">Security Risk Score</h3>
                        <div className="flex items-baseline space-x-4">
                          <span className={`text-8xl font-black ${
                            response.risk_score <= 30 ? 'bg-gradient-to-r from-emerald-400 to-green-400 bg-clip-text text-transparent' :
                            response.risk_score <= 60 ? 'bg-gradient-to-r from-yellow-400 to-amber-400 bg-clip-text text-transparent' :
                            response.risk_score <= 80 ? 'bg-gradient-to-r from-orange-400 to-red-400 bg-clip-text text-transparent' :
                            'bg-gradient-to-r from-red-500 to-rose-500 bg-clip-text text-transparent'
                          }`}>
                            {response.risk_score}
                          </span>
                          <span className="text-3xl text-slate-500 font-bold">/100</span>
                        </div>
                      </div>
                      
                      {/* Grade Badge */}
                      <div className={`px-8 py-4 rounded-2xl font-black text-3xl shadow-2xl border-2 ${
                        response.risk_score <= 30 ? 'bg-gradient-to-br from-emerald-500/20 to-green-500/20 text-emerald-400 border-emerald-500/40' :
                        response.risk_score <= 60 ? 'bg-gradient-to-br from-yellow-500/20 to-amber-500/20 text-yellow-400 border-yellow-500/40' :
                        response.risk_score <= 80 ? 'bg-gradient-to-br from-orange-500/20 to-red-500/20 text-orange-400 border-orange-500/40' :
                        'bg-gradient-to-br from-red-500/20 to-rose-500/20 text-red-400 border-red-500/40'
                      }`}>
                        {getRiskGrade(response.risk_score).grade}
                      </div>
                    </div>

                    {/* Status Label */}
                    <div className="mb-6">
                      <div className={`inline-flex items-center space-x-2 px-5 py-2.5 rounded-full font-bold text-lg ${
                        response.risk_score <= 30 ? 'bg-emerald-500/20 text-emerald-300 border-2 border-emerald-500/40' :
                        response.risk_score <= 60 ? 'bg-yellow-500/20 text-yellow-300 border-2 border-yellow-500/40' :
                        response.risk_score <= 80 ? 'bg-orange-500/20 text-orange-300 border-2 border-orange-500/40' :
                        'bg-red-500/20 text-red-300 border-2 border-red-500/40'
                      }`}>
                        {response.risk_score <= 30 ? <CheckCircle className="w-5 h-5" /> :
                         response.risk_score <= 60 ? <AlertCircle className="w-5 h-5" /> :
                         response.risk_score <= 80 ? <AlertTriangle className="w-5 h-5" /> :
                         <XCircle className="w-5 h-5" />}
                        <span>{getRiskGrade(response.risk_score).label}</span>
                      </div>
                    </div>
                    
                    {/* Animated Progress Bar */}
                    <div className="mb-6">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm text-slate-400 font-semibold">Risk Level</span>
                        <span className="text-sm text-slate-400 font-semibold">{response.findings.length} {response.findings.length === 1 ? 'issue' : 'issues'} found</span>
                      </div>
                      <div className="w-full bg-slate-800/50 rounded-full h-3 overflow-hidden shadow-inner">
                        <div
                          className={`h-3 rounded-full transition-all duration-1000 shadow-lg ${
                            response.risk_score <= 30 ? 'bg-gradient-to-r from-emerald-500 to-green-400' :
                            response.risk_score <= 60 ? 'bg-gradient-to-r from-yellow-500 to-amber-400' :
                            response.risk_score <= 80 ? 'bg-gradient-to-r from-orange-500 to-red-400' :
                            'bg-gradient-to-r from-red-500 to-rose-500'
                          }`}
                          style={{ width: `${response.risk_score}%` }}
                        ></div>
                      </div>
                    </div>

                    {/* Quick Stats */}
                    <div className="grid grid-cols-2 gap-4">
                      <div className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-xl p-4">
                        <div className="text-purple-400 text-xs font-bold uppercase tracking-wider mb-1">Total Findings</div>
                        <div className="text-white text-3xl font-black">{response.findings.length}</div>
                      </div>
                      <div className="bg-gradient-to-br from-orange-500/10 to-pink-500/10 border border-orange-500/30 rounded-xl p-4">
                        <div className="text-orange-400 text-xs font-bold uppercase tracking-wider mb-1">Compliance Gaps</div>
                        <div className="text-white text-3xl font-black">
                          {Object.values(response.compliance_status || {}).filter((f: any) => f.status !== 'Compliant').length}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* RIGHT: Severity Breakdown */}
              <div className="space-y-4 animate-in fade-in slide-in-from-right duration-700" style={{ animationDelay: '0.2s' }}>
                {/* Critical */}
                <div className="bg-gradient-to-br from-red-500/10 to-rose-500/10 backdrop-blur-xl border-2 border-red-500/30 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-3">
                      <XCircle className="w-6 h-6 text-red-400" />
                      <span className="text-red-300 font-bold text-sm uppercase tracking-wide">Critical</span>
                    </div>
                    <span className="text-4xl font-black text-red-400">
                      {response.findings.filter(f => f.severity === 'Critical').length}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400">Immediate action required</div>
                </div>

                {/* High */}
                <div className="bg-gradient-to-br from-orange-500/10 to-amber-500/10 backdrop-blur-xl border-2 border-orange-500/30 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-3">
                      <AlertTriangle className="w-6 h-6 text-orange-400" />
                      <span className="text-orange-300 font-bold text-sm uppercase tracking-wide">High</span>
                    </div>
                    <span className="text-4xl font-black text-orange-400">
                      {response.findings.filter(f => f.severity === 'High').length}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400">High priority fixes</div>
                </div>

                {/* Medium */}
                <div className="bg-gradient-to-br from-yellow-500/10 to-amber-500/10 backdrop-blur-xl border-2 border-yellow-500/30 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-3">
                      <AlertCircle className="w-6 h-6 text-yellow-400" />
                      <span className="text-yellow-300 font-bold text-sm uppercase tracking-wide">Medium</span>
                    </div>
                    <span className="text-4xl font-black text-yellow-400">
                      {response.findings.filter(f => f.severity === 'Medium').length}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400">Should be addressed</div>
                </div>

                {/* Low */}
                <div className="bg-gradient-to-br from-slate-500/10 to-slate-600/10 backdrop-blur-xl border-2 border-slate-500/30 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-3">
                      <Info className="w-6 h-6 text-slate-400" />
                      <span className="text-slate-300 font-bold text-sm uppercase tracking-wide">Low</span>
                    </div>
                    <span className="text-4xl font-black text-slate-400">
                      {response.findings.filter(f => f.severity === 'Low').length}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400">Minor improvements</div>
                </div>
              </div>
            </div>

            {/* SCORE BREAKDOWN */}
            <div className="mb-16">
              <div className="relative z-10">

                  {/* Score Breakdown Expandable Section */}
                  <div className="mt-8">
                    <button
                      onClick={() => setShowScoreBreakdown(!showScoreBreakdown)}
                      className="w-full px-8 py-5 bg-gradient-to-r from-purple-500/10 to-pink-500/10 hover:from-purple-500/20 hover:to-pink-500/20 border-2 border-purple-500/30 hover:border-purple-500/50 rounded-2xl transition-all duration-300 flex items-center justify-between group"
                    >
                      <div className="flex items-center space-x-3">
                        <Info className="w-6 h-6 text-purple-400 group-hover:scale-110 transition-transform" />
                        <span className="text-purple-300 font-bold text-lg">Why score of {response.risk_score}/100?</span>
                      </div>
                      {showScoreBreakdown ? <ChevronUp className="w-6 h-6 text-purple-400" /> : <ChevronDown className="w-6 h-6 text-purple-400" />}
                    </button>

                    {showScoreBreakdown && (
                      <div className="mt-6 bg-gradient-to-br from-slate-950/80 to-slate-900/80 rounded-2xl p-8 border-2 border-slate-700/50 backdrop-blur-xl animate-in slide-in-from-top duration-300">
                        <p className="text-slate-300 text-lg leading-relaxed mb-8">
                          Your policy has the following issues contributing to this score:
                        </p>

                        {/* Critical Issues */}
                        {response.findings.filter(f => f.severity === 'Critical').length > 0 && (
                          <div className="mb-8">
                            <h5 className="text-red-400 font-bold mb-4 text-lg flex items-center space-x-2">
                              <XCircle className="w-5 h-5" />
                              <span>Critical Issues (Weight: -40 points each)</span>
                            </h5>
                            <ul className="space-y-3 text-slate-300 text-base">
                              {response.findings.filter(f => f.severity === 'Critical').map((finding, idx) => (
                                <li key={idx} className="flex items-start space-x-3">
                                  <span className="text-red-400 mt-1 text-lg">•</span>
                                  <span>{finding.title} - {finding.description}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* High Issues */}
                        {response.findings.filter(f => f.severity === 'High').length > 0 && (
                          <div className="mb-8">
                            <h5 className="text-orange-400 font-bold mb-4 text-lg flex items-center space-x-2">
                              <AlertTriangle className="w-5 h-5" />
                              <span>High Issues (Weight: -20 points each)</span>
                            </h5>
                            <ul className="space-y-3 text-slate-300 text-base">
                              {response.findings.filter(f => f.severity === 'High').map((finding, idx) => (
                                <li key={idx} className="flex items-start space-x-3">
                                  <span className="text-orange-400 mt-1 text-lg">•</span>
                                  <span>{finding.title} - {finding.description}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* Medium Issues */}
                        {response.findings.filter(f => f.severity === 'Medium').length > 0 && (
                          <div className="mb-8">
                            <h5 className="text-yellow-400 font-bold mb-4 text-lg flex items-center space-x-2">
                              <AlertCircle className="w-5 h-5" />
                              <span>Medium Issues (Weight: -10 points each)</span>
                            </h5>
                            <ul className="space-y-3 text-slate-300 text-base">
                              {response.findings.filter(f => f.severity === 'Medium').map((finding, idx) => (
                                <li key={idx} className="flex items-start space-x-3">
                                  <span className="text-yellow-400 mt-1 text-lg">•</span>
                                  <span>{finding.title}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* Score Calculation Info */}
                        <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border-2 border-purple-500/30 rounded-xl p-6">
                          <h5 className="text-purple-300 font-bold mb-3 text-lg">How the score is calculated:</h5>
                          <ul className="space-y-2 text-slate-400 text-base">
                            <li>• Base score starts at 100 (perfect security)</li>
                            <li>• Critical issues: -{response.findings.filter(f => f.severity === 'Critical').length * 40} points</li>
                            <li>• High issues: -{response.findings.filter(f => f.severity === 'High').length * 20} points</li>
                            <li>• Medium issues: -{response.findings.filter(f => f.severity === 'Medium').length * 10} points</li>
                            <li>• Low issues: -{response.findings.filter(f => f.severity === 'Low').length * 5} points</li>
                            <li className="pt-3 border-t border-slate-700/50">
                              <span className={`font-bold text-lg ${
                                response.risk_score <= 30 ? 'text-emerald-400' :
                                response.risk_score <= 60 ? 'text-yellow-400' :
                                response.risk_score <= 80 ? 'text-orange-400' :
                                'text-red-400'
                              }`}>
                                Final Score: {response.risk_score}/100 - {getRiskGrade(response.risk_score).label}
                              </span>
                            </li>
                          </ul>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

            {/* SECURITY FINDINGS - WITH INLINE EXPLANATIONS */}
            <div className="mb-16">
              <h3 className="text-white text-3xl font-black mb-8 flex items-center space-x-3">
                <Shield className="w-8 h-8 text-purple-400" />
                <span>Security Findings</span>
              </h3>
              
              {response.findings.length === 0 ? (
                <div className="bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border-2 border-cyan-500/30 rounded-2xl p-16 text-center backdrop-blur-xl">
                  <CheckCircle className="w-24 h-24 text-cyan-400 mx-auto mb-6" />
                  <h4 className="text-cyan-400 font-black text-3xl mb-3">Perfect Security Score!</h4>
                  <p className="text-slate-300 text-lg leading-relaxed">This policy follows all AWS security best practices.</p>
                </div>
              ) : (
                <div className="space-y-6">
                  {response.findings.map((finding, index) => {
                    const colors = getSeverityColor(finding.severity);
                    const isExpanded = expandedFindings.has(finding.id);
                    
                    return (
                      <div key={index} className={`bg-gradient-to-br ${colors.bg} backdrop-blur-xl border-2 ${colors.border} rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl transition-all duration-300`}>
                        <div className="p-8">
                          {/* Finding Header */}
                          <div className="flex items-start space-x-4 mb-4">
                            {/* CHANGE 4: Fixed icon colors */}
                            <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${colors.icon} border`}>
                              {finding.severity === 'Critical' ? <XCircle className="w-7 h-7 text-cyan-400" /> :
                               finding.severity === 'High' ? <AlertTriangle className="w-7 h-7 text-blue-400" /> :
                               finding.severity === 'Medium' ? <AlertCircle className="w-7 h-7 text-yellow-400" /> :
                               <Info className="w-7 h-7 text-slate-400" />}
                            </div>
                            <div className="flex-1">
                              <div className="flex items-center space-x-3 mb-2">
                                <h4 className="text-white font-bold text-xl">{finding.title}</h4>
                                {/* CHANGE 5: Fixed badge colors */}
                                <span className={`px-4 py-1.5 rounded-full text-sm font-bold shadow-lg ${
                                  finding.severity === 'Critical' ? 'bg-cyan-500/30 text-cyan-300 border border-cyan-500/50' :
                                  finding.severity === 'High' ? 'bg-blue-500/30 text-blue-300 border border-blue-500/50' :
                                  finding.severity === 'Medium' ? 'bg-yellow-500/30 text-yellow-300 border border-yellow-500/50' :
                                  'bg-slate-500/30 text-slate-300 border border-slate-500/50'
                                }`}>
                                  {finding.severity}
                                </span>
                                <span className="text-xs font-mono text-slate-500 bg-slate-800/50 px-3 py-1 rounded-full">{finding.id}</span>
                              </div>
                              <p className="text-slate-300 text-lg mb-6 leading-relaxed">
                                {finding.description}
                              </p>
                              
                              {/* Code Snippet */}
                              {finding.code_snippet && (
                                <div className="bg-slate-950/80 rounded-xl p-5 mb-6 border border-slate-700/50 shadow-lg">
                                  <div className="flex items-center justify-between mb-3">
                                    <span className="text-xs text-slate-500 font-bold uppercase tracking-wide">Problematic Code</span>
                                    <button className="text-slate-500 hover:text-slate-300 transition-colors">
                                      <Copy className="w-4 h-4" />
                                    </button>
                                  </div>
                                  <pre className="text-base text-cyan-300 font-mono leading-relaxed overflow-x-auto">
                                    {finding.code_snippet}
                                  </pre>
                                </div>
                              )}

                              {/* INLINE DETAILED EXPLANATION */}
                              <button
                                onClick={() => toggleFindingExpansion(finding.id)}
                                className="w-full mb-4 px-6 py-4 bg-purple-500/10 hover:bg-purple-500/20 border-2 border-purple-500/30 hover:border-purple-500/50 rounded-xl transition-all duration-300 flex items-center justify-between group"
                              >
                                <div className="flex items-center space-x-3">
                                  <Eye className="w-5 h-5 text-purple-400 group-hover:scale-110 transition-transform" />
                                  <span className="text-purple-300 font-bold text-base">
                                    {isExpanded ? 'Hide' : 'Show'} Detailed Explanation
                                  </span>
                                </div>
                                {isExpanded ? <ChevronUp className="w-5 h-5 text-purple-400" /> : <ChevronDown className="w-5 h-5 text-purple-400" />}
                              </button>

                              {isExpanded && (
                                <div className="mb-6 bg-slate-950/60 rounded-2xl p-8 border-2 border-slate-700/50 backdrop-blur-xl animate-in slide-in-from-top duration-300">
                                  <h5 className="text-white font-bold text-lg mb-4 flex items-center space-x-2">
                                    <Info className="w-5 h-5 text-purple-400" />
                                    <span>Why This Matters</span>
                                  </h5>
                                  <div className="space-y-4 text-slate-300 text-base leading-relaxed">
                                    {finding.detailed_explanation ? (
                                      <div dangerouslySetInnerHTML={{ __html: finding.detailed_explanation.replace(/\n/g, '<br/>') }} />
                                    ) : (
                                      <>
                                        <p>
                                          This security issue was detected because {finding.description.toLowerCase()}. 
                                          Here's what you need to know:
                                        </p>
                                        <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border-l-4 border-cyan-500/50 rounded-r-xl p-4">
                                          <div className="font-bold text-cyan-400 mb-2">Security Impact:</div>
                                          <p className="text-slate-300">
                                            {finding.severity === 'Critical' && "This represents an immediate and severe security risk that could lead to complete account compromise. Attackers could gain full control over all AWS resources."}
                                            {finding.severity === 'High' && "This poses a significant security risk that could result in unauthorized access to sensitive resources or data exposure."}
                                            {finding.severity === 'Medium' && "This creates a moderate security gap that violates the principle of least privilege and increases your attack surface."}
                                            {finding.severity === 'Low' && "While not immediately critical, this represents a security best practice violation that should be addressed."}
                                          </p>
                                        </div>
                                        <div className="bg-gradient-to-r from-orange-500/10 via-pink-500/10 to-purple-500/10 border-l-4 border-pink-500/50 rounded-r-xl p-4">
                                          <div className="font-bold text-pink-400 mb-2 flex items-center space-x-2">
                                            <AlertTriangle className="w-4 h-4" />
                                            <span>Real-World Attack Scenario:</span>
                                          </div>
                                          <p className="text-slate-300">
                                            {finding.type === 'wildcard' ? 
                                              "If an attacker gained access to credentials with these permissions, they could read, modify, or delete ANY data in your account - including production databases, S3 buckets with customer data, and critical infrastructure. This is equivalent to giving someone the master key to your entire AWS environment." :
                                            finding.type === 'overly_broad' ? 
                                              "An attacker exploiting this could escalate privileges, access resources they shouldn't have permission to, or perform destructive operations. For example, they could create new admin users, delete security logs, or exfiltrate sensitive data." :
                                            finding.type === 'missing_condition' ? 
                                              "Without proper conditions, these permissions could be used from any location, at any time, by anyone who gains access to the credentials - even temporarily. An attacker from anywhere in the world could abuse these permissions without MFA or IP restrictions." :
                                            finding.severity === 'Critical' ?
                                              "This vulnerability could allow an attacker to gain complete control over your AWS account, potentially leading to data breaches, service disruptions, and significant financial losses. Real-world attacks exploiting similar issues have resulted in millions of dollars in damages." :
                                            finding.severity === 'High' ?
                                              "Attackers could exploit this to access sensitive data, modify critical resources, or disrupt services. Similar vulnerabilities have been used in real breaches to steal customer data and compromise production systems." :
                                            "While not immediately exploitable, this weakness could be chained with other vulnerabilities to escalate an attack. Security best practices recommend addressing all identified issues to maintain a strong security posture."}
                                          </p>
                                        </div>
                                      </>
                                    )}
                                  </div>
                                </div>
                              )}
                              
                              {/* Recommendation */}
                              <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border-2 border-purple-500/30 rounded-xl p-6 shadow-lg">
                                <div className="flex items-start space-x-3">
                                  <Sparkles className="w-6 h-6 text-purple-400 mt-0.5 flex-shrink-0" />
                                  <div className="flex-1">
                                    <div className="text-purple-300 font-bold text-base mb-2">How to Fix This</div>
                                    <p className="text-slate-300 text-base leading-relaxed">{finding.recommendation}</p>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* CHANGE 6: COMPLIANCE STATUS with full violations handling */}
            {response.compliance_status && Object.keys(response.compliance_status).length > 0 && (
              <div className="mb-16">
                <h3 className="text-white text-3xl font-black mb-8 flex items-center space-x-3">
                  <CheckCircle className="w-8 h-8 text-cyan-400" />
                  <span>Compliance Status</span>
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {Object.entries(response.compliance_status).map(([key, framework]: [string, any]) => {
                    if (framework.status === 'Compliant') return null;
                    return (
                      <div key={key} className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-cyan-500/30 rounded-2xl p-6">
                        <div className="flex items-center justify-between mb-4">
                          <h4 className="text-white font-bold text-lg">{framework.name}</h4>
                          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-cyan-500/20 text-cyan-400">
                            {framework.status}
                          </span>
                        </div>
                        
                        {/* Full violations handling */}
                        {framework.violations && framework.violations.length > 0 && (
                          <div className="space-y-4">
                            {framework.violations.map((violation: any, idx: number) => (
                              <div key={idx} className="bg-slate-950/50 rounded-xl p-4 border border-slate-700/50">
                                <div className="text-cyan-400 font-semibold text-sm mb-2">{violation.requirement}</div>
                                <p className="text-slate-400 text-sm mb-3 leading-relaxed">{violation.description}</p>
                                <div className="bg-purple-500/5 border border-purple-500/20 rounded-lg p-3">
                                  <div className="text-purple-400 text-xs font-semibold mb-1">How to Fix:</div>
                                  <p className="text-slate-300 text-sm">{violation.fix}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                        
                        {/* Fallback to gaps if no violations */}
                        {(!framework.violations || framework.violations.length === 0) && framework.gaps && (
                          <div className="text-slate-400 text-sm">
                            {framework.gaps.map((gap: string, idx: number) => (
                              <p key={idx} className="mb-2">• {gap}</p>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}


            {/* REFINE YOUR POLICY - AI-POWERED ACTIONS */}
            <div className="mb-16">
              <div className="bg-gradient-to-br from-orange-500/10 via-pink-500/10 to-purple-500/10 backdrop-blur-xl border-2 border-orange-500/30 rounded-2xl p-8 shadow-xl">
                <div className="flex items-center space-x-3 mb-6">
                  <Sparkles className="w-7 h-7 text-orange-400" />
                  <h4 className="text-orange-400 text-2xl font-black">Refine Your Policy with AI</h4>
                </div>
                <p className="text-slate-300 text-base mb-6 leading-relaxed">
                  Use the <strong className="text-white">Aegis AI Assistant</strong> (bottom right) to automatically fix security issues and improve your policy:
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-gradient-to-br from-red-500/10 to-orange-500/10 border-2 border-red-500/30 rounded-xl p-5 hover:scale-105 transition-all duration-300">
                    <div className="flex items-center space-x-2 mb-2">
                      <XCircle className="w-5 h-5 text-red-400" />
                      <span className="text-red-300 font-bold text-sm">Fix Critical Issues</span>
                    </div>
                    <p className="text-slate-400 text-xs">Remove wildcards, add resource restrictions, enforce MFA</p>
                  </div>
                  <div className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 border-2 border-purple-500/30 rounded-xl p-5 hover:scale-105 transition-all duration-300">
                    <div className="flex items-center space-x-2 mb-2">
                      <Shield className="w-5 h-5 text-purple-400" />
                      <span className="text-purple-300 font-bold text-sm">Add Security Controls</span>
                    </div>
                    <p className="text-slate-400 text-xs">IP restrictions, time-based access, encryption requirements</p>
                  </div>
                  <div className="bg-gradient-to-br from-blue-500/10 to-cyan-500/10 border-2 border-blue-500/30 rounded-xl p-5 hover:scale-105 transition-all duration-300">
                    <div className="flex items-center space-x-2 mb-2">
                      <Target className="w-5 h-5 text-blue-400" />
                      <span className="text-blue-300 font-bold text-sm">Principle of Least Privilege</span>
                    </div>
                    <p className="text-slate-400 text-xs">Minimize permissions to only what's needed</p>
                  </div>
                  <div className="bg-gradient-to-br from-yellow-500/10 to-amber-500/10 border-2 border-yellow-500/30 rounded-xl p-5 hover:scale-105 transition-all duration-300">
                    <div className="flex items-center space-x-2 mb-2">
                      <CheckCircle className="w-5 h-5 text-yellow-400" />
                      <span className="text-yellow-300 font-bold text-sm">Compliance Alignment</span>
                    </div>
                    <p className="text-slate-400 text-xs">Meet PCI DSS, HIPAA, SOX, GDPR requirements</p>
                  </div>
                </div>
              </div>
            </div>

            {/* EXPORT ANALYSIS REPORT */}
            <div className="mb-16">
              <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border-2 border-slate-700/50 rounded-2xl p-8 shadow-xl">
                <h4 className="text-white text-2xl font-black mb-6 flex items-center space-x-3">
                  <Download className="w-7 h-7 text-slate-400" />
                  <span>Export Analysis Report</span>
                </h4>
                <div className="flex flex-wrap gap-4">
                  <button 
                    onClick={() => {
                      const dataStr = JSON.stringify(response, null, 2);
                      const dataBlob = new Blob([dataStr], { type: 'application/json' });
                      const url = URL.createObjectURL(dataBlob);
                      const link = document.createElement('a');
                      link.href = url;
                      link.download = `aegis-security-analysis-${new Date().toISOString().split('T')[0]}.json`;
                      link.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="group px-6 py-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 rounded-xl text-white font-bold transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105 flex items-center space-x-3"
                  >
                    <Download className="w-5 h-5 group-hover:translate-y-0.5 transition-transform" />
                    <span>Download JSON</span>
                  </button>
                  <button 
                    onClick={() => {
                      const reportText = `
AEGIS IAM SECURITY ANALYSIS REPORT
Generated: ${new Date().toLocaleString()}
================================

RISK SCORE: ${response.risk_score}/100 - ${getRiskGrade(response.risk_score).label}

FINDINGS SUMMARY:
- Critical: ${response.findings.filter(f => f.severity === 'Critical').length}
- High: ${response.findings.filter(f => f.severity === 'High').length}
- Medium: ${response.findings.filter(f => f.severity === 'Medium').length}
- Low: ${response.findings.filter(f => f.severity === 'Low').length}

DETAILED FINDINGS:
${response.findings.map((f, i) => `
${i + 1}. [${f.severity}] ${f.title}
   ID: ${f.id}
   Description: ${f.description}
   Recommendation: ${f.recommendation}
`).join('\n')}

QUICK WINS:
${response.quick_wins?.map((w, i) => `${i + 1}. ${w}`).join('\n') || 'None'}

RECOMMENDATIONS:
${response.recommendations?.map((r, i) => `${i + 1}. ${r}`).join('\n') || 'None'}
                      `.trim();
                      navigator.clipboard.writeText(reportText);
                      alert('Report copied to clipboard!');
                    }}
                    className="group px-6 py-4 bg-slate-700 hover:bg-slate-600 rounded-xl text-white font-bold transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105 flex items-center space-x-3"
                  >
                    <Copy className="w-5 h-5 group-hover:scale-110 transition-transform" />
                    <span>Copy Report</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* FLOATING CHATBOT WIDGET */}
        {!loading && response && (
          <div className="fixed bottom-6 right-6 z-50">
            {!isChatbotOpen && (
              <button
                onClick={() => setIsChatbotOpen(true)}
                className="group relative w-20 h-20 bg-gradient-to-br from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 rounded-full shadow-2xl shadow-purple-500/50 hover:shadow-purple-500/70 transition-all duration-300 hover:scale-110 flex items-center justify-center animate-bounce hover:animate-none"
              >
                <Bot className="w-10 h-10 text-white" />
                <div className="absolute -top-1 -right-1 w-5 h-5 bg-cyan-400 rounded-full border-4 border-slate-950 animate-pulse"></div>
              </button>
            )}

            {isChatbotOpen && (
              <div className={`${isChatbotExpanded ? 'w-[90vw] h-[90vh]' : 'w-[480px] h-[700px]'} bg-gradient-to-br from-slate-900/95 via-slate-950/95 to-slate-900/95 backdrop-blur-xl border-2 border-purple-500/30 rounded-2xl shadow-2xl shadow-purple-500/20 flex flex-col overflow-hidden transition-all duration-300`}>
                {/* Chatbot Header - REDESIGNED */}
                <div className="p-6 bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-purple-500/10 border-b-2 border-purple-500/30 flex items-center justify-between backdrop-blur-xl">
                  <div className="flex items-center space-x-4">
                    <div className="relative">
                      <div className="absolute inset-0 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full blur-lg opacity-50 animate-pulse"></div>
                      <div className="relative w-14 h-14 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full flex items-center justify-center shadow-lg">
                        <Bot className="w-7 h-7 text-white" />
                      </div>
                    </div>
                    <div>
                      <h3 className="text-white font-black text-lg">Aegis AI Assistant</h3>
                      <div className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></div>
                        <p className="text-sm text-slate-400">Ready to help</p>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => setIsChatbotExpanded(!isChatbotExpanded)}
                      className="text-slate-400 hover:text-white transition-colors duration-300 p-2.5 hover:bg-slate-800/50 rounded-xl"
                    >
                      {isChatbotExpanded ? <Minimize2 className="w-5 h-5" /> : <Maximize2 className="w-5 h-5" />}
                    </button>
                    <button
                      onClick={() => setIsChatbotOpen(false)}
                      className="text-slate-400 hover:text-white transition-colors duration-300 p-2.5 hover:bg-slate-800/50 rounded-xl"
                    >
                      <X className="w-5 h-5" />
                    </button>
                  </div>
                </div>

                {/* Chat Messages - REDESIGNED */}
                <div className="flex-1 overflow-y-auto p-6 space-y-6">
                  {enhancementChat.map((msg, idx) => (
                    <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'} animate-in slide-in-from-bottom duration-300`}>
                      <div className={`max-w-[85%] ${
                        msg.role === 'user' 
                          ? 'bg-gradient-to-br from-purple-500/20 to-pink-500/20 border-2 border-purple-500/30' 
                          : 'bg-gradient-to-br from-slate-800/80 to-slate-900/80 border-2 border-slate-700/50'
                      } rounded-2xl p-5 shadow-xl backdrop-blur-xl`}>
                        {msg.role === 'assistant' && (
                          <div className="flex items-center space-x-2 mb-3">
                            <div className="w-6 h-6 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full flex items-center justify-center">
                              <Bot className="w-3.5 h-3.5 text-white" />
                            </div>
                            <span className="text-xs font-bold text-purple-400 uppercase tracking-wide">Aegis AI</span>
                          </div>
                        )}
                        {msg.role === 'user' && (
                          <div className="flex items-center justify-end space-x-2 mb-3">
                            <span className="text-xs font-bold text-purple-300 uppercase tracking-wide">You</span>
                          </div>
                        )}
                        <p className="text-slate-200 text-base leading-relaxed whitespace-pre-wrap">{msg.content}</p>
                      </div>
                    </div>
                  ))}
                  
                  {enhancementLoading && (
                    <div className="flex justify-start animate-in slide-in-from-bottom duration-300">
                      <div className="max-w-[85%] bg-gradient-to-br from-slate-800/80 to-slate-900/80 border-2 border-slate-700/50 rounded-2xl p-5 shadow-xl">
                        <div className="flex items-center space-x-3">
                          <div className="w-6 h-6 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full flex items-center justify-center">
                            <Bot className="w-3.5 h-3.5 text-white" />
                          </div>
                          <div className="flex items-center space-x-2">
                            <div className="flex space-x-1">
                              <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce"></div>
                              <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                              <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
                            </div>
                            <span className="text-sm text-slate-400 font-medium">Thinking...</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                  
                  <div ref={chatEndRef} />
                </div>

                {/* Chat Input - REDESIGNED */}
                <div className="p-6 border-t-2 border-purple-500/30 bg-gradient-to-br from-slate-900/50 to-slate-950/50 backdrop-blur-xl">
                  {/* Quick Actions - REDESIGNED */}
                  <div className="mb-4 p-5 bg-gradient-to-br from-orange-500/10 via-pink-500/10 to-purple-500/10 rounded-xl border-2 border-purple-500/30 backdrop-blur-xl">
                    <p className="text-purple-300 font-semibold text-sm mb-3 flex items-center space-x-2">
                      <Zap className="w-4 h-4" />
                      <span>Quick Actions:</span>
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <button 
                        onClick={() => setEnhancementInput('Fix all critical issues')}
                        className="group px-4 py-2.5 bg-gradient-to-r from-red-500/20 to-orange-500/20 hover:from-red-500/30 hover:to-orange-500/30 border-2 border-red-500/40 hover:border-red-500/60 rounded-xl text-red-300 hover:text-white text-xs font-semibold transition-all hover:scale-105 shadow-lg"
                      >
                        <span>🔥 Fix Critical Issues</span>
                      </button>
                      <button 
                        onClick={() => setEnhancementInput('Add MFA requirement for all actions')}
                        className="group px-4 py-2.5 bg-gradient-to-r from-purple-500/20 to-pink-500/20 hover:from-purple-500/30 hover:to-pink-500/30 border-2 border-purple-500/40 hover:border-purple-500/60 rounded-xl text-purple-300 hover:text-white text-xs font-semibold transition-all hover:scale-105 shadow-lg"
                      >
                        <span>🔒 Add MFA</span>
                      </button>
                      <button 
                        onClick={() => setEnhancementInput('Replace wildcards with specific permissions')}
                        className="group px-4 py-2.5 bg-gradient-to-r from-yellow-500/20 to-amber-500/20 hover:from-yellow-500/30 hover:to-amber-500/30 border-2 border-yellow-500/40 hover:border-yellow-500/60 rounded-xl text-yellow-300 hover:text-white text-xs font-semibold transition-all hover:scale-105 shadow-lg"
                      >
                        <span>✨ Remove Wildcards</span>
                      </button>
                      <button 
                        onClick={() => setEnhancementInput('Add IP address restrictions')}
                        className="group px-4 py-2.5 bg-gradient-to-r from-blue-500/20 to-cyan-500/20 hover:from-blue-500/30 hover:to-cyan-500/30 border-2 border-blue-500/40 hover:border-blue-500/60 rounded-xl text-blue-300 hover:text-white text-xs font-semibold transition-all hover:scale-105 shadow-lg"
                      >
                        <span>🌍 IP Restrictions</span>
                      </button>
                    </div>
                  </div>

                  <form onSubmit={handleEnhancementSubmit} className="space-y-3">
                    <textarea
                      value={enhancementInput}
                      onChange={(e) => setEnhancementInput(e.target.value)}
                      placeholder="Ask me to fix issues, explain findings, add security controls..."
                      className="w-full h-24 px-4 py-3 bg-slate-800/50 border-2 border-slate-700/50 focus:border-purple-500/50 rounded-xl text-white text-base placeholder-slate-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none resize-none transition-all duration-300"
                      disabled={enhancementLoading}
                    />
                    
                    <button
                      type="submit"
                      disabled={enhancementLoading || !enhancementInput.trim()}
                      className="w-full bg-gradient-to-r from-purple-600 via-pink-500 to-purple-600 hover:from-purple-500 hover:via-pink-400 hover:to-purple-500 text-white py-4 px-6 rounded-xl font-bold text-base disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-xl shadow-purple-500/25 hover:shadow-purple-500/40 flex items-center justify-center space-x-2 hover:scale-[1.02]"
                    >
                      {enhancementLoading ? (
                        <>
                          <RefreshCw className="w-5 h-5 animate-spin" />
                          <span>Processing...</span>
                        </>
                      ) : (
                        <>
                          <Send className="w-5 h-5" />
                          <span>Send Message</span>
                        </>
                      )}
                    </button>
                  </form>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ValidatePolicy;