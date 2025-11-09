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
  const [showScoreBreakdown, setShowScoreBreakdown] = useState(true); // Expanded by default
  
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

**Your Policy Assessment:**
• Risk Score: **${data.risk_score}/100** (${getRiskGrade(data.risk_score).label})
• Total Findings: **${data.findings.length}** security ${data.findings.length === 1 ? 'issue' : 'issues'}
• Critical: **${data.findings.filter((f: SecurityFinding) => f.severity === 'Critical').length}** | High: **${data.findings.filter((f: SecurityFinding) => f.severity === 'High').length}** | Medium: **${data.findings.filter((f: SecurityFinding) => f.severity === 'Medium').length}** | Low: **${data.findings.filter((f: SecurityFinding) => f.severity === 'Low').length}**

**I can help you:**

• **"Fix all critical issues"** - Automatically remediate high-risk vulnerabilities
• **"Add MFA requirement"** - Enforce multi-factor authentication
• **"Remove wildcards"** - Replace * with specific permissions
• **"Add IP restrictions"** - Limit access by source IP
• **"Rewrite this policy"** - Generate a secure version from scratch
• **"Explain finding IAM-001"** - Get detailed explanations

**Try one of the quick actions below or ask me anything!**`,
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

  // Premium Light Theme - getSeverityColor
  const getSeverityColor = (severity: SecurityFinding['severity']) => {
    switch (severity) {
      case 'Critical': return { 
        bg: 'bg-white/80', 
        border: 'border-red-200/50', 
        icon: 'bg-red-500/10 border-red-200/50', 
        text: 'text-red-600',
        badge: 'bg-red-500/10 text-red-700 border-red-200/50'
      };
      case 'High': return { 
        bg: 'bg-white/80', 
        border: 'border-orange-200/50', 
        icon: 'bg-orange-500/10 border-orange-200/50', 
        text: 'text-orange-600',
        badge: 'bg-orange-500/10 text-orange-700 border-orange-200/50'
      };
      case 'Medium': return { 
        bg: 'bg-white/80', 
        border: 'border-yellow-200/50', 
        icon: 'bg-yellow-500/10 border-yellow-200/50', 
        text: 'text-yellow-600',
        badge: 'bg-yellow-500/10 text-yellow-700 border-yellow-200/50'
      };
      case 'Low': return { 
        bg: 'bg-white/80', 
        border: 'border-slate-200/50', 
        icon: 'bg-slate-500/10 border-slate-200/50', 
        text: 'text-slate-600',
        badge: 'bg-slate-500/10 text-slate-700 border-slate-200/50'
      };
    }
  };

  // Get dynamic impact description - Only use backend-provided detailed_explanation
  // No hardcoded scenarios or fear-mongering - let backend AI generate context-appropriate explanations
  const getSpecificImpact = (finding: SecurityFinding) => {
    // Only show detailed explanation if backend provides it
    // This ensures explanations are dynamic, specific to the finding, and context-appropriate
    if (finding.detailed_explanation && finding.detailed_explanation.trim().length > 0) {
      return {
        impact: finding.detailed_explanation,
        hasExplanation: true
      };
    }
    
    // If no detailed explanation from backend, don't show impact sections
    // The finding description is already shown above and is specific enough
    return null;
  };

  return (
    <div className="min-h-screen relative overflow-hidden">
      {/* Premium Animated Background - Light Theme */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 right-0 w-[800px] h-[800px] bg-gradient-to-br from-blue-400/8 via-purple-400/6 to-pink-400/4 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 left-0 w-[700px] h-[700px] bg-gradient-to-tr from-amber-400/6 via-orange-400/4 to-red-400/3 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '2s' }}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-br from-emerald-400/5 via-cyan-400/4 to-blue-400/3 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '4s' }}></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-8 py-12 sm:py-20">
        {/* ============================================ */}
        {/* INITIAL FORM */}
        {/* ============================================ */}
        {showInitialForm && !response && (
          <div className="relative">
            {/* Hero Section */}
            <div className="mb-16 animate-fadeIn text-center">
              <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-200 rounded-full px-6 py-2 mb-6 backdrop-blur-sm">
                <Shield className="w-4 h-4 text-blue-600" />
                <span className="text-blue-700 text-sm font-semibold">AI-Powered Security Analysis</span>
              </div>
              
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent mb-4 sm:mb-6 leading-tight tracking-tight px-4">
                Validate IAM<br />
                <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
                  Security Policies
                </span>
              </h1>
              
              <p className="text-base sm:text-lg lg:text-xl text-slate-600 max-w-3xl mx-auto leading-relaxed font-medium px-4">
                Deep security analysis powered by AI agents. Get instant risk assessment, 
                compliance validation, and actionable recommendations.
              </p>
            </div>

            {/* Main Input Form */}
            <div className="max-w-4xl mx-auto">
              <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-xl">
                {/* Input Type Selection */}
                <div className="mb-8">
                  <label className="block text-slate-900 text-lg font-bold mb-4">What would you like to validate?</label>
                  <div className="grid grid-cols-2 gap-4">
                    <button
                      onClick={() => setInputType('policy')}
                      className={`group px-6 py-6 rounded-2xl font-bold transition-all duration-300 ${
                        inputType === 'policy'
                          ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg hover:shadow-xl'
                          : 'bg-gradient-to-br from-white to-slate-50 text-slate-600 hover:text-slate-900 border-2 border-slate-200 hover:border-blue-300 hover:shadow-md'
                      }`}
                    >
                      <Shield className="w-8 h-8 mx-auto mb-2 group-hover:scale-110 transition-transform duration-300" />
                      <span className="block text-base">Policy JSON</span>
                      <span className="block text-xs opacity-75 mt-1">Paste your IAM policy</span>
                    </button>
                    <button
                      onClick={() => setInputType('arn')}
                      className={`group px-6 py-6 rounded-2xl font-bold transition-all duration-300 ${
                        inputType === 'arn'
                          ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg hover:shadow-xl'
                          : 'bg-gradient-to-br from-white to-slate-50 text-slate-600 hover:text-slate-900 border-2 border-slate-200 hover:border-blue-300 hover:shadow-md'
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
                    <label className="block text-slate-900 text-lg font-bold mb-4">IAM Policy JSON</label>
                    <textarea
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      placeholder='{\n  "Version": "2012-10-17",\n  "Statement": [{\n    "Effect": "Allow",\n    "Action": "s3:GetObject",\n    "Resource": "arn:aws:s3:::my-bucket/*"\n  }]\n}'
                      className="w-full h-64 px-6 py-5 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-2xl text-slate-900 placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none resize-none font-mono text-sm leading-relaxed transition-all duration-300"
                    />
                  </div>
                ) : (
                  <div className="mb-8">
                    <label className="block text-slate-900 text-lg font-bold mb-4">IAM Role ARN</label>
                    <input
                      type="text"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      placeholder="arn:aws:iam::123456789012:role/MyRole"
                      className="w-full px-6 py-5 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-2xl text-slate-900 placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none font-mono text-base transition-all duration-300 shadow-sm"
                    />
                  </div>
                )}

                {/* Compliance Framework Selector */}
                <div className="mb-8">
                  <div className="flex items-center justify-between mb-4">
                    <label className="text-slate-900 text-lg font-bold">Compliance Frameworks</label>
                    <button
                      onClick={() => setShowFrameworkSelector(!showFrameworkSelector)}
                      className="text-blue-600 hover:text-blue-700 text-sm font-semibold flex items-center space-x-1 transition-colors"
                    >
                      <Settings className="w-4 h-4" />
                      <span>{showFrameworkSelector ? 'Hide' : 'Customize'}</span>
                    </button>
                  </div>
                  
                  {!showFrameworkSelector ? (
                    <div className="flex flex-wrap gap-2">
                      {AVAILABLE_FRAMEWORKS.filter(f => selectedFrameworks.includes(f.id)).map(framework => (
                        <div key={framework.id} className="px-4 py-2 bg-gradient-to-r from-blue-100 to-purple-100 border-2 border-blue-300 rounded-full text-blue-700 text-sm font-semibold">
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
                              ? 'bg-gradient-to-r from-blue-50 to-purple-50 border-2 border-blue-400'
                              : 'bg-gradient-to-br from-white to-slate-50 border-2 border-slate-200 hover:border-blue-300'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={selectedFrameworks.includes(framework.id)}
                            onChange={() => toggleFramework(framework.id)}
                            className="w-5 h-5 mt-0.5 rounded-md border-2 border-slate-300 bg-white text-blue-600 focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 cursor-pointer transition-all hover:border-blue-400 checked:bg-blue-600 checked:border-blue-600"
                          />
                          <div className="flex-1">
                            <div className="text-slate-900 font-bold text-sm">{framework.name}</div>
                            <div className="text-slate-600 text-xs mt-0.5 font-medium">{framework.description}</div>
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
                  className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white py-4 sm:py-5 px-6 sm:px-8 rounded-2xl font-bold text-base sm:text-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-[1.02] flex items-center justify-center space-x-3 group transform touch-manipulation"
                  style={{ minHeight: '44px' }}
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
                <div className="absolute inset-0 border-4 border-transparent border-t-blue-500 border-r-purple-500 rounded-full animate-spin"></div>
                <div className="absolute inset-2 border-4 border-transparent border-t-purple-500 border-r-pink-500 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '2s' }}></div>
                <div className="absolute inset-0 bg-gradient-to-br from-blue-500/20 via-purple-500/20 to-pink-500/20 rounded-full animate-ping"></div>
                <Shield className="w-16 h-16 text-blue-600 relative z-10 animate-pulse" />
              </div>
              
              <h2 className="text-6xl font-extrabold bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent mb-4 animate-pulse leading-tight pb-2">
                Deep Security Scan
              </h2>
              
              <p className="text-2xl text-slate-700 mb-8 leading-relaxed font-semibold max-w-2xl mx-auto">
                Analyzing your IAM policy for vulnerabilities and compliance issues...
              </p>
              
              <div className="flex flex-col items-center space-y-4 mb-10">
                <div className="flex items-center space-x-3 px-6 py-3 bg-white/80 backdrop-blur-xl border-2 border-blue-200 rounded-full shadow-lg">
                  <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
                  <span className="text-sm font-semibold text-slate-700">Checking security controls...</span>
                </div>
                <div className="flex items-center space-x-3 px-6 py-3 bg-white/80 backdrop-blur-xl border-2 border-purple-200 rounded-full shadow-lg">
                  <div className="w-2 h-2 bg-purple-500 rounded-full animate-pulse" style={{ animationDelay: '0.5s' }}></div>
                  <span className="text-sm font-semibold text-slate-700">Validating compliance...</span>
                </div>
                <div className="flex items-center space-x-3 px-6 py-3 bg-white/80 backdrop-blur-xl border-2 border-pink-200 rounded-full shadow-lg">
                  <div className="w-2 h-2 bg-pink-500 rounded-full animate-pulse" style={{ animationDelay: '1s' }}></div>
                  <span className="text-sm font-semibold text-slate-700">Calculating risk score...</span>
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
            {/* Premium Header - Matching Audit Account */}
            <div className="flex flex-col items-center justify-center mb-16 animate-fadeIn">
              <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-200 rounded-full px-4 py-1.5 mb-6 backdrop-blur-sm">
                <Shield className="w-4 h-4 text-blue-600" />
                <span className="text-blue-700 text-sm font-semibold">Security Analysis Complete</span>
              </div>
              <h1 className="text-6xl font-extrabold bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent mb-4 tracking-tight leading-tight text-center">
                Policy Validation Results
              </h1>
              <div className="w-32 h-1.5 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 mx-auto rounded-full mb-8 shadow-lg"></div>
              <div className="flex items-center justify-center gap-4">
                <button
                  onClick={() => {
                    setResponse(null);
                    setInputValue('');
                    setShowInitialForm(true);
                    setEnhancementChat([]);
                    setExpandedFindings(new Set());
                  }}
                  className="group relative px-6 py-3 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white rounded-xl transition-all duration-300 shadow-xl hover:shadow-2xl hover:scale-105 flex items-center space-x-2"
                >
                  <RefreshCw className="w-4 h-4 group-hover:rotate-180 transition-transform duration-500" />
                  <span className="font-bold">New Analysis</span>
                </button>
              </div>
            </div>

            {/* PREMIUM SECURITY RISK SCORE - Matching Audit Account Design */}
            {(() => {
              const riskScore = response.risk_score || 0;
              const grade = getRiskGrade(riskScore);
              
              // Color scheme based on score
              const getScoreColors = (score: number) => {
                if (score <= 30) {
                  return {
                    bg: 'from-emerald-50 to-green-50',
                    border: 'border-emerald-300',
                    scoreGradient: 'from-emerald-500 to-green-500',
                    scoreText: 'text-emerald-600',
                    badge: 'from-emerald-500/20 to-green-500/20 text-emerald-600 border-emerald-500/40',
                    status: 'bg-emerald-100 text-emerald-800'
                  };
                } else if (score <= 60) {
                  return {
                    bg: 'from-blue-50 to-cyan-50',
                    border: 'border-blue-300',
                    scoreGradient: 'from-blue-500 to-cyan-500',
                    scoreText: 'text-blue-600',
                    badge: 'from-blue-500/20 to-cyan-500/20 text-blue-600 border-blue-500/40',
                    status: 'bg-blue-100 text-blue-800'
                  };
                } else if (score <= 80) {
                  return {
                    bg: 'from-amber-50 to-orange-50',
                    border: 'border-amber-300',
                    scoreGradient: 'from-amber-500 to-orange-500',
                    scoreText: 'text-amber-600',
                    badge: 'from-amber-500/20 to-orange-500/20 text-amber-600 border-amber-500/40',
                    status: 'bg-amber-100 text-amber-800'
                  };
                } else {
                  return {
                    bg: 'from-red-50 to-rose-50',
                    border: 'border-red-300',
                    scoreGradient: 'from-red-500 to-rose-500',
                    scoreText: 'text-red-600',
                    badge: 'from-red-500/20 to-rose-500/20 text-red-600 border-red-500/40',
                    status: 'bg-red-100 text-red-800'
                  };
                }
              };
              
              const colors = getScoreColors(riskScore);
              
              return (
                <div className="relative max-w-full mx-auto mb-16">
                  {/* Enhanced gradient background with multiple layers */}
                  <div className="absolute inset-0 bg-gradient-to-br from-blue-500/8 via-purple-500/8 to-pink-500/8 rounded-3xl blur-3xl -z-10"></div>
                  <div className="absolute inset-0 bg-gradient-to-tr from-transparent via-white/20 to-transparent rounded-3xl -z-10"></div>
                  
                  {/* Main card - Ultra-premium with refined spacing */}
                  <div className="relative bg-white/90 backdrop-blur-2xl border-2 border-blue-200/60 rounded-3xl p-8 shadow-2xl hover:shadow-3xl transition-all duration-500 overflow-hidden">
                    {/* Enhanced top accent bar with glow */}
                    <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 shadow-lg"></div>
                    
                    {/* Row 1: Clean & Balanced Top Section */}
                    <div className="flex items-center justify-between gap-8 mb-6">
                      {/* Left: Label Only */}
                      <div className="flex items-center gap-4 flex-shrink-0">
                        <div className="flex flex-col gap-1">
                          <div className="text-slate-700 text-sm font-black uppercase tracking-widest">Security Risk Score</div>
                          <div className="text-xs text-slate-500 font-medium">Higher = More Risk</div>
                        </div>
                      </div>
                      
                      {/* Center: Massive Score */}
                      <div className="flex items-baseline gap-4 flex-1 justify-center">
                        <span 
                          className={`text-8xl font-bold leading-none drop-shadow-lg`}
                          style={{
                            background: riskScore <= 30 
                              ? 'linear-gradient(135deg, #10b981, #3b82f6)' 
                              : riskScore <= 60
                              ? 'linear-gradient(135deg, #3b82f6, #8b5cf6)'
                              : riskScore <= 80
                              ? 'linear-gradient(135deg, #f59e0b, #f97316)'
                              : 'linear-gradient(135deg, #ef4444, #ec4899)',
                            WebkitBackgroundClip: 'text',
                            WebkitTextFillColor: 'transparent',
                            backgroundClip: 'text',
                            filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.1))'
                          }}
                        >
                          {riskScore}
                        </span>
                        <span className="text-3xl text-slate-400 font-semibold pb-2">/100</span>
                      </div>
                      
                      {/* Right: Single Grade Badge */}
                      <div className={`inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-bold ${colors.status} shadow-md flex-shrink-0 ring-2 ring-opacity-20 ${colors.status.includes('red') ? 'ring-red-200' : colors.status.includes('orange') ? 'ring-orange-200' : colors.status.includes('blue') ? 'ring-blue-200' : 'ring-green-200'}`}>
                        <span className="text-base">Grade {grade.grade}</span>
                        <span className="opacity-50">•</span>
                        <span className="text-xs">{grade.label}</span>
                      </div>
                    </div>
                    
                    {/* Row 2: Refined Bottom Section */}
                    <div className="flex items-center justify-between gap-8 pt-6 border-t-2 border-slate-200/60">
                      {/* Left: Risk Level */}
                      <div className="flex flex-col gap-1.5 flex-shrink-0 min-w-[140px]">
                        <div className="text-slate-600 text-xs font-semibold uppercase tracking-wide">Risk Level</div>
                        <div className="text-slate-800 text-lg font-bold">{riskScore}% <span className="text-sm font-normal text-slate-500">risk</span></div>
                      </div>
                      
                      {/* Center: Enhanced Progress Bar */}
                      <div className="flex-1 max-w-2xl flex flex-col gap-2">
                        <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                          <span className="font-medium">Progress</span>
                          <span className="font-bold text-slate-700">{riskScore}%</span>
                        </div>
                        <div className="relative w-full bg-gradient-to-r from-slate-100 via-slate-50 to-slate-100 rounded-full h-3 overflow-hidden border border-slate-200 shadow-inner">
                          <div
                            className={`h-full bg-gradient-to-r ${colors.scoreGradient} rounded-full transition-all duration-1000 ease-out shadow-lg relative overflow-hidden`}
                            style={{ width: `${riskScore}%` }}
                          >
                            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer"></div>
                          </div>
                        </div>
                      </div>
                      
                      {/* Right: Findings Count */}
                      <div className="flex items-center gap-6 text-sm flex-shrink-0">
                        <div className="flex flex-col items-end gap-1">
                          <div className="text-slate-500 text-xs font-medium uppercase tracking-wide">Total Findings</div>
                          <div className="flex items-center gap-2">
                            <span className="text-slate-800 font-black text-xl">{response.findings.length}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* RISK BREAKDOWN CARDS - Premium Light Theme */}
            <div className="mb-16 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              {/* Critical */}
              <div className="bg-white/80 backdrop-blur-xl border-2 border-red-200/50 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <XCircle className="w-6 h-6 text-red-600" />
                    <span className="text-red-700 font-bold text-sm uppercase tracking-wide">Critical</span>
                  </div>
                  <span className="text-4xl font-black text-red-600">
                    {response.findings.filter(f => f.severity === 'Critical').length}
                  </span>
                </div>
                <div className="text-xs text-slate-600 font-medium">Immediate action required</div>
              </div>

              {/* High */}
              <div className="bg-white/80 backdrop-blur-xl border-2 border-orange-200/50 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <AlertTriangle className="w-6 h-6 text-orange-600" />
                    <span className="text-orange-700 font-bold text-sm uppercase tracking-wide">High</span>
                  </div>
                  <span className="text-4xl font-black text-orange-600">
                    {response.findings.filter(f => f.severity === 'High').length}
                  </span>
                </div>
                <div className="text-xs text-slate-600 font-medium">High priority fixes</div>
              </div>

              {/* Medium */}
              <div className="bg-white/80 backdrop-blur-xl border-2 border-yellow-200/50 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <AlertCircle className="w-6 h-6 text-yellow-600" />
                    <span className="text-yellow-700 font-bold text-sm uppercase tracking-wide">Medium</span>
                  </div>
                  <span className="text-4xl font-black text-yellow-600">
                    {response.findings.filter(f => f.severity === 'Medium').length}
                  </span>
                </div>
                <div className="text-xs text-slate-600 font-medium">Should be addressed</div>
              </div>

              {/* Low */}
              <div className="bg-white/80 backdrop-blur-xl border-2 border-slate-200/50 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <Info className="w-6 h-6 text-slate-600" />
                    <span className="text-slate-700 font-bold text-sm uppercase tracking-wide">Low</span>
                  </div>
                  <span className="text-4xl font-black text-slate-600">
                    {response.findings.filter(f => f.severity === 'Low').length}
                  </span>
                </div>
                <div className="text-xs text-slate-600 font-medium">Minor improvements</div>
              </div>
            </div>

            {/* SCORE BREAKDOWN - Ultra-Premium Redesign */}
            <div className="mb-16">
              <div className="relative z-10">
                {/* Premium Subsection Header */}
                <div className="flex items-center space-x-3 mb-6">
                  <div className="w-1 h-8 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
                  <div className="flex-1 flex items-center justify-between">
                    <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                      <Shield className="w-7 h-7 text-blue-600" />
                      <span>Score Breakdown</span>
                    </h3>
                    <button
                      onClick={() => setShowScoreBreakdown(!showScoreBreakdown)}
                      className="group flex items-center space-x-2 px-5 py-2.5 bg-white/80 backdrop-blur-xl hover:bg-white/90 border-2 border-slate-200 hover:border-blue-300 rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105"
                    >
                      <span className="text-sm font-bold text-slate-700 group-hover:text-blue-600 transition-colors duration-300">
                        {showScoreBreakdown ? 'Hide Details' : 'Show Details'}
                      </span>
                      {showScoreBreakdown ? (
                        <ChevronUp className="w-4 h-4 text-slate-500 group-hover:text-blue-600 transition-colors duration-300" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500 group-hover:text-blue-600 transition-colors duration-300" />
                      )}
                    </button>
                  </div>
                </div>

                {showScoreBreakdown && (
                  <div className="mt-6 relative bg-white/90 backdrop-blur-2xl border-2 border-blue-200/50 rounded-3xl p-8 shadow-2xl hover:shadow-3xl transition-all duration-500 overflow-hidden animate-in slide-in-from-top duration-300">
                    {/* Gradient accent bar at top */}
                    <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 shadow-lg"></div>
                    
                    {/* Background gradient layers */}
                    <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-purple-500/5 to-pink-500/5 rounded-3xl -z-10"></div>
                    
                    <div className="relative">
                      <p className="text-slate-700 text-base leading-relaxed mb-8 font-semibold">
                        Your policy has the following issues contributing to this score:
                      </p>

                      {/* Critical Issues - Premium Design */}
                      {response.findings.filter(f => f.severity === 'Critical').length > 0 && (
                        <div className="mb-8">
                          <div className="flex items-center justify-between mb-5">
                            <div className="flex items-center space-x-3">
                              <div className="w-12 h-12 bg-gradient-to-br from-red-500/20 to-red-600/20 rounded-xl flex items-center justify-center border-2 border-red-200/50 shadow-lg">
                                <XCircle className="w-6 h-6 text-red-600" />
                              </div>
                              <div>
                                <h5 className="text-red-600 font-black text-xl flex items-center space-x-2">
                                  <span>Critical Issues</span>
                                </h5>
                                <p className="text-xs text-slate-500 font-medium mt-0.5">Requires immediate attention</p>
                              </div>
                            </div>
                            <div className="px-4 py-2 bg-red-500/10 border-2 border-red-200/50 rounded-xl">
                              <span className="text-red-700 font-black text-lg">
                                {response.findings.filter(f => f.severity === 'Critical').length}
                              </span>
                              <span className="text-red-600 text-xs font-semibold ml-1">
                                {response.findings.filter(f => f.severity === 'Critical').length === 1 ? 'issue' : 'issues'}
                              </span>
                            </div>
                          </div>
                          <div className="space-y-3">
                            {response.findings.filter(f => f.severity === 'Critical').map((finding, idx) => (
                              <div key={idx} className="group relative bg-gradient-to-br from-red-50/80 to-white border-2 border-red-200/50 rounded-xl p-5 hover:border-red-300 hover:shadow-xl transition-all duration-300 hover:scale-[1.01]">
                                {/* Vertical accent bar */}
                                <div className="absolute left-0 top-0 bottom-0 w-1.5 bg-gradient-to-b from-red-500 to-red-600 rounded-l-xl"></div>
                                <div className="pl-4">
                                  <div className="flex items-start justify-between mb-2">
                                    <div className="font-black text-red-700 text-base mb-1">{finding.title}</div>
                                    <div className="px-2.5 py-1 bg-red-500/10 border border-red-200/50 rounded-lg">
                                      <span className="text-red-700 text-xs font-bold">Critical</span>
                                    </div>
                                  </div>
                                  <p className="text-slate-700 text-sm leading-relaxed font-medium">{finding.description}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* High Issues - Premium Design */}
                      {response.findings.filter(f => f.severity === 'High').length > 0 && (
                        <div className="mb-8">
                          <div className="flex items-center justify-between mb-5">
                            <div className="flex items-center space-x-3">
                              <div className="w-12 h-12 bg-gradient-to-br from-orange-500/20 to-orange-600/20 rounded-xl flex items-center justify-center border-2 border-orange-200/50 shadow-lg">
                                <AlertTriangle className="w-6 h-6 text-orange-600" />
                              </div>
                              <div>
                                <h5 className="text-orange-600 font-black text-xl flex items-center space-x-2">
                                  <span>High Issues</span>
                                </h5>
                                <p className="text-xs text-slate-500 font-medium mt-0.5">Should be addressed soon</p>
                              </div>
                            </div>
                            <div className="px-4 py-2 bg-orange-500/10 border-2 border-orange-200/50 rounded-xl">
                              <span className="text-orange-700 font-black text-lg">
                                {response.findings.filter(f => f.severity === 'High').length}
                              </span>
                              <span className="text-orange-600 text-xs font-semibold ml-1">
                                {response.findings.filter(f => f.severity === 'High').length === 1 ? 'issue' : 'issues'}
                              </span>
                            </div>
                          </div>
                          <div className="space-y-3">
                            {response.findings.filter(f => f.severity === 'High').map((finding, idx) => (
                              <div key={idx} className="group relative bg-gradient-to-br from-orange-50/80 to-white border-2 border-orange-200/50 rounded-xl p-5 hover:border-orange-300 hover:shadow-xl transition-all duration-300 hover:scale-[1.01]">
                                {/* Vertical accent bar */}
                                <div className="absolute left-0 top-0 bottom-0 w-1.5 bg-gradient-to-b from-orange-500 to-orange-600 rounded-l-xl"></div>
                                <div className="pl-4">
                                  <div className="flex items-start justify-between mb-2">
                                    <div className="font-black text-orange-700 text-base mb-1">{finding.title}</div>
                                    <div className="px-2.5 py-1 bg-orange-500/10 border border-orange-200/50 rounded-lg">
                                      <span className="text-orange-700 text-xs font-bold">High</span>
                                    </div>
                                  </div>
                                  <p className="text-slate-700 text-sm leading-relaxed font-medium">{finding.description}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Medium Issues - Premium Design */}
                      {response.findings.filter(f => f.severity === 'Medium').length > 0 && (
                        <div className="mb-8">
                          <div className="flex items-center justify-between mb-5">
                            <div className="flex items-center space-x-3">
                              <div className="w-12 h-12 bg-gradient-to-br from-yellow-500/20 to-yellow-600/20 rounded-xl flex items-center justify-center border-2 border-yellow-200/50 shadow-lg">
                                <AlertCircle className="w-6 h-6 text-yellow-600" />
                              </div>
                              <div>
                                <h5 className="text-yellow-600 font-black text-xl flex items-center space-x-2">
                                  <span>Medium Issues</span>
                                </h5>
                                <p className="text-xs text-slate-500 font-medium mt-0.5">Consider addressing</p>
                              </div>
                            </div>
                            <div className="px-4 py-2 bg-yellow-500/10 border-2 border-yellow-200/50 rounded-xl">
                              <span className="text-yellow-700 font-black text-lg">
                                {response.findings.filter(f => f.severity === 'Medium').length}
                              </span>
                              <span className="text-yellow-600 text-xs font-semibold ml-1">
                                {response.findings.filter(f => f.severity === 'Medium').length === 1 ? 'issue' : 'issues'}
                              </span>
                            </div>
                          </div>
                          <div className="space-y-3">
                            {response.findings.filter(f => f.severity === 'Medium').map((finding, idx) => (
                              <div key={idx} className="group relative bg-gradient-to-br from-yellow-50/80 to-white border-2 border-yellow-200/50 rounded-xl p-5 hover:border-yellow-300 hover:shadow-xl transition-all duration-300 hover:scale-[1.01]">
                                {/* Vertical accent bar */}
                                <div className="absolute left-0 top-0 bottom-0 w-1.5 bg-gradient-to-b from-yellow-500 to-yellow-600 rounded-l-xl"></div>
                                <div className="pl-4">
                                  <div className="flex items-start justify-between mb-2">
                                    <div className="font-black text-yellow-700 text-base mb-1">{finding.title}</div>
                                    <div className="px-2.5 py-1 bg-yellow-500/10 border border-yellow-200/50 rounded-lg">
                                      <span className="text-yellow-700 text-xs font-bold">Medium</span>
                                    </div>
                                  </div>
                                  <p className="text-slate-700 text-sm leading-relaxed font-medium">{finding.description}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Low Issues - Premium Design */}
                      {response.findings.filter(f => f.severity === 'Low').length > 0 && (
                        <div className="mb-8">
                          <div className="flex items-center justify-between mb-5">
                            <div className="flex items-center space-x-3">
                              <div className="w-12 h-12 bg-gradient-to-br from-slate-500/20 to-slate-600/20 rounded-xl flex items-center justify-center border-2 border-slate-200/50 shadow-lg">
                                <Info className="w-6 h-6 text-slate-600" />
                              </div>
                              <div>
                                <h5 className="text-slate-600 font-black text-xl flex items-center space-x-2">
                                  <span>Low Issues</span>
                                </h5>
                                <p className="text-xs text-slate-500 font-medium mt-0.5">Minor improvements</p>
                              </div>
                            </div>
                            <div className="px-4 py-2 bg-slate-500/10 border-2 border-slate-200/50 rounded-xl">
                              <span className="text-slate-700 font-black text-lg">
                                {response.findings.filter(f => f.severity === 'Low').length}
                              </span>
                              <span className="text-slate-600 text-xs font-semibold ml-1">
                                {response.findings.filter(f => f.severity === 'Low').length === 1 ? 'issue' : 'issues'}
                              </span>
                            </div>
                          </div>
                          <div className="space-y-3">
                            {response.findings.filter(f => f.severity === 'Low').map((finding, idx) => (
                              <div key={idx} className="group relative bg-gradient-to-br from-slate-50/80 to-white border-2 border-slate-200/50 rounded-xl p-5 hover:border-slate-300 hover:shadow-xl transition-all duration-300 hover:scale-[1.01]">
                                {/* Vertical accent bar */}
                                <div className="absolute left-0 top-0 bottom-0 w-1.5 bg-gradient-to-b from-slate-400 to-slate-500 rounded-l-xl"></div>
                                <div className="pl-4">
                                  <div className="flex items-start justify-between mb-2">
                                    <div className="font-black text-slate-700 text-base mb-1">{finding.title}</div>
                                    <div className="px-2.5 py-1 bg-slate-500/10 border border-slate-200/50 rounded-lg">
                                      <span className="text-slate-700 text-xs font-bold">Low</span>
                                    </div>
                                  </div>
                                  <p className="text-slate-700 text-sm leading-relaxed font-medium">{finding.description}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Final Score Summary - Premium Design */}
                      <div className="pt-6 mt-6 border-t-2 border-slate-200/60">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            <div className="w-10 h-10 bg-gradient-to-br from-blue-500/10 to-purple-500/10 rounded-xl flex items-center justify-center border-2 border-blue-200/50">
                              <Shield className="w-5 h-5 text-blue-600" />
                            </div>
                            <div>
                              <span className="text-slate-600 text-sm font-bold uppercase tracking-wide">Final Risk Score</span>
                              <div className="mt-1">
                                <span className={`text-xs font-semibold ${
                                  response.risk_score <= 30 ? 'text-emerald-600' :
                                  response.risk_score <= 60 ? 'text-blue-600' :
                                  response.risk_score <= 80 ? 'text-orange-600' :
                                  'text-red-600'
                                }`}>
                                  {getRiskGrade(response.risk_score).label}
                                </span>
                              </div>
                            </div>
                          </div>
                          <div className="text-right">
                            <span className={`font-black text-4xl leading-none ${
                              response.risk_score <= 30 ? 'text-emerald-600' :
                              response.risk_score <= 60 ? 'text-blue-600' :
                              response.risk_score <= 80 ? 'text-orange-600' :
                              'text-red-600'
                            }`}>
                              {response.risk_score}
                            </span>
                            <span className="text-slate-400 text-2xl font-semibold ml-1">/100</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* SECURITY FINDINGS - Premium Light Theme */}
            <div className="mb-16">
              {/* Premium Subsection Header */}
              <div className="flex items-center space-x-3 mb-8">
                <div className="w-1 h-8 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
                <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                  <Shield className="w-7 h-7 text-blue-600" />
                  <span>Security Findings</span>
                </h3>
              </div>
              
              {response.findings.length === 0 ? (
                <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-16 text-center shadow-xl">
                  <CheckCircle className="w-24 h-24 text-blue-600 mx-auto mb-6" />
                  <h4 className="text-blue-600 font-black text-3xl mb-3">Perfect Security Score!</h4>
                  <p className="text-slate-700 text-lg leading-relaxed font-medium">This policy follows all AWS security best practices.</p>
                </div>
              ) : (
                <div className="space-y-6">
                  {response.findings.map((finding, index) => {
                    const colors = getSeverityColor(finding.severity);
                    const isExpanded = expandedFindings.has(finding.id);
                    const specificImpact = getSpecificImpact(finding);
                    
                    return (
                      <div key={index} className={`${colors.bg} backdrop-blur-xl border-2 ${colors.border} rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl transition-all duration-300 group`}>
                        {/* Gradient accent bar at top */}
                        <div className={`absolute top-0 left-0 right-0 h-1.5 ${
                          finding.severity === 'Critical' ? 'bg-gradient-to-r from-red-500 via-rose-500 to-red-600' :
                          finding.severity === 'High' ? 'bg-gradient-to-r from-orange-500 via-amber-500 to-orange-600' :
                          finding.severity === 'Medium' ? 'bg-gradient-to-r from-yellow-500 via-amber-500 to-yellow-600' :
                          'bg-gradient-to-r from-slate-400 via-slate-500 to-slate-600'
                        } shadow-lg`}></div>
                        
                        <div className="p-8 relative">
                          {/* Finding Header - Premium Design */}
                          <div className="flex items-start space-x-4 mb-6">
                            <div className={`w-16 h-16 rounded-2xl flex items-center justify-center ${colors.icon} border-2 shadow-lg group-hover:scale-110 transition-transform duration-300`}>
                              {finding.severity === 'Critical' ? <XCircle className="w-8 h-8 text-red-600" /> :
                               finding.severity === 'High' ? <AlertTriangle className="w-8 h-8 text-orange-600" /> :
                               finding.severity === 'Medium' ? <AlertCircle className="w-8 h-8 text-yellow-600" /> :
                               <Info className="w-8 h-8 text-slate-600" />}
                            </div>
                            <div className="flex-1">
                              <div className="flex items-center flex-wrap gap-3 mb-3">
                                <h4 className="text-slate-900 font-black text-2xl tracking-tight">{finding.title}</h4>
                                <span className={`px-4 py-2 rounded-xl text-sm font-bold shadow-md ${colors.badge}`}>
                                  {finding.severity}
                                </span>
                                <span className="text-xs font-mono text-slate-500 bg-slate-100 px-3 py-1.5 rounded-lg border border-slate-200">{finding.id}</span>
                              </div>
                              <p className="text-slate-700 text-base mb-6 leading-relaxed font-medium">
                                {finding.description}
                              </p>
                              
                              {/* Code Snippet - Premium Design */}
                              {finding.code_snippet && (
                                <div className="bg-gradient-to-br from-slate-50 to-white rounded-xl p-6 mb-6 border-2 border-slate-200 shadow-lg hover:shadow-xl transition-all duration-300">
                                  <div className="flex items-center justify-between mb-4">
                                    <div className="flex items-center space-x-2">
                                      <div className="w-1 h-5 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
                                      <span className="text-xs text-slate-600 font-bold uppercase tracking-wide">Problematic Code</span>
                                    </div>
                                    <button 
                                      onClick={() => {
                                        navigator.clipboard.writeText(finding.code_snippet || '');
                                        // You could add a toast notification here
                                      }}
                                      className="text-slate-500 hover:text-slate-700 transition-colors p-2 hover:bg-slate-100 rounded-lg"
                                    >
                                      <Copy className="w-4 h-4" />
                                    </button>
                                  </div>
                                  <pre className="text-sm text-slate-800 font-mono leading-relaxed overflow-x-auto bg-white/50 p-4 rounded-lg border border-slate-200">
                                    {finding.code_snippet}
                                  </pre>
                                </div>
                              )}

                              {/* INLINE DETAILED EXPLANATION - Only show if specific impact exists */}
                              {specificImpact && (
                                <>
                                  <button
                                    onClick={() => toggleFindingExpansion(finding.id)}
                                    className="w-full mb-4 px-6 py-4 bg-gradient-to-r from-blue-500/10 to-purple-500/10 hover:from-blue-500/20 hover:to-purple-500/20 border-2 border-blue-200/50 hover:border-blue-300 rounded-xl transition-all duration-300 flex items-center justify-between group"
                                  >
                                    <div className="flex items-center space-x-3">
                                      <Eye className="w-5 h-5 text-blue-600 group-hover:scale-110 transition-transform" />
                                      <span className="text-blue-700 font-bold text-base">
                                        {isExpanded ? 'Hide' : 'Show'} Detailed Impact Analysis
                                      </span>
                                    </div>
                                    {isExpanded ? <ChevronUp className="w-5 h-5 text-blue-600" /> : <ChevronDown className="w-5 h-5 text-blue-600" />}
                                  </button>

                                  {isExpanded && specificImpact && specificImpact.hasExplanation && (
                                    <div className="mb-6 bg-gradient-to-br from-slate-50 to-white rounded-2xl p-8 border-2 border-slate-200/50 backdrop-blur-xl animate-in slide-in-from-top duration-300 shadow-xl">
                                      <div className="space-y-6">
                                        {/* Parse and display Security Impact and Practical Risk Assessment separately */}
                                        {(() => {
                                          const explanation = finding.detailed_explanation || '';
                                          const parts = explanation.split(/\n\n+/);
                                          
                                          let securityImpact = '';
                                          let practicalRisk = '';
                                          
                                          // Extract Security Impact
                                          const impactMatch = explanation.match(/Security Impact:\s*(.+?)(?:\n\n|Practical Risk Assessment:|$)/s);
                                          if (impactMatch) {
                                            securityImpact = impactMatch[1].trim();
                                          }
                                          
                                          // Extract Practical Risk Assessment
                                          const riskMatch = explanation.match(/Practical Risk Assessment:\s*(.+?)$/s);
                                          if (riskMatch) {
                                            practicalRisk = riskMatch[1].trim();
                                          }
                                          
                                          // If structured format not found, show full explanation
                                          if (!securityImpact && !practicalRisk) {
                                            return (
                                              <div className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 border-l-4 border-blue-500/50 rounded-r-xl p-5 shadow-lg">
                                                <div className="flex items-center space-x-2 mb-3">
                                                  <Shield className="w-5 h-5 text-blue-600" />
                                                  <div className="font-bold text-blue-700 text-base">Detailed Explanation</div>
                                                </div>
                                                <div className="text-slate-800 text-sm leading-relaxed font-medium prose prose-sm max-w-none">
                                                  <div dangerouslySetInnerHTML={{ __html: explanation.replace(/\n/g, '<br/>') }} />
                                                </div>
                                              </div>
                                            );
                                          }
                                          
                                          return (
                                            <>
                                              {/* Security Impact */}
                                              {securityImpact && (
                                                <div className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 border-l-4 border-blue-500/50 rounded-r-xl p-5 shadow-lg">
                                                  <div className="flex items-center space-x-2 mb-3">
                                                    <Shield className="w-5 h-5 text-blue-600" />
                                                    <div className="font-bold text-blue-700 text-base">Security Impact</div>
                                                  </div>
                                                  <p className="text-slate-800 text-sm leading-relaxed font-medium">
                                                    {securityImpact}
                                                  </p>
                                                </div>
                                              )}
                                              
                                              {/* Practical Risk Assessment */}
                                              {practicalRisk && (
                                                <div className="bg-gradient-to-r from-orange-500/10 via-red-500/10 to-pink-500/10 border-l-4 border-red-500/50 rounded-r-xl p-5 shadow-lg">
                                                  <div className="flex items-center space-x-2 mb-3">
                                                    <AlertTriangle className="w-5 h-5 text-red-600" />
                                                    <div className="font-bold text-red-700 text-base">Practical Risk Assessment</div>
                                                  </div>
                                                  <p className="text-slate-800 text-sm leading-relaxed font-medium">
                                                    {practicalRisk}
                                                  </p>
                                                </div>
                                              )}
                                            </>
                                          );
                                        })()}
                                      </div>
                                    </div>
                                  )}
                                </>
                              )}
                              
                              {/* Recommendation - Premium Design */}
                              <div className="bg-gradient-to-br from-blue-500/10 via-purple-500/10 to-pink-500/10 border-2 border-blue-200/50 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-300">
                                <div className="flex items-start space-x-3">
                                  <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-xl flex items-center justify-center shadow-lg flex-shrink-0">
                                    <Sparkles className="w-5 h-5 text-white" />
                                  </div>
                                  <div className="flex-1">
                                    <div className="text-blue-700 font-bold text-base mb-2 flex items-center space-x-2">
                                      <span>How to Fix This</span>
                                      <span className="px-2 py-0.5 bg-blue-500/10 text-blue-700 text-xs font-semibold rounded border border-blue-200/50">
                                        Quick Fix
                                      </span>
                                    </div>
                                    <p className="text-slate-700 text-base leading-relaxed font-medium">{finding.recommendation}</p>
                                    <button
                                      onClick={() => {
                                        setIsChatbotOpen(true);
                                        setEnhancementInput(`Fix this finding: ${finding.title}. ${finding.recommendation}`);
                                      }}
                                      className="mt-4 px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white text-sm font-bold rounded-lg transition-all duration-300 shadow-md hover:shadow-lg hover:scale-105 flex items-center space-x-2"
                                    >
                                      <Bot className="w-4 h-4" />
                                      <span>Fix with AI Assistant</span>
                                    </button>
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

            {/* COMPLIANCE STATUS - Premium Light Theme with Enhanced Features */}
            <div className="mb-16">
              {response.compliance_status && Object.keys(response.compliance_status).length > 0 ? (
                <div>
                {/* Premium Subsection Header */}
                <div className="flex items-center space-x-3 mb-8">
                  <div className="w-1 h-8 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
                  <div className="flex-1">
                    <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                      <CheckCircle className="w-7 h-7 text-blue-600" />
                      <span>Compliance Status</span>
                    </h3>
                    <p className="text-slate-600 text-sm mt-2 font-medium">Compliance validation against regulatory standards</p>
                  </div>
                </div>

                {/* Overall Compliance Summary Banner */}
                {(() => {
                  const frameworks = Object.values(response.compliance_status || {});
                  const compliantCount = frameworks.filter((f: any) => f.status === 'Compliant').length;
                  const nonCompliantCount = frameworks.length - compliantCount;
                  const totalViolations = frameworks.reduce((sum: number, f: any) => {
                    return sum + (f.violations?.length || f.gaps?.length || 0);
                  }, 0);
                  
                  return (
                    <div className="mb-8 bg-gradient-to-r from-red-50 via-orange-50 to-yellow-50 border-2 border-red-200/50 rounded-2xl p-6 shadow-xl">
                      <div className="flex items-center justify-between flex-wrap gap-4">
                        <div className="flex items-center space-x-4">
                          <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center border-2 border-red-200/50">
                            <XCircle className="w-8 h-8 text-red-600" />
                          </div>
                          <div>
                            <div className="text-red-900 font-black text-2xl mb-1">Critical Non-Compliance</div>
                            <div className="text-slate-700 text-sm font-medium">
                              {nonCompliantCount} of {frameworks.length} frameworks failed • {totalViolations} total violations
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <div className="text-right">
                            <div className="text-slate-600 text-xs font-semibold uppercase tracking-wide mb-1">Compliance Rate</div>
                            <div className="text-red-600 font-black text-3xl">
                              {Math.round((compliantCount / frameworks.length) * 100)}%
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })()}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {Object.entries(response.compliance_status).map(([key, framework]: [string, any]) => {
                    const violations = framework.violations || [];
                    const gaps = framework.gaps || [];
                    const totalIssues = violations.length + gaps.length;
                    
                    return (
                      <div key={key} className={`bg-white/80 backdrop-blur-xl border-2 rounded-2xl p-6 shadow-xl hover:shadow-2xl transition-all duration-300 ${
                        framework.status === 'Compliant' 
                          ? 'border-green-200/50' 
                          : 'border-red-200/50'
                      }`}>
                        <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center space-x-3">
                            <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                              framework.status === 'Compliant'
                                ? 'bg-green-500/10 border-2 border-green-200/50'
                                : 'bg-red-500/10 border-2 border-red-200/50'
                            }`}>
                              {framework.status === 'Compliant' ? (
                                <CheckCircle className="w-6 h-6 text-green-600" />
                              ) : (
                                <XCircle className="w-6 h-6 text-red-600" />
                              )}
                            </div>
                            <div>
                              <h4 className="text-slate-900 font-bold text-lg">{framework.name}</h4>
                              <div className="text-xs text-slate-500 font-medium">{totalIssues} {totalIssues === 1 ? 'issue' : 'issues'} found</div>
                            </div>
                          </div>
                          <span className={`px-3 py-1.5 rounded-full text-xs font-bold ${
                            framework.status === 'Compliant'
                              ? 'bg-green-500/10 text-green-700 border border-green-200/50'
                              : 'bg-red-500/10 text-red-700 border border-red-200/50'
                          }`}>
                            {framework.status}
                          </span>
                        </div>
                        
                        {/* Progress Indicator */}
                        {framework.status !== 'Compliant' && (
                          <div className="mb-4">
                            <div className="flex items-center justify-between text-xs text-slate-600 mb-2">
                              <span className="font-semibold">Remediation Progress</span>
                              <span className="font-bold">0%</span>
                            </div>
                            <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                              <div className="h-full bg-gradient-to-r from-red-500 to-orange-500 rounded-full transition-all duration-500" style={{ width: '0%' }}></div>
                            </div>
                            <div className="text-xs text-slate-500 mt-1 font-medium">Start remediation using AI Assistant below</div>
                          </div>
                        )}
                        
                        {/* Full violations handling */}
                        {violations.length > 0 && (
                          <div className="space-y-3">
                            <div className="text-xs text-slate-600 font-bold uppercase tracking-wide mb-2">Violations:</div>
                            {violations.map((violation: any, idx: number) => (
                              <div key={idx} className="bg-slate-50 rounded-xl p-4 border-2 border-slate-200/50 hover:border-red-200/50 transition-all duration-300">
                                <div className="flex items-start justify-between mb-2">
                                  <div className="flex items-center space-x-2">
                                    <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                                    <div className="text-red-700 font-bold text-sm">{violation.requirement}</div>
                                  </div>
                                  <span className="px-2 py-0.5 bg-red-500/10 text-red-700 text-xs font-semibold rounded border border-red-200/50">
                                    High Priority
                                  </span>
                                </div>
                                <p className="text-slate-700 text-sm mb-3 leading-relaxed font-medium">{violation.description}</p>
                                <div className="bg-blue-500/10 border-l-4 border-blue-500/50 rounded-r-lg p-3">
                                  <div className="text-blue-700 text-xs font-bold mb-1 flex items-center space-x-1">
                                    <Sparkles className="w-3 h-3" />
                                    <span>How to Fix:</span>
                                  </div>
                                  <p className="text-slate-700 text-sm font-medium">{violation.fix}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                        
                        {/* Fallback to gaps if no violations */}
                        {violations.length === 0 && gaps.length > 0 && (
                          <div className="space-y-2">
                            <div className="text-xs text-slate-600 font-bold uppercase tracking-wide mb-2">Compliance Gaps:</div>
                            {gaps.map((gap: string, idx: number) => (
                              <div key={idx} className="flex items-start space-x-2 bg-slate-50 rounded-lg p-3 border border-slate-200/50">
                                <XCircle className="w-4 h-4 text-red-600 mt-0.5 flex-shrink-0" />
                                <p className="text-slate-700 text-sm font-medium">{gap}</p>
                              </div>
                            ))}
                          </div>
                        )}

                        {/* Compliant State */}
                        {framework.status === 'Compliant' && (
                          <div className="bg-green-50 rounded-xl p-4 border-2 border-green-200/50 text-center">
                            <CheckCircle className="w-8 h-8 text-green-600 mx-auto mb-2" />
                            <p className="text-green-700 font-semibold text-sm">All requirements met</p>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
              ) : (
                <div>
                  {/* Premium Subsection Header */}
                  <div className="flex items-center space-x-3 mb-8">
                    <div className="w-1 h-8 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
                    <div className="flex-1">
                      <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                        <CheckCircle className="w-7 h-7 text-blue-600" />
                        <span>Compliance Status</span>
                      </h3>
                      <p className="text-slate-600 text-sm mt-2 font-medium">Compliance validation against regulatory standards</p>
                    </div>
                  </div>
                  <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 shadow-xl text-center">
                    <CheckCircle className="w-16 h-16 text-blue-600 mx-auto mb-4" />
                    <p className="text-slate-700 text-base leading-relaxed font-medium">
                      No compliance frameworks were selected for validation. Select frameworks in the validation form to check compliance status.
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* REFINE YOUR POLICY - Premium Light Theme with Enhanced Features */}
            <div className="mb-16">
              {/* Premium Subsection Header */}
              <div className="flex items-center space-x-3 mb-6">
                <div className="w-1 h-8 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
                <div className="flex-1">
                  <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                    <Sparkles className="w-7 h-7 text-blue-600" />
                    <span>Refine Your Policy with AI</span>
                  </h3>
                  <p className="text-slate-600 text-sm mt-2 font-medium">Automated remediation powered by Claude 3.7 Sonnet</p>
                </div>
              </div>

              {/* AI Assistant CTA Banner */}
              <div className="mb-8 bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-pink-500/10 border-2 border-blue-200/50 rounded-2xl p-6 shadow-xl">
                <div className="flex items-center justify-between flex-wrap gap-4">
                  <div className="flex items-center space-x-4">
                    <div className="w-14 h-14 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full flex items-center justify-center shadow-lg">
                      <Bot className="w-7 h-7 text-white" />
                    </div>
                    <div>
                      <div className="text-slate-900 font-black text-xl mb-1">Aegis AI Assistant Ready</div>
                      <div className="text-slate-700 text-sm font-medium">
                        Click the chatbot icon (bottom right) to start automated remediation
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => setIsChatbotOpen(true)}
                    className="px-6 py-3 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white font-bold rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105 flex items-center space-x-2"
                  >
                    <Bot className="w-5 h-5" />
                    <span>Open Assistant</span>
                  </button>
                </div>
              </div>

              <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 shadow-xl">
                <p className="text-slate-700 text-base mb-6 leading-relaxed font-medium">
                  Quick actions you can request from the AI Assistant:
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <button
                    onClick={() => {
                      setIsChatbotOpen(true);
                      setEnhancementInput('Fix all critical issues');
                    }}
                    className="group bg-white/80 hover:bg-white border-2 border-red-200/50 hover:border-red-300 rounded-xl p-5 hover:scale-105 transition-all duration-300 shadow-lg hover:shadow-xl text-left"
                  >
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-2">
                        <XCircle className="w-5 h-5 text-red-600" />
                        <span className="text-red-700 font-bold text-sm">Fix Critical Issues</span>
                      </div>
                      <div className="px-2 py-1 bg-red-500/10 text-red-700 text-xs font-bold rounded border border-red-200/50">
                        {response.findings.filter(f => f.severity === 'Critical').length} issues
                      </div>
                    </div>
                    <p className="text-slate-600 text-xs font-medium mb-3">Remove wildcards, add resource restrictions, enforce MFA</p>
                    <div className="flex items-center space-x-2 text-xs text-slate-500">
                      <Clock className="w-3 h-3" />
                      <span className="font-medium">~2-3 min</span>
                      <span className="mx-1">•</span>
                      <Zap className="w-3 h-3" />
                      <span className="font-medium">Auto-fix available</span>
                    </div>
                  </button>

                  <button
                    onClick={() => {
                      setIsChatbotOpen(true);
                      setEnhancementInput('Add security controls including IP restrictions, time-based access, and encryption requirements');
                    }}
                    className="group bg-white/80 hover:bg-white border-2 border-purple-200/50 hover:border-purple-300 rounded-xl p-5 hover:scale-105 transition-all duration-300 shadow-lg hover:shadow-xl text-left"
                  >
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-2">
                        <Shield className="w-5 h-5 text-purple-600" />
                        <span className="text-purple-700 font-bold text-sm">Add Security Controls</span>
                      </div>
                      <div className="px-2 py-1 bg-purple-500/10 text-purple-700 text-xs font-bold rounded border border-purple-200/50">
                        Enhanced
                      </div>
                    </div>
                    <p className="text-slate-600 text-xs font-medium mb-3">IP restrictions, time-based access, encryption requirements</p>
                    <div className="flex items-center space-x-2 text-xs text-slate-500">
                      <Clock className="w-3 h-3" />
                      <span className="font-medium">~3-5 min</span>
                      <span className="mx-1">•</span>
                      <Target className="w-3 h-3" />
                      <span className="font-medium">Customizable</span>
                    </div>
                  </button>

                  <button
                    onClick={() => {
                      setIsChatbotOpen(true);
                      setEnhancementInput('Apply principle of least privilege - minimize permissions to only what is needed');
                    }}
                    className="group bg-white/80 hover:bg-white border-2 border-blue-200/50 hover:border-blue-300 rounded-xl p-5 hover:scale-105 transition-all duration-300 shadow-lg hover:shadow-xl text-left"
                  >
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-2">
                        <Target className="w-5 h-5 text-blue-600" />
                        <span className="text-blue-700 font-bold text-sm">Principle of Least Privilege</span>
                      </div>
                      <div className="px-2 py-1 bg-blue-500/10 text-blue-700 text-xs font-bold rounded border border-blue-200/50">
                        Best Practice
                      </div>
                    </div>
                    <p className="text-slate-600 text-xs font-medium mb-3">Minimize permissions to only what's needed</p>
                    <div className="flex items-center space-x-2 text-xs text-slate-500">
                      <Clock className="w-3 h-3" />
                      <span className="font-medium">~5-7 min</span>
                      <span className="mx-1">•</span>
                      <Activity className="w-3 h-3" />
                      <span className="font-medium">Policy review</span>
                    </div>
                  </button>

                  <button
                    onClick={() => {
                      setIsChatbotOpen(true);
                      setEnhancementInput('Ensure compliance with PCI DSS, HIPAA, SOX, and GDPR requirements');
                    }}
                    className="group bg-white/80 hover:bg-white border-2 border-yellow-200/50 hover:border-yellow-300 rounded-xl p-5 hover:scale-105 transition-all duration-300 shadow-lg hover:shadow-xl text-left"
                  >
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-2">
                        <CheckCircle className="w-5 h-5 text-yellow-600" />
                        <span className="text-yellow-700 font-bold text-sm">Compliance Alignment</span>
                      </div>
                      <div className="px-2 py-1 bg-yellow-500/10 text-yellow-700 text-xs font-bold rounded border border-yellow-200/50">
                        {Object.values(response.compliance_status || {}).filter((f: any) => f.status !== 'Compliant').length} failed
                      </div>
                    </div>
                    <p className="text-slate-600 text-xs font-medium mb-3">Meet PCI DSS, HIPAA, SOX, GDPR requirements</p>
                    <div className="flex items-center space-x-2 text-xs text-slate-500">
                      <Clock className="w-3 h-3" />
                      <span className="font-medium">~10-15 min</span>
                      <span className="mx-1">•</span>
                      <FileSearch className="w-3 h-3" />
                      <span className="font-medium">Multi-framework</span>
                    </div>
                  </button>
                </div>
              </div>
            </div>

            {/* EXPORT ANALYSIS REPORT - Premium Light Theme */}
            <div className="mb-16">
              {/* Premium Subsection Header */}
              <div className="flex items-center space-x-3 mb-6">
                <div className="w-1 h-8 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
                <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                  <Download className="w-7 h-7 text-blue-600" />
                  <span>Export Analysis Report</span>
                </h3>
              </div>
              <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 shadow-xl">
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
                    className="group px-6 py-4 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 rounded-xl text-white font-bold transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105 flex items-center space-x-3"
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
                    className="group px-6 py-4 bg-white/80 hover:bg-white border-2 border-slate-200 hover:border-slate-300 rounded-xl text-slate-700 hover:text-slate-900 font-bold transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105 flex items-center space-x-3"
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
              <div className={`${isChatbotExpanded ? 'w-[90vw] h-[90vh]' : 'w-[480px] h-[700px]'} bg-white/95 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl shadow-2xl flex flex-col overflow-hidden transition-all duration-300`}>
                {/* Chatbot Header - Premium Light Theme */}
                <div className="p-4 bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-pink-500/10 border-b-2 border-slate-200/50 flex items-center justify-between backdrop-blur-xl">
                  <div className="flex items-center space-x-4">
                    <div className="relative">
                      <div className="absolute inset-0 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full blur-lg opacity-30 animate-pulse"></div>
                      <div className="relative w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full flex items-center justify-center shadow-lg">
                        <Bot className="w-6 h-6 text-white" />
                      </div>
                    </div>
                    <div>
                      <h3 className="text-slate-900 font-bold text-sm">Aegis AI Assistant</h3>
                      <div className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                        <p className="text-xs text-slate-600 font-medium">Ready to help</p>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => setIsChatbotExpanded(!isChatbotExpanded)}
                      className="text-slate-500 hover:text-slate-900 transition-colors duration-300 p-1 hover:bg-slate-100 rounded"
                    >
                      {isChatbotExpanded ? <Minimize2 className="w-5 h-5" /> : <Maximize2 className="w-5 h-5" />}
                    </button>
                    <button
                      onClick={() => setIsChatbotOpen(false)}
                      className="text-slate-500 hover:text-slate-900 transition-colors duration-300 p-1 hover:bg-slate-100 rounded"
                    >
                      <X className="w-5 h-5" />
                    </button>
                  </div>
                </div>

                {/* Chat Messages - Premium Light Theme */}
                <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-slate-50/30">
                  {enhancementChat.map((msg, idx) => (
                    <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'} animate-in slide-in-from-bottom duration-300`}>
                      <div className={`max-w-[85%] ${
                        msg.role === 'user' 
                          ? 'bg-gradient-to-br from-blue-500/20 to-purple-500/20 border-2 border-blue-200/50' 
                          : 'bg-white/80 border-2 border-slate-200/50'
                      } rounded-2xl p-4 shadow-lg backdrop-blur-xl`}>
                        {msg.role === 'assistant' && (
                          <div className="flex items-center space-x-2 mb-3">
                            <div className="w-5 h-5 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full flex items-center justify-center">
                              <Bot className="w-3 h-3 text-white" />
                            </div>
                            <span className="text-xs font-bold text-blue-600 uppercase tracking-wide">Aegis AI</span>
                          </div>
                        )}
                        {msg.role === 'user' && (
                          <div className="flex items-center justify-end space-x-2 mb-3">
                            <span className="text-xs font-bold text-blue-600 uppercase tracking-wide">You</span>
                          </div>
                        )}
                        <p className="text-slate-800 text-sm leading-relaxed whitespace-pre-wrap">{msg.content}</p>
                      </div>
                    </div>
                  ))}
                  
                  {enhancementLoading && (
                    <div className="flex justify-start animate-in slide-in-from-bottom duration-300">
                      <div className="max-w-[85%] bg-white/80 border-2 border-slate-200/50 rounded-2xl p-4 shadow-lg">
                        <div className="flex items-center space-x-3">
                          <div className="w-5 h-5 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full flex items-center justify-center">
                            <Bot className="w-3 h-3 text-white" />
                          </div>
                          <div className="flex items-center space-x-2">
                            <div className="flex space-x-1">
                              <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce"></div>
                              <div className="w-2 h-2 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                              <div className="w-2 h-2 bg-pink-500 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
                            </div>
                            <span className="text-sm text-slate-600 font-medium">Thinking...</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                  
                  <div ref={chatEndRef} />
                </div>

                {/* Chat Input - Premium Light Theme */}
                <div className="p-4 border-t-2 border-slate-200/50 bg-white/80 backdrop-blur-xl">
                  {/* Quick Actions - Premium Light Theme */}
                  <div className="mb-4 p-4 bg-gradient-to-r from-blue-500/10 to-purple-500/10 rounded-xl border-2 border-blue-200/50 backdrop-blur-xl">
                    <p className="text-blue-700 font-semibold text-xs mb-3 flex items-center space-x-2">
                      <Zap className="w-4 h-4" />
                      <span>Quick Actions:</span>
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <button 
                        onClick={() => setEnhancementInput('Fix all critical issues')}
                        className="group px-3 py-2 bg-white/80 hover:bg-white border-2 border-red-200/50 hover:border-red-300 rounded-lg text-red-700 hover:text-red-900 text-xs font-semibold transition-all hover:scale-105 shadow-sm hover:shadow-md"
                      >
                        <span>Fix Critical Issues</span>
                      </button>
                      <button 
                        onClick={() => setEnhancementInput('Add MFA requirement for all actions')}
                        className="group px-3 py-2 bg-white/80 hover:bg-white border-2 border-purple-200/50 hover:border-purple-300 rounded-lg text-purple-700 hover:text-purple-900 text-xs font-semibold transition-all hover:scale-105 shadow-sm hover:shadow-md"
                      >
                        <span>Add MFA</span>
                      </button>
                      <button 
                        onClick={() => setEnhancementInput('Replace wildcards with specific permissions')}
                        className="group px-3 py-2 bg-white/80 hover:bg-white border-2 border-yellow-200/50 hover:border-yellow-300 rounded-lg text-yellow-700 hover:text-yellow-900 text-xs font-semibold transition-all hover:scale-105 shadow-sm hover:shadow-md"
                      >
                        <span>Remove Wildcards</span>
                      </button>
                      <button 
                        onClick={() => setEnhancementInput('Add IP address restrictions')}
                        className="group px-3 py-2 bg-white/80 hover:bg-white border-2 border-blue-200/50 hover:border-blue-300 rounded-lg text-blue-700 hover:text-blue-900 text-xs font-semibold transition-all hover:scale-105 shadow-sm hover:shadow-md"
                      >
                        <span>IP Restrictions</span>
                      </button>
                    </div>
                  </div>

                  <form onSubmit={handleEnhancementSubmit} className="space-y-3">
                    <textarea
                      value={enhancementInput}
                      onChange={(e) => setEnhancementInput(e.target.value)}
                      placeholder="Ask me to fix issues, explain findings, add security controls..."
                      className="w-full h-20 px-4 py-3 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl text-slate-900 text-sm placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none resize-none transition-all duration-300"
                      disabled={enhancementLoading}
                    />
                    
                    <button
                      type="submit"
                      disabled={enhancementLoading || !enhancementInput.trim()}
                      className="w-full bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white py-2.5 px-4 rounded-xl font-bold text-sm disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-xl hover:shadow-2xl flex items-center justify-center space-x-2 hover:scale-[1.02]"
                    >
                      {enhancementLoading ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          <span>Processing...</span>
                        </>
                      ) : (
                        <>
                          <Send className="w-4 h-4" />
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