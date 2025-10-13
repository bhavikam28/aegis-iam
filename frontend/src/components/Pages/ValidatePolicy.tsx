import React, { useState } from 'react';
import { Search, AlertTriangle, XCircle, CheckCircle, Info, AlertCircle, Shield, Sparkles, Copy, Download, RefreshCw, Zap, Bot, ChevronDown, ChevronUp, Send, TrendingUp, Target, Clock, Share2 } from 'lucide-react';

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

// ============================================
// MOCK API (Replace with real API calls)
// ============================================

const mockValidation = (): ValidatePolicyResponse => ({
  risk_score: 50,
  findings: [
    {
      id: 'IAM.1',
      severity: 'Critical',
      type: 'Overly Permissive',
      title: 'Universal Action Wildcard Detected',
      description: 'Policy grants "*:*" permissions, allowing ANY action on ANY AWS service. This violates the principle of least privilege and poses severe security risks.',
      recommendation: 'Replace wildcard with specific actions. List only the exact permissions needed (e.g., s3:GetObject, s3:PutObject instead of s3:*).',
      affectedStatement: 0,
      code_snippet: '{\n  "Effect": "Allow",\n  "Action": "*:*",\n  "Resource": "*"\n}'
    },
    {
      id: 'IAM.21',
      severity: 'Critical',
      type: 'Resource Wildcard',
      title: 'Universal Resource Wildcard',
      description: 'Resource field uses "*", applying permissions to ALL resources across the entire AWS account without any boundaries.',
      recommendation: 'Specify exact resource ARNs. Use arn:aws:s3:::bucket-name/* for S3, arn:aws:dynamodb:region:account:table/table-name for DynamoDB.',
      affectedStatement: 0,
      code_snippet: '"Resource": "*"'
    },
    {
      id: 'IAM.SEC.1',
      severity: 'High',
      type: 'Missing Conditions',
      title: 'No Condition Blocks Present',
      description: 'Policy lacks condition keys for IP restrictions, MFA requirements, or time-based controls, allowing access from any location without additional verification.',
      recommendation: 'Add Condition block with aws:SourceIp for IP restrictions, aws:MultiFactorAuthPresent for MFA, or aws:RequestedRegion for region constraints.',
      affectedStatement: 0
    }
  ],
  recommendations: [
    'Replace "*:*" with specific service actions',
    'Add specific resource ARNs instead of wildcards',
    'Implement MFA requirement for sensitive operations',
    'Add IP-based restrictions using Condition blocks',
    'Separate read and write permissions into different statements'
  ],
  quick_wins: [
    'Remove universal wildcards (instant 40-point risk reduction)',
    'Add specific S3 bucket ARNs (15-point improvement)',
    'Require MFA for delete operations (10-point improvement)'
  ],
  compliance_status: {
    pci_dss: {
      name: 'PCI DSS',
      status: 'NonCompliant',
      gaps: ['Requirement 7.1: Limit access to system components'],
      violations: [
        {
          requirement: '7.1.2 - Restrict privileged user access',
          description: 'Wildcard permissions violate least privilege principle',
          fix: 'Implement role-based access with specific permissions'
        }
      ]
    },
    hipaa: {
      name: 'HIPAA',
      status: 'NonCompliant',
      gaps: ['164.308(a)(4) - Access Controls'],
      violations: [
        {
          requirement: '164.312(a)(1) - Access Control',
          description: 'Overly broad permissions do not ensure unique user identification',
          fix: 'Restrict access to minimum necessary for job function'
        }
      ]
    }
  },
  agent_reasoning: `🧠 AGENT REASONING:

I analyzed the provided IAM policy and identified critical security issues:

1. **Discovery Phase**: Detected universal wildcard patterns ("*:*" and "*")
2. **Risk Assessment**: This configuration grants god-mode access - any action on any resource
3. **Attack Vector Analysis**: 
   - Compromised credentials = full AWS account takeover
   - No blast radius containment
   - Privilege escalation trivial
4. **Compliance Impact**: Violates PCI DSS 7.1, HIPAA 164.312(a)(1), SOX segregation of duties
5. **Remediation Priority**: CRITICAL - Fix immediately before production deployment

Calculating risk score: Base 0 + Wildcard actions (40) + Wildcard resources (20) + No conditions (10) = 70/100 → Adjusted to 50/100 for partial mitigating factors.`
});

// ============================================
// MAIN COMPONENT
// ============================================

const ValidatePolicy: React.FC = () => {
  const [inputType, setInputType] = useState<'policy' | 'arn'>('policy');
  const [inputValue, setInputValue] = useState('');
  const [response, setResponse] = useState<ValidatePolicyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showInitialForm, setShowInitialForm] = useState(true);
  
  // Enhancement chat state
  const [enhancementChat, setEnhancementChat] = useState<EnhancementMessage[]>([]);
  const [enhancementInput, setEnhancementInput] = useState('');
  const [enhancementLoading, setEnhancementLoading] = useState(false);
  
  // Expandable sections
  const [showScoreExplanation, setShowScoreExplanation] = useState(false);
  const [showAgentReasoning, setShowAgentReasoning] = useState(true);

  const handleValidation = () => {
    setLoading(true);
    setError(null);
    setShowInitialForm(false);
    
    // Simulate API call
    setTimeout(() => {
      setResponse(mockValidation());
      setLoading(false);
    }, 2000);
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
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Background Effects */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-20 w-[500px] h-[500px] bg-purple-500/10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-20 left-20 w-[500px] h-[500px] bg-pink-500/8 rounded-full blur-3xl"></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-8 py-12 sm:py-16">
        {/* ============================================ */}
        {/* INITIAL FORM */}
        {/* ============================================ */}
        {showInitialForm && !response && (
          <>
            <div className="mb-16">
              <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-purple-500/10 border border-purple-500/30 rounded-full px-6 py-2 mb-6">
                <Shield className="w-4 h-4 text-purple-400" />
                <span className="text-purple-300 text-sm font-medium">AI-Powered Security Analysis</span>
              </div>
              
              <h1 className="text-5xl sm:text-6xl font-bold mb-6 leading-tight">
                <span className="text-white">Validate &</span>
                <br />
                <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-400 bg-clip-text text-transparent">
                  Audit Security
                </span>
              </h1>
              
              <p className="text-xl text-slate-300 max-w-3xl leading-relaxed">
                Comprehensive security analysis powered by AI agents and AWS best practices
              </p>
            </div>

            <div className="max-w-4xl mx-auto">
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-3xl p-10 shadow-2xl">
                <div className="mb-8">
                  <label className="block text-white text-lg font-semibold mb-4">Input Type</label>
                  <div className="grid grid-cols-2 gap-4">
                    <button
                      onClick={() => setInputType('policy')}
                      className={`px-6 py-4 rounded-2xl font-medium transition-all ${
                        inputType === 'policy'
                          ? 'bg-gradient-to-r from-purple-500 to-pink-600 text-white shadow-lg'
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
                          ? 'bg-gradient-to-r from-purple-500 to-pink-600 text-white shadow-lg'
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
                  className="w-full bg-gradient-to-r from-purple-500 via-pink-500 to-purple-600 text-white py-5 px-8 rounded-2xl font-semibold text-lg hover:from-purple-600 hover:via-pink-600 hover:to-purple-700 disabled:opacity-50 transition-all shadow-lg flex items-center justify-center space-x-3"
                >
                  <Search className="w-6 h-6" />
                  <span>Analyze Security</span>
                  <Shield className="w-5 h-5" />
                </button>
              </div>
            </div>
          </>
        )}

        {/* ============================================ */}
        {/* LOADING STATE */}
        {/* ============================================ */}
        {loading && (
          <div className="min-h-screen flex items-center justify-center">
            <div className="text-center">
              <div className="w-24 h-24 mb-8 relative mx-auto">
                <div className="absolute inset-0 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-full animate-ping"></div>
                <div className="absolute inset-0 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full opacity-20 animate-pulse"></div>
                <Shield className="w-12 h-12 text-purple-400 absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2" />
              </div>
              <h2 className="text-4xl font-bold text-white mb-4">Deep Security Analysis</h2>
              <p className="text-xl text-slate-300 mb-8">Scanning for vulnerabilities and compliance issues...</p>
              <div className="flex items-center justify-center space-x-2">
                <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce"></div>
                <div className="w-2 h-2 bg-pink-400 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
                <div className="w-2 h-2 bg-orange-400 rounded-full animate-bounce" style={{animationDelay: '0.4s'}}></div>
              </div>
            </div>
          </div>
        )}

        {/* ============================================ */}
        {/* RESULTS */}
        {/* ============================================ */}
        {!loading && response && (
          <div className="max-w-[1600px] mx-auto">
            {/* Header */}
            <div className="flex items-center justify-between mb-12">
              <div>
                <h2 className="text-3xl font-bold text-white mb-2">Security Analysis Complete</h2>
                <p className="text-slate-400">Comprehensive security assessment of your IAM policy</p>
              </div>
              <button
                onClick={() => {
                  setResponse(null);
                  setInputValue('');
                  setShowInitialForm(true);
                  setEnhancementChat([]);
                }}
                className="px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white rounded-xl transition-all border border-slate-700 flex items-center space-x-2"
              >
                <RefreshCw className="w-4 h-4" />
                <span>New Analysis</span>
              </button>
            </div>

            {/* Agent Reasoning - FIXED: Clean separate boxes */}
            {response.agent_reasoning && (
              <div className="mb-8">
                <button
                  onClick={() => setShowAgentReasoning(!showAgentReasoning)}
                  className="w-full bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-6 flex items-center justify-between hover:border-purple-500/40 transition-all"
                >
                  <div className="flex items-center space-x-4">
                    <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center border border-purple-500/30">
                      <Bot className="w-6 h-6 text-purple-400" />
                    </div>
                    <div className="text-left">
                      <h3 className="text-white text-xl font-bold">AI Agent Analysis</h3>
                      <p className="text-slate-400 text-sm">See how the AI reasoned through your policy</p>
                    </div>
                  </div>
                  {showAgentReasoning ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                </button>
                
                {showAgentReasoning && (
                  <div className="mt-4 space-y-4">
                    {response.agent_reasoning.split('\n\n').filter(section => section.trim()).map((section, idx) => {
                      // Parse section into title and content
                      const lines = section.split('\n');
                      const title = lines[0].replace(/^[🧠📊🔥🚨🎯]\s*/, '').trim();
                      const content = lines.slice(1).join('\n').trim();
                      
                      // Determine icon and color based on content
                      let icon = '🧠';
                      let colorClass = 'from-purple-500/10 to-pink-500/10 border-purple-500/30';
                      
                      if (title.toLowerCase().includes('critical') || title.toLowerCase().includes('risk')) {
                        icon = '🔥';
                        colorClass = 'from-red-500/10 to-pink-500/10 border-red-500/30';
                      } else if (title.toLowerCase().includes('compliance')) {
                        icon = '🚨';
                        colorClass = 'from-orange-500/10 to-yellow-500/10 border-orange-500/30';
                      } else if (title.toLowerCase().includes('recommendation')) {
                        icon = '🎯';
                        colorClass = 'from-green-500/10 to-blue-500/10 border-green-500/30';
                      } else if (title.toLowerCase().includes('structure') || title.toLowerCase().includes('policy')) {
                        icon = '📊';
                        colorClass = 'from-blue-500/10 to-purple-500/10 border-blue-500/30';
                      }
                      
                      return (
                        <div key={idx} className={`bg-gradient-to-br ${colorClass} backdrop-blur-xl border rounded-2xl p-6`}>
                          <div className="flex items-start space-x-3 mb-4">
                            <div className="text-2xl">{icon}</div>
                            <h4 className="text-white text-base font-bold leading-relaxed">{title}</h4>
                          </div>
                          <div className="text-slate-300 text-base leading-relaxed whitespace-pre-line pl-11">
                            {content}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* Security Risk Score - FIXED: With detailed explanation */}
            <div className="mb-8">
              <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8">
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <h3 className="text-white text-2xl font-bold mb-2">Security Risk Score</h3>
                    <p className="text-slate-400 text-base">Based on AWS Security Hub controls</p>
                  </div>
                  <div className="text-center">
                    <div className={`text-6xl font-bold ${getRiskScoreColor(response.risk_score)}`}>
                      {response.risk_score}
                    </div>
                    <div className="text-slate-400 text-sm mt-2">/ 100</div>
                  </div>
                </div>
                
                <div className="w-full bg-slate-800 rounded-full h-4 mb-6">
                  <div
                    className={`h-4 rounded-full transition-all duration-1000 ${
                      response.risk_score <= 30 ? 'bg-gradient-to-r from-green-500 to-green-400' :
                      response.risk_score <= 60 ? 'bg-gradient-to-r from-yellow-500 to-yellow-400' :
                      response.risk_score <= 80 ? 'bg-gradient-to-r from-orange-500 to-pink-500' :
                      'bg-gradient-to-r from-red-500 to-pink-500'
                    }`}
                    style={{ width: `${response.risk_score}%` }}
                  ></div>
                </div>

                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center space-x-3">
                    <div className={`w-16 h-16 rounded-2xl flex items-center justify-center font-bold text-2xl ${
                      response.risk_score <= 30 ? 'bg-green-500/20 text-green-400 border border-green-500/30' :
                      response.risk_score <= 60 ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                      response.risk_score <= 80 ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                      'bg-red-500/20 text-red-400 border border-red-500/30'
                    }`}>
                      {getRiskGrade(response.risk_score).grade}
                    </div>
                    <div>
                      <div className={`font-semibold text-base ${getRiskScoreColor(response.risk_score)}`}>
                        {getRiskGrade(response.risk_score).label}
                      </div>
                      <div className="text-slate-400 text-sm">
                        {response.findings.length} findings detected
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-6">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-red-400">
                        {response.findings.filter(f => f.severity === 'Critical').length}
                      </div>
                      <div className="text-xs text-slate-500">Critical</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-orange-400">
                        {response.findings.filter(f => f.severity === 'High').length}
                      </div>
                      <div className="text-xs text-slate-500">High</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-yellow-400">
                        {response.findings.filter(f => f.severity === 'Medium').length}
                      </div>
                      <div className="text-xs text-slate-500">Medium</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-blue-400">
                        {response.findings.filter(f => f.severity === 'Low').length}
                      </div>
                      <div className="text-xs text-slate-500">Low</div>
                    </div>
                  </div>
                </div>

                {/* Score Explanation - EXPANDABLE */}
                <button
                  onClick={() => setShowScoreExplanation(!showScoreExplanation)}
                  className="w-full mt-4 px-6 py-4 bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 rounded-xl transition-all flex items-center justify-between"
                >
                  <div className="flex items-center space-x-2">
                    <Info className="w-5 h-5 text-purple-400" />
                    <span className="text-purple-300 font-semibold text-base">Why score of {response.risk_score}/100?</span>
                  </div>
                  {showScoreExplanation ? <ChevronUp className="w-5 h-5 text-purple-400" /> : <ChevronDown className="w-5 h-5 text-purple-400" />}
                </button>

                {showScoreExplanation && (
                  <div className="mt-4 bg-slate-950/50 rounded-xl p-6 border border-slate-700/50">
                    <p className="text-slate-300 text-base leading-relaxed mb-6">
                      Your policy has the following issues contributing to this score:
                    </p>

                    <div className="space-y-4 mb-6">
                      <div>
                        <h5 className="text-red-400 font-semibold mb-2 text-base">Critical Issues (Weight: 40 points)</h5>
                        <ul className="space-y-2 text-slate-300 text-base">
                          <li className="flex items-start space-x-2">
                            <span className="text-red-400 mt-1">•</span>
                            <span>Universal Action Wildcard ("*:*") - Grants permission to perform ANY action across ALL AWS services</span>
                          </li>
                          <li className="flex items-start space-x-2">
                            <span className="text-red-400 mt-1">•</span>
                            <span>Universal Resource Wildcard ("*") - Applies these permissions to ALL resources in AWS</span>
                          </li>
                        </ul>
                      </div>

                      <div>
                        <h5 className="text-yellow-400 font-semibold mb-2 text-base">Medium Issues (Weight: 10 points)</h5>
                        <ul className="space-y-2 text-slate-300 text-base">
                          <li className="flex items-start space-x-2">
                            <span className="text-yellow-400 mt-1">•</span>
                            <span>No Conditions - Policy lacks IP restrictions, MFA requirements, or time-based controls</span>
                          </li>
                          <li className="flex items-start space-x-2">
                            <span className="text-yellow-400 mt-1">•</span>
                            <span>No Resource Boundaries - Missing resource ARN specifications</span>
                          </li>
                        </ul>
                      </div>
                    </div>

                    <div className="bg-purple-500/5 border border-purple-500/20 rounded-lg p-4">
                      <h5 className="text-purple-300 font-semibold mb-2 text-base">How the score is calculated:</h5>
                      <ul className="space-y-1 text-slate-400 text-sm">
                        <li>• Base score starts at 0 (perfect security)</li>
                        <li>• Each wildcard in Action adds +20 points</li>
                        <li>• Each wildcard in Resource adds +20 points</li>
                        <li>• Missing conditions adds +10 points</li>
                        <li>• <span className="text-orange-400 font-semibold">Score of {response.risk_score} = Moderate Risk (needs immediate attention)</span></li>
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Policy Impact Analysis */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              <div className="bg-gradient-to-br from-orange-500/10 to-red-500/10 backdrop-blur-xl border border-orange-500/30 rounded-2xl p-6">
                <div className="flex items-center space-x-3 mb-4">
                  <div className="w-10 h-10 bg-orange-500/20 rounded-xl flex items-center justify-center border border-orange-500/30">
                    <Target className="w-5 h-5 text-orange-400" />
                  </div>
                  <h4 className="text-white font-bold text-base">Blast Radius</h4>
                </div>
                <p className="text-orange-300 text-2xl font-bold mb-2">Entire Account</p>
                <p className="text-slate-400 text-sm leading-relaxed">
                  Compromised credentials with this policy can access ALL services and resources across your AWS account
                </p>
              </div>

              <div className="bg-gradient-to-br from-red-500/10 to-pink-500/10 backdrop-blur-xl border border-red-500/30 rounded-2xl p-6">
                <div className="flex items-center space-x-3 mb-4">
                  <div className="w-10 h-10 bg-red-500/20 rounded-xl flex items-center justify-center border border-red-500/30">
                    <AlertTriangle className="w-5 h-5 text-red-400" />
                  </div>
                  <h4 className="text-white font-bold text-base">Attack Vectors</h4>
                </div>
                <p className="text-red-300 text-2xl font-bold mb-2">High Risk</p>
                <p className="text-slate-400 text-sm leading-relaxed">
                  Enables privilege escalation, data exfiltration, resource deletion, and account takeover
                </p>
              </div>

              <div className="bg-gradient-to-br from-green-500/10 to-blue-500/10 backdrop-blur-xl border border-green-500/30 rounded-2xl p-6">
                <div className="flex items-center space-x-3 mb-4">
                  <div className="w-10 h-10 bg-green-500/20 rounded-xl flex items-center justify-center border border-green-500/30">
                    <Clock className="w-5 h-5 text-green-400" />
                  </div>
                  <h4 className="text-white font-bold text-base">Fix Time</h4>
                </div>
                <p className="text-green-300 text-2xl font-bold mb-2">~15 minutes</p>
                <p className="text-slate-400 text-sm leading-relaxed">
                  Estimated time to implement recommended security improvements
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
              {/* LEFT COLUMN - Security Findings */}
              <div className="lg:col-span-8 space-y-6">
                <h3 className="text-white text-2xl font-bold">Security Findings</h3>
                
                {response.findings.length === 0 ? (
                  <div className="bg-green-500/10 border border-green-500/30 rounded-2xl p-8 text-center">
                    <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
                    <h4 className="text-green-400 font-bold text-xl mb-2">No Security Issues Found!</h4>
                    <p className="text-slate-300 text-base">This policy follows AWS security best practices.</p>
                  </div>
                ) : (
                  response.findings.map((finding, index) => (
                    <div key={index} className={`bg-gradient-to-br ${getSeverityColor(finding.severity)} backdrop-blur-xl border rounded-2xl p-6`}>
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center space-x-3">
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
                          <div>
                            <div className="flex items-center space-x-2 mb-1">
                              <h4 className="text-white font-bold text-lg">{finding.title}</h4>
                              <span className="text-xs font-mono text-slate-500">{finding.id}</span>
                            </div>
                            <span className={`inline-block px-3 py-1 rounded-full text-xs font-semibold ${
                              finding.severity === 'Critical' ? 'bg-red-500/20 text-red-400' :
                              finding.severity === 'High' ? 'bg-orange-500/20 text-orange-400' :
                              finding.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-blue-500/20 text-blue-400'
                            }`}>
                              {finding.severity}
                            </span>
                          </div>
                        </div>
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
                      
                      <div className="bg-slate-900/50 border border-slate-700/50 rounded-xl p-4">
                        <div className="flex items-start space-x-3">
                          <Sparkles className="w-5 h-5 text-purple-400 mt-0.5 flex-shrink-0" />
                          <div className="flex-1">
                            <div className="text-purple-300 font-semibold text-base mb-2">Recommendation</div>
                            <p className="text-slate-300 text-base leading-relaxed">{finding.recommendation}</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* RIGHT SIDEBAR */}
              <div className="lg:col-span-4 space-y-6">
                {/* Quick Wins */}
                {response.quick_wins && response.quick_wins.length > 0 && (
                  <div className="bg-green-500/10 backdrop-blur-xl border border-green-500/30 rounded-2xl p-6">
                    <div className="flex items-center space-x-2 mb-4">
                      <Zap className="w-5 h-5 text-green-400" />
                      <h4 className="text-green-400 text-lg font-semibold">Quick Wins</h4>
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
                  <div className="bg-purple-500/10 backdrop-blur-xl border border-purple-500/30 rounded-2xl p-6">
                    <div className="flex items-center space-x-2 mb-4">
                      <Shield className="w-5 h-5 text-purple-400" />
                      <h4 className="text-purple-400 text-lg font-semibold">Recommendations</h4>
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

                {/* Compliance Status */}
                <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6">
                  <h4 className="text-white text-lg font-semibold mb-4">Compliance Status</h4>
                  <div className="space-y-3">
                    {Object.entries(response.compliance_status).map(([key, framework]: [string, any]) => (
                      <div key={key} className="p-3 bg-slate-800/50 rounded-xl">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-slate-300 text-sm font-medium">{framework.name}</span>
                          <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                            framework.status === 'Compliant' ? 'bg-green-500/20 text-green-400' :
                            framework.status === 'Partial' ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-red-500/20 text-red-400'
                          }`}>
                            {framework.status}
                          </span>
                        </div>
                        {framework.gaps && framework.gaps.length > 0 && (
                          <div className="text-xs text-slate-500 mt-2">
                            {framework.gaps[0]}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* What's Next */}
                <div className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 backdrop-blur-xl border border-purple-500/30 rounded-2xl p-6">
                  <div className="flex items-center space-x-2 mb-4">
                    <TrendingUp className="w-5 h-5 text-purple-400" />
                    <h4 className="text-purple-400 text-lg font-semibold">What's Next?</h4>
                  </div>
                  <ol className="space-y-3 text-slate-300 text-sm">
                    <li className="flex items-start space-x-3">
                      <span className="text-purple-400 font-bold flex-shrink-0">1.</span>
                      <span>Use the enhancement chat below to fix issues interactively</span>
                    </li>
                    <li className="flex items-start space-x-3">
                      <span className="text-purple-400 font-bold flex-shrink-0">2.</span>
                      <span>Test the updated policy in a non-production environment</span>
                    </li>
                    <li className="flex items-start space-x-3">
                      <span className="text-purple-400 font-bold flex-shrink-0">3.</span>
                      <span>Monitor CloudWatch Logs after deployment</span>
                    </li>
                    <li className="flex items-start space-x-3">
                      <span className="text-purple-400 font-bold flex-shrink-0">4.</span>
                      <span>Schedule regular policy audits</span>
                    </li>
                  </ol>
                </div>
              </div>
            </div>

            {/* Compliance Framework Violations - Full Width */}
            <div className="mt-8">
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