import React, { useState } from 'react';
import { Search, AlertTriangle, XCircle, CheckCircle, Info, AlertCircle, Shield, Sparkles, Copy, Download, RefreshCw, Zap, Bot } from 'lucide-react';

// Type definitions
interface SecurityFinding {
  id: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  type: string;
  title: string;
  description: string;
  recommendation: string;
  affectedStatement?: number;
}

interface ComplianceFramework {
  name: string;
  status: 'Compliant' | 'NonCompliant' | 'Partial';
  gaps?: string[];
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

interface ValidatePolicyRequest {
  policy_json?: string;
  role_arn?: string;
  compliance_frameworks?: string[];
}

interface AuditProgressEvent {
  type: 'thinking' | 'progress' | 'complete' | 'error';
  message: string;
  progress: number;
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

// API functions (inline)
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const validatePolicy = async (request: ValidatePolicyRequest): Promise<ValidatePolicyResponse> => {
  const mode = request.policy_json || request.role_arn ? 'quick' : 'audit';
  
  const response = await fetch(`${API_URL}/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      policy_json: request.policy_json || null,
      role_arn: request.role_arn || null,
      compliance_frameworks: request.compliance_frameworks || ['pci_dss', 'hipaa', 'sox', 'gdpr', 'cis'],
      mode: mode
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Validation failed: ${response.status} - ${errorText}`);
  }

  const backendResponse = await response.json();
  
  if (!backendResponse.success) {
    throw new Error(backendResponse.error || 'Validation failed');
  }

  return {
    findings: backendResponse.findings || [],
    risk_score: backendResponse.risk_score || 50,
    security_issues: backendResponse.findings?.map((f: any) => f.description) || [],
    recommendations: backendResponse.recommendations || [],
    compliance_status: backendResponse.compliance_status || {},
    quick_wins: backendResponse.quick_wins || [],
    audit_summary: backendResponse.audit_summary || null,
    top_risks: backendResponse.top_risks || [],
    agent_reasoning: backendResponse.agent_reasoning || backendResponse.raw_response || null
  };
};

const performStreamingAudit = async (
  request: { compliance_frameworks?: string[] },
  onProgress: (event: AuditProgressEvent) => void
): Promise<ValidatePolicyResponse> => {
  const response = await fetch(`${API_URL}/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      compliance_frameworks: request.compliance_frameworks || ['pci_dss', 'hipaa', 'sox', 'gdpr', 'cis']
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Audit failed: ${response.status} - ${errorText}`);
  }

  const result = await response.json();
  
  if (!result.success) {
    throw new Error(result.error || 'Audit failed');
  }

  // Simulate progress updates for better UX
  onProgress({ type: 'thinking', message: 'Starting autonomous audit...', progress: 10 });
  await new Promise(resolve => setTimeout(resolve, 500));
  
  onProgress({ type: 'progress', message: 'Fetching IAM roles...', progress: 30 });
  await new Promise(resolve => setTimeout(resolve, 500));
  
  onProgress({ type: 'progress', message: 'Analyzing policies...', progress: 60 });
  await new Promise(resolve => setTimeout(resolve, 500));
  
  onProgress({ type: 'progress', message: 'Running compliance checks...', progress: 85 });
  await new Promise(resolve => setTimeout(resolve, 500));
  
  onProgress({ type: 'complete', message: 'Audit complete!', progress: 100 });

  return {
    findings: result.findings || [],
    risk_score: result.risk_score || 50,
    security_issues: result.findings?.map((f: any) => f.description) || [],
    recommendations: result.recommendations || [],
    compliance_status: result.compliance_status || {},
    quick_wins: result.quick_wins || [],
    audit_summary: result.audit_summary || null,
    top_risks: result.top_risks || [],
    agent_reasoning: result.agent_reasoning || result.raw_response || null
  };
};

type ValidationMode = 'quick' | 'audit';
type InputType = 'policy' | 'arn';

const ValidatePolicy: React.FC = () => {
  // Mode selection
  const [mode, setMode] = useState<ValidationMode>('quick');
  
  // Quick mode state
  const [inputType, setInputType] = useState<InputType>('policy');
  const [inputValue, setInputValue] = useState('');
  
  // Shared state
  const [response, setResponse] = useState<ValidatePolicyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [auditProgress, setAuditProgress] = useState<AuditProgressEvent[]>([]);

  const handleCopy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleQuickValidation = async () => {
    if (!inputValue.trim()) return;

    setLoading(true);
    setError(null);
    setResponse(null);

    try {
      const request: ValidatePolicyRequest = inputType === 'policy' 
        ? { policy_json: inputValue, compliance_frameworks: ['pci_dss', 'hipaa', 'sox', 'gdpr', 'cis'] }
        : { role_arn: inputValue, compliance_frameworks: ['pci_dss', 'hipaa', 'sox', 'gdpr', 'cis'] };
      
      const result = await validatePolicy(request);
      setResponse(result);
    } catch (err) {
      console.error("Validation error:", err);
      setError(err instanceof Error ? err.message : 'Validation failed');
    } finally {
      setLoading(false);
    }
  };

  const handleAudit = async () => {
    setLoading(true);
    setError(null);
    setResponse(null);

    try {
      const result = await performAutonomousAudit({
        compliance_frameworks: ['pci_dss', 'hipaa', 'sox', 'gdpr', 'cis']
      });
      setResponse(result);
    } catch (err) {
      console.error("Audit error:", err);
      setError(err instanceof Error ? err.message : 'Audit failed');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: SecurityFinding['severity']) => {
    switch (severity) {
      case 'Critical': return 'from-red-500/20 to-pink-500/20 border-red-500/30 text-red-400';
      case 'High': return 'from-orange-500/20 to-pink-500/20 border-orange-500/30 text-orange-400';
      case 'Medium': return 'from-yellow-500/20 to-purple-500/10 border-yellow-500/30 text-yellow-400';
      case 'Low': return 'from-blue-500/20 to-purple-500/10 border-blue-500/30 text-blue-400';
    }
  };

  const getSeverityIcon = (severity: SecurityFinding['severity']) => {
    switch (severity) {
      case 'Critical': return XCircle;
      case 'High': return AlertTriangle;
      case 'Medium': return AlertCircle;
      case 'Low': return Info;
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score <= 30) return 'text-green-400';
    if (score <= 60) return 'text-yellow-400';
    if (score <= 80) return 'text-orange-400';
    return 'text-red-400';
  };

  const getRiskGrade = (score: number) => {
    if (score <= 30) return { grade: 'A', label: 'Excellent Security', color: 'green' };
    if (score <= 60) return { grade: 'B', label: 'Good Security', color: 'yellow' };
    if (score <= 80) return { grade: 'C', label: 'Moderate Risk', color: 'orange' };
    return { grade: 'F', label: 'High Risk', color: 'red' };
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Animated Background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-20 w-[500px] h-[500px] bg-purple-500/10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-20 left-20 w-[500px] h-[500px] bg-pink-500/8 rounded-full blur-3xl"></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-8 py-12 sm:py-16">
        {!loading && !response && (
          <>
            {/* Header */}
            <div className="mb-16">
              <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-purple-500/10 border border-purple-500/30 rounded-full px-6 py-2 mb-6 backdrop-blur-sm">
                <Sparkles className="w-4 h-4 text-purple-400" />
                <span className="text-purple-300 text-sm font-medium">AI-Powered Security Analysis</span>
              </div>
              
              <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold mb-6 leading-tight">
                <span className="text-white">Validate &</span>
                <br />
                <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-400 bg-clip-text text-transparent">
                  Audit Security
                </span>
              </h1>
              
              <p className="text-xl text-slate-300 max-w-3xl leading-relaxed">
                Choose your security analysis mode: Quick validation for individual policies, or autonomous 
                full-account audit powered by AI agents and MCP servers.
              </p>
            </div>

            {/* What is Security Validation? Educational Section */}
            <div className="max-w-5xl mx-auto mb-12">
              <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-purple-500/20 rounded-3xl p-8 sm:p-10">
                <div className="flex items-start space-x-4 mb-6">
                  <div className="w-14 h-14 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-2xl flex items-center justify-center flex-shrink-0 border border-purple-500/30">
                    <Shield className="w-7 h-7 text-purple-400" />
                  </div>
                  <div>
                    <h3 className="text-2xl font-bold text-white mb-2">What is IAM Security Validation?</h3>
                    <p className="text-slate-400 text-sm">Understanding the importance of security analysis</p>
                  </div>
                </div>

                <div className="grid md:grid-cols-3 gap-6">
                  <div className="bg-slate-800/30 rounded-2xl p-6 border border-slate-700/50">
                    <div className="w-10 h-10 bg-orange-500/10 rounded-xl flex items-center justify-center mb-4 border border-orange-500/30">
                      <Search className="w-5 h-5 text-orange-400" />
                    </div>
                    <h4 className="text-white font-semibold mb-2">Find Vulnerabilities</h4>
                    <p className="text-slate-400 text-sm leading-relaxed">
                      Identify overly permissive policies, privilege escalation risks, and security misconfigurations before attackers do.
                    </p>
                  </div>

                  <div className="bg-slate-800/30 rounded-2xl p-6 border border-slate-700/50">
                    <div className="w-10 h-10 bg-purple-500/10 rounded-xl flex items-center justify-center mb-4 border border-purple-500/30">
                      <CheckCircle className="w-5 h-5 text-purple-400" />
                    </div>
                    <h4 className="text-white font-semibold mb-2">Ensure Compliance</h4>
                    <p className="text-slate-400 text-sm leading-relaxed">
                      Validate against PCI DSS, HIPAA, SOX, GDPR, and CIS benchmarks to meet regulatory requirements and industry standards.
                    </p>
                  </div>

                  <div className="bg-slate-800/30 rounded-2xl p-6 border border-slate-700/50">
                    <div className="w-10 h-10 bg-pink-500/10 rounded-xl flex items-center justify-center mb-4 border border-pink-500/30">
                      <Shield className="w-5 h-5 text-pink-400" />
                    </div>
                    <h4 className="text-white font-semibold mb-2">Prevent Breaches</h4>
                    <p className="text-slate-400 text-sm leading-relaxed">
                      Proactively detect and fix security issues that could lead to data breaches, unauthorized access, or compliance violations.
                    </p>
                  </div>
                </div>

                <div className="mt-6 bg-purple-500/5 border border-purple-500/20 rounded-xl p-4 flex items-start space-x-3">
                  <Info className="w-5 h-5 text-purple-400 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-slate-300 text-sm leading-relaxed">
                      <span className="font-semibold text-purple-300">Pro Tip:</span> Regular security validation helps you maintain least-privilege access, 
                      reduce attack surface, and detect drift from security baselines—all critical for cloud security posture management.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* MODE SELECTION */}
            <div className="max-w-5xl mx-auto mb-12">
              <div className="text-center mb-8">
                <h2 className="text-3xl font-bold text-white mb-3">Choose Analysis Mode</h2>
                <p className="text-slate-400">Select the type of security assessment you need</p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Quick Validation Card */}
                <button
                  onClick={() => setMode('quick')}
                  className={`relative group text-left transition-all duration-300 ${
                    mode === 'quick'
                      ? 'scale-[1.02]'
                      : 'hover:scale-[1.01]'
                  }`}
                >
                  <div className={`absolute inset-0 rounded-3xl transition-all ${
                    mode === 'quick'
                      ? 'bg-gradient-to-br from-purple-500/20 via-pink-500/20 to-purple-500/20 blur-xl'
                      : 'bg-gradient-to-br from-slate-800/50 to-slate-900/50 blur-xl opacity-0 group-hover:opacity-100'
                  }`}></div>
                  
                  <div className={`relative p-8 rounded-3xl border-2 transition-all backdrop-blur-xl ${
                    mode === 'quick'
                      ? 'border-purple-500 bg-gradient-to-br from-purple-500/10 via-pink-500/5 to-purple-500/10 shadow-2xl shadow-purple-500/25'
                      : 'border-slate-700 bg-slate-900/50 group-hover:border-purple-500/50 group-hover:bg-gradient-to-br group-hover:from-purple-500/5 group-hover:via-pink-500/5 group-hover:to-purple-500/5'
                  }`}>
                    {/* Badge */}
                    <div className="inline-flex items-center space-x-2 bg-purple-500/10 border border-purple-500/30 rounded-full px-4 py-1.5 mb-6">
                      <Zap className="w-3.5 h-3.5 text-purple-400" />
                      <span className="text-purple-300 text-xs font-semibold">FAST</span>
                    </div>

                    <div className="flex items-start space-x-4 mb-6">
                      <div className={`w-16 h-16 rounded-2xl flex items-center justify-center transition-all ${
                        mode === 'quick'
                          ? 'bg-gradient-to-br from-purple-500/30 to-pink-500/30 border border-purple-500/50 shadow-lg shadow-purple-500/25'
                          : 'bg-slate-800/50 border border-slate-700 group-hover:bg-gradient-to-br group-hover:from-purple-500/20 group-hover:to-pink-500/20 group-hover:border-purple-500/40'
                      }`}>
                        <Search className="w-8 h-8 text-purple-400" />
                      </div>
                      <div className="flex-1">
                        <h3 className="text-2xl font-bold text-white mb-2">Quick Validation</h3>
                        <p className="text-slate-400 text-sm leading-relaxed">
                          Analyze a single IAM policy or role. Perfect for spot-checks and rapid security assessments.
                        </p>
                      </div>
                    </div>
                    
                    <div className="space-y-3 mb-6">
                      <div className="flex items-start space-x-3">
                        <CheckCircle className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                        <span className="text-slate-300 text-sm">Paste policy JSON or provide role ARN</span>
                      </div>
                      <div className="flex items-start space-x-3">
                        <CheckCircle className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                        <span className="text-slate-300 text-sm">Get results in ~5 seconds</span>
                      </div>
                      <div className="flex items-start space-x-3">
                        <CheckCircle className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                        <span className="text-slate-300 text-sm">Uses MCP servers for role ARN analysis</span>
                      </div>
                      <div className="flex items-start space-x-3">
                        <CheckCircle className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                        <span className="text-slate-300 text-sm">Multi-framework compliance checking</span>
                      </div>
                    </div>

                    <div className="bg-purple-500/5 border border-purple-500/20 rounded-xl p-4">
                      <div className="flex items-center space-x-2 mb-2">
                        <Shield className="w-4 h-4 text-purple-400" />
                        <span className="text-purple-300 text-xs font-semibold">BEST FOR</span>
                      </div>
                      <p className="text-slate-400 text-sm">
                        Individual policy reviews, pre-deployment checks, and quick security validations
                      </p>
                    </div>
                    
                    {mode === 'quick' && (
                      <div className="absolute top-4 right-4 w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full flex items-center justify-center shadow-lg shadow-purple-500/50">
                        <CheckCircle className="w-6 h-6 text-white" />
                      </div>
                    )}
                  </div>
                </button>

                {/* Autonomous Audit Card */}
                <button
                  onClick={() => setMode('audit')}
                  className={`relative group text-left transition-all duration-300 ${
                    mode === 'audit'
                      ? 'scale-[1.02]'
                      : 'hover:scale-[1.01]'
                  }`}
                >
                  <div className={`absolute inset-0 rounded-3xl transition-all ${
                    mode === 'audit'
                      ? 'bg-gradient-to-br from-orange-500/20 via-pink-500/20 to-purple-500/20 blur-xl'
                      : 'bg-gradient-to-br from-slate-800/50 to-slate-900/50 blur-xl opacity-0 group-hover:opacity-100'
                  }`}></div>
                  
                  <div className={`relative p-8 rounded-3xl border-2 transition-all backdrop-blur-xl ${
                    mode === 'audit'
                      ? 'border-orange-500 bg-gradient-to-br from-orange-500/10 via-pink-500/5 to-purple-500/10 shadow-2xl shadow-orange-500/25'
                      : 'border-slate-700 bg-slate-900/50 group-hover:border-orange-500/50 group-hover:bg-gradient-to-br group-hover:from-orange-500/5 group-hover:via-pink-500/5 group-hover:to-purple-500/5'
                  }`}>
                    {/* Badge */}
                    <div className="inline-flex items-center space-x-2 bg-orange-500/10 border border-orange-500/30 rounded-full px-4 py-1.5 mb-6">
                      <Sparkles className="w-3.5 h-3.5 text-orange-400" />
                      <span className="text-orange-300 text-xs font-semibold">AI AGENT + MCP</span>
                    </div>

                    <div className="flex items-start space-x-4 mb-6">
                      <div className={`w-16 h-16 rounded-2xl flex items-center justify-center transition-all ${
                        mode === 'audit'
                          ? 'bg-gradient-to-br from-orange-500/30 to-pink-500/30 border border-orange-500/50 shadow-lg shadow-orange-500/25'
                          : 'bg-slate-800/50 border border-slate-700 group-hover:bg-gradient-to-br group-hover:from-orange-500/20 group-hover:to-pink-500/20 group-hover:border-orange-500/40'
                      }`}>
                        <Bot className="w-8 h-8 text-orange-400" />
                      </div>
                      <div className="flex-1">
                        <h3 className="text-2xl font-bold text-white mb-2">Full Account Audit</h3>
                        <p className="text-slate-400 text-sm leading-relaxed">
                          Autonomous AI agent scans your entire AWS account for security vulnerabilities and compliance gaps.
                        </p>
                      </div>
                    </div>
                    
                    <div className="space-y-3 mb-6">
                      <div className="flex items-start space-x-3">
                        <Zap className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                        <span className="text-slate-300 text-sm">Scans ALL IAM roles and policies automatically</span>
                      </div>
                      <div className="flex items-start space-x-3">
                        <Zap className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                        <span className="text-slate-300 text-sm">Autonomous AI decision-making and prioritization</span>
                      </div>
                      <div className="flex items-start space-x-3">
                        <Zap className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                        <span className="text-slate-300 text-sm">Uses system AWS credentials via MCP</span>
                      </div>
                      <div className="flex items-start space-x-3">
                        <Zap className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                        <span className="text-slate-300 text-sm">Comprehensive compliance and risk assessment</span>
                      </div>
                    </div>

                    <div className="bg-orange-500/5 border border-orange-500/20 rounded-xl p-4">
                      <div className="flex items-center space-x-2 mb-2">
                        <Bot className="w-4 h-4 text-orange-400" />
                        <span className="text-orange-300 text-xs font-semibold">BEST FOR</span>
                      </div>
                      <p className="text-slate-400 text-sm">
                        Complete security posture assessment, compliance audits, and organization-wide security reviews
                      </p>
                    </div>
                    
                    {mode === 'audit' && (
                      <div className="absolute top-4 right-4 w-10 h-10 bg-gradient-to-br from-orange-500 to-pink-500 rounded-full flex items-center justify-center shadow-lg shadow-orange-500/50">
                        <CheckCircle className="w-6 h-6 text-white" />
                      </div>
                    )}
                  </div>
                </button>
              </div>
            </div>

            {/* INPUT FORMS */}
            <div className="max-w-4xl mx-auto">
              {mode === 'quick' ? (
                // QUICK VALIDATION FORM
                <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-3xl p-8 sm:p-10 shadow-2xl">
                  {/* Input Type Toggle */}
                  <div className="mb-8">
                    <label className="block text-white text-lg font-semibold mb-4">Input Type</label>
                    <div className="grid grid-cols-2 gap-4">
                      <button
                        type="button"
                        onClick={() => setInputType('policy')}
                        className={`px-6 py-4 rounded-2xl font-medium transition-all ${
                          inputType === 'policy'
                            ? 'bg-gradient-to-r from-purple-500 via-pink-500 to-purple-600 text-white shadow-lg shadow-purple-500/25'
                            : 'bg-slate-800/50 text-slate-400 hover:text-white border border-slate-700/50'
                        }`}
                      >
                        <div className="flex items-center justify-center space-x-2">
                          <Shield className="w-5 h-5" />
                          <span>Policy JSON</span>
                        </div>
                      </button>
                      <button
                        type="button"
                        onClick={() => setInputType('arn')}
                        className={`px-6 py-4 rounded-2xl font-medium transition-all ${
                          inputType === 'arn'
                            ? 'bg-gradient-to-r from-purple-500 via-pink-500 to-purple-600 text-white shadow-lg shadow-purple-500/25'
                            : 'bg-slate-800/50 text-slate-400 hover:text-white border border-slate-700/50'
                        }`}
                      >
                        <div className="flex items-center justify-center space-x-2">
                          <Zap className="w-5 h-5" />
                          <span>Role ARN</span>
                        </div>
                      </button>
                    </div>
                  </div>

                  {/* Input Field */}
                  {inputType === 'policy' ? (
                    <div className="mb-8">
                      <label className="block text-white text-lg font-semibold mb-4">IAM Policy JSON</label>
                      <textarea
                        value={inputValue}
                        onChange={(e) => setInputValue(e.target.value)}
                        placeholder='{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "s3:*",\n      "Resource": "*"\n    }\n  ]\n}'
                        className="w-full h-64 px-6 py-5 bg-slate-800/50 border border-slate-600/50 rounded-2xl text-white text-base placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none resize-none font-mono leading-relaxed"
                      />
                      <p className="text-sm text-slate-500 mt-3">
                        Paste your IAM policy JSON for comprehensive security analysis
                      </p>
                    </div>
                  ) : (
                    <div className="mb-8">
                      <label className="block text-white text-lg font-semibold mb-4">IAM Role ARN</label>
                      <input
                        type="text"
                        value={inputValue}
                        onChange={(e) => setInputValue(e.target.value)}
                        placeholder="arn:aws:iam::123456789012:role/MyApplicationRole"
                        className="w-full px-6 py-5 bg-slate-800/50 border border-slate-600/50 rounded-2xl text-white text-lg placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none font-mono"
                      />
                      <p className="text-sm text-slate-500 mt-3">
                        MCP server will fetch and analyze the role's policies from AWS
                      </p>
                    </div>
                  )}

                  {/* Submit Button */}
                  <button
                    onClick={handleQuickValidation}
                    disabled={loading || !inputValue.trim()}
                    className="w-full bg-gradient-to-r from-purple-500 via-pink-500 to-purple-600 text-white py-5 px-8 rounded-2xl font-semibold text-lg hover:from-purple-600 hover:via-pink-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-purple-500/25 hover:shadow-xl hover:shadow-purple-500/40 flex items-center justify-center space-x-3"
                  >
                    <Search className="w-6 h-6" />
                    <span>Analyze Security Posture</span>
                    <Shield className="w-5 h-5" />
                  </button>
                </div>
              ) : (
                // AUTONOMOUS AUDIT FORM
                <div className="bg-slate-900/50 backdrop-blur-xl border border-orange-500/20 rounded-3xl p-8 sm:p-10 shadow-2xl">
                  <div className="mb-8 flex items-start space-x-4 bg-orange-500/10 border border-orange-500/30 rounded-2xl p-6">
                    <Bot className="w-8 h-8 text-orange-400 flex-shrink-0 mt-1" />
                    <div>
                      <h4 className="text-orange-400 font-bold text-lg mb-2">Autonomous AI Agent (MCP-Powered)</h4>
                      <p className="text-slate-300 text-sm leading-relaxed">
                        The AI agent will autonomously scan your entire AWS account using MCP servers. 
                        It uses your system's AWS credentials (from AWS CLI or environment variables). 
                        No manual credential input required!
                      </p>
                    </div>
                  </div>

                  {/* Security Note */}
                  <div className="mb-8 bg-purple-500/5 border border-purple-500/20 rounded-2xl p-6">
                    <div className="flex items-start space-x-3">
                      <Shield className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <h5 className="text-purple-300 font-semibold mb-2">Security & Permissions</h5>
                        <ul className="space-y-1 text-slate-400 text-sm">
                          <li>• Uses AWS credentials from your system (AWS CLI or environment variables)</li>
                          <li>• Read-only IAM permissions required (iam:ListRoles, iam:GetRolePolicy, iam:GetPolicy)</li>
                          <li>• MCP servers run on your backend with your configured credentials</li>
                          <li>• No credentials are sent through the frontend</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  {/* Compliance Frameworks Info */}
                  <div className="mb-8 bg-slate-800/50 border border-slate-700/50 rounded-2xl p-6">
                    <h5 className="text-white font-semibold mb-3">Compliance Frameworks to Check</h5>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="flex items-center space-x-2">
                        <CheckCircle className="w-4 h-4 text-green-400" />
                        <span className="text-slate-300 text-sm">PCI DSS</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <CheckCircle className="w-4 h-4 text-green-400" />
                        <span className="text-slate-300 text-sm">HIPAA</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <CheckCircle className="w-4 h-4 text-green-400" />
                        <span className="text-slate-300 text-sm">SOX</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <CheckCircle className="w-4 h-4 text-green-400" />
                        <span className="text-slate-300 text-sm">GDPR</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <CheckCircle className="w-4 h-4 text-green-400" />
                        <span className="text-slate-300 text-sm">CIS Benchmarks</span>
                      </div>
                    </div>
                  </div>

                  {/* Submit Button */}
                  <button
                    onClick={handleAudit}
                    disabled={loading}
                    className="w-full bg-gradient-to-r from-orange-500 via-pink-500 to-purple-600 text-white py-5 px-8 rounded-2xl font-semibold text-lg hover:from-orange-600 hover:via-pink-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-orange-500/25 hover:shadow-xl hover:shadow-orange-500/40 flex items-center justify-center space-x-3"
                  >
                    <Bot className="w-6 h-6" />
                    <span>Start Autonomous Audit</span>
                    <Sparkles className="w-5 h-5" />
                  </button>
                </div>
              )}

              {error && (
                <div className="mt-6 bg-red-500/10 border border-red-500/30 rounded-2xl p-6">
                  <div className="flex items-start space-x-3">
                    <XCircle className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <h4 className="text-red-400 font-semibold mb-1">Error</h4>
                      <p className="text-red-300 text-sm">{error}</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </>
        )}

        {/* Professional Loading State */}
        {loading && (
          <div className="relative overflow-hidden min-h-screen flex items-center justify-center">
            <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-purple-500/10 rounded-full blur-3xl animate-pulse"></div>
            <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-pink-500/10 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
            
            <div className="relative text-center px-8 max-w-2xl">
              <div className="inline-flex items-center justify-center w-24 h-24 mb-8 relative">
                <div className="absolute inset-0 bg-gradient-to-br from-orange-500/20 via-pink-500/20 to-purple-600/20 rounded-full animate-ping"></div>
                <div className="absolute inset-0 bg-gradient-to-br from-orange-500 via-pink-500 to-purple-600 rounded-full opacity-20 animate-pulse"></div>
                {mode === 'audit' ? (
                  <Bot className="w-12 h-12 text-orange-400 relative z-10" />
                ) : (
                  <Search className="w-12 h-12 text-purple-400 relative z-10" />
                )}
              </div>
              
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
                {mode === 'audit' ? 'Autonomous AI Audit Running' : 'Deep Security Analysis'}
              </h2>
              
              <p className="text-lg sm:text-xl text-slate-300 mb-8 leading-relaxed">
                {mode === 'audit' 
                  ? 'AI agent is autonomously scanning your entire AWS account using MCP servers...'
                  : 'Scanning for vulnerabilities, compliance issues, and security best practices...'
                }
              </p>

              {/* Real-Time Progress Timeline (for audit mode) */}
              {mode === 'audit' && auditProgress.length > 0 && (
                <div 
                  id="progress-container"
                  className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-6 max-h-[400px] overflow-y-auto mb-6 text-left"
                >
                  <div className="space-y-4">
                    {auditProgress.map((step, index) => (
                      <div 
                        key={index}
                        className={`flex items-start space-x-4 ${
                          step.type === 'error' ? 'text-red-400' :
                          step.type === 'complete' ? 'text-green-400' :
                          step.type === 'thinking' ? 'text-purple-400' :
                          'text-slate-300'
                        }`}
                      >
                        {step.type === 'thinking' ? (
                          <Bot className="w-5 h-5 mt-0.5 flex-shrink-0 animate-pulse" />
                        ) : step.type === 'complete' ? (
                          <CheckCircle className="w-5 h-5 mt-0.5 flex-shrink-0" />
                        ) : step.type === 'error' ? (
                          <XCircle className="w-5 h-5 mt-0.5 flex-shrink-0" />
                        ) : (
                          <Sparkles className="w-5 h-5 mt-0.5 flex-shrink-0" />
                        )}
                        
                        <div className="flex-1">
                          <div className="text-sm leading-relaxed">
                            {step.message}
                          </div>
                          
                          {step.type === 'progress' && step.progress < 100 && (
                            <div className="w-full bg-slate-800 rounded-full h-1 mt-2">
                              <div
                                className="bg-gradient-to-r from-orange-500 via-pink-500 to-purple-600 h-1 rounded-full transition-all duration-500"
                                style={{ width: `${step.progress}%` }}
                              ></div>
                            </div>
                          )}
                        </div>
                        
                        <div className="text-xs text-slate-500 flex-shrink-0">
                          {new Date().toLocaleTimeString()}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              <div className="flex items-center justify-center space-x-2 mb-8">
                <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0ms', animationDuration: '1s' }}></div>
                <div className="w-2 h-2 bg-pink-400 rounded-full animate-bounce" style={{ animationDelay: '200ms', animationDuration: '1s' }}></div>
                <div className="w-2 h-2 bg-orange-400 rounded-full animate-bounce" style={{ animationDelay: '400ms', animationDuration: '1s' }}></div>
              </div>

              <div className="text-sm text-slate-500">
                {mode === 'audit' ? 'This may take 30-60 seconds for large accounts...' : 'This may take up to 30 seconds...'}
              </div>
            </div>
          </div>
        )}

        {/* RESULTS DISPLAY */}
        {!loading && response && (
          <div className="max-w-[1600px] mx-auto">
            <div className="flex items-center justify-between mb-12">
              <div>
                <h2 className="text-3xl font-bold text-white mb-2">
                  {mode === 'audit' ? 'Autonomous Audit Complete' : 'Security Analysis Complete'}
                </h2>
                <p className="text-slate-400">
                  {mode === 'audit' 
                    ? `Analyzed ${response.audit_summary?.total_roles || 0} IAM roles across your AWS account`
                    : 'Comprehensive security assessment of your IAM policy'
                  }
                </p>
              </div>
              <button
                onClick={() => {
                  setResponse(null);
                  setInputValue('');
                  setError(null);
                  setAuditProgress([]);
                }}
                className="px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white rounded-xl transition-all border border-slate-700 flex items-center space-x-2"
              >
                <RefreshCw className="w-4 h-4" />
                <span>New Analysis</span>
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
              {/* Agent Reasoning Section - Full Width - PREMIUM */}
              {response.agent_reasoning && (
                <div className="lg:col-span-12">
                  <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8">
                    <div className="flex items-start space-x-4 mb-6">
                      <div className="w-14 h-14 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-2xl flex items-center justify-center flex-shrink-0 border border-purple-500/30">
                        <Bot className="w-7 h-7 text-purple-400 animate-pulse" />
                      </div>
                      <div>
                        <div className="flex items-center space-x-3 mb-2">
                          <h3 className="text-2xl font-bold text-white">Agent Reasoning</h3>
                          <span className="px-3 py-1 bg-purple-500/20 text-purple-300 text-xs font-semibold rounded-full border border-purple-500/30">AUTONOMOUS</span>
                        </div>
                        <p className="text-slate-400 text-sm">Real-time decision-making process</p>
                      </div>
                    </div>
                    
                    <div className="bg-slate-950/50 rounded-2xl p-6 border border-slate-700/50 overflow-x-auto max-h-[600px] overflow-y-auto"
                      style={{
                        scrollbarWidth: 'thin',
                        scrollbarColor: '#a855f7 #1e293b'
                      }}>
                      <pre className="text-slate-300 text-sm font-mono leading-relaxed whitespace-pre-wrap">
                        {response.agent_reasoning}
                      </pre>
                    </div>

                    <div className="mt-4 flex items-center space-x-2 text-sm text-slate-500">
                      <Sparkles className="w-4 h-4 text-purple-400" />
                      <span>This shows the AI agent's autonomous thinking and decision-making in real-time</span>
                    </div>
                  </div>
                </div>
              )}
              {/* Risk Score Card - Full Width */}
              <div className="lg:col-span-12">
                <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8">
                  <div className="flex items-center justify-between mb-6">
                    <div>
                      <h3 className="text-white text-2xl font-bold mb-2">Security Risk Score</h3>
                      <p className="text-slate-400">Based on AWS Security Hub controls and industry best practices</p>
                    </div>
                    <div className="text-center">
                      <div className={`text-6xl font-bold ${getRiskScoreColor(response.risk_score)}`}>
                        {response.risk_score}
                      </div>
                      <div className="text-slate-400 text-sm mt-2">/ 100</div>
                    </div>
                  </div>
                  
                  <div className="w-full bg-slate-800 rounded-full h-4 mb-4">
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

                  <div className="flex items-center justify-between">
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
                        <div className={`font-semibold ${getRiskScoreColor(response.risk_score)}`}>
                          {getRiskGrade(response.risk_score).label}
                        </div>
                        <div className="text-slate-500 text-sm">
                          {response.findings.length} security findings detected
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
                </div>
              </div>

              {/* Audit Summary (only for audit mode) */}
              {response.audit_summary && (
                <div className="lg:col-span-12">
                  <div className="bg-gradient-to-br from-orange-500/10 to-purple-500/10 backdrop-blur-xl border border-orange-500/30 rounded-2xl p-8">
                    <div className="flex items-center space-x-3 mb-6">
                      <Bot className="w-6 h-6 text-orange-400" />
                      <h3 className="text-white text-2xl font-bold">Autonomous Audit Summary</h3>
                    </div>
                    
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                      <div className="bg-slate-800/50 rounded-xl p-4 text-center border border-slate-700/50">
                        <div className="text-3xl font-bold text-purple-400 mb-1">
                          {response.audit_summary.total_roles}
                        </div>
                        <div className="text-sm text-slate-400">Total Roles</div>
                      </div>
                      
                      <div className="bg-slate-800/50 rounded-xl p-4 text-center border border-slate-700/50">
                        <div className="text-3xl font-bold text-blue-400 mb-1">
                          {response.audit_summary.total_policies}
                        </div>
                        <div className="text-sm text-slate-400">Total Policies</div>
                      </div>
                      
                      <div className="bg-slate-800/50 rounded-xl p-4 text-center border border-slate-700/50">
                        <div className="text-3xl font-bold text-orange-400 mb-1">
                          {response.audit_summary.total_findings}
                        </div>
                        <div className="text-sm text-slate-400">Total Findings</div>
                      </div>
                      
                      <div className="bg-slate-800/50 rounded-xl p-4 text-center border border-slate-700/50">
                        <div className="text-3xl font-bold text-red-400 mb-1">
                          {response.audit_summary.critical_findings}
                        </div>
                        <div className="text-sm text-slate-400">Critical Issues</div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Findings List */}
              <div className="lg:col-span-8 space-y-6">
                <h3 className="text-white text-xl font-semibold">Security Findings</h3>
                
                {response.findings.length === 0 ? (
                  <div className="bg-green-500/10 border border-green-500/30 rounded-2xl p-8 text-center">
                    <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
                    <h4 className="text-green-400 font-bold text-xl mb-2">No Security Issues Found!</h4>
                    <p className="text-slate-300">This policy follows AWS security best practices.</p>
                  </div>
                ) : (
                  response.findings.map((finding, index) => {
                    const Icon = getSeverityIcon(finding.severity);
                    return (
                      <div key={index} className={`bg-gradient-to-br ${getSeverityColor(finding.severity)} backdrop-blur-xl border rounded-2xl p-6`}>
                        <div className="flex items-start space-x-4">
                          <div className="flex-shrink-0">
                            <Icon className="w-6 h-6" />
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center justify-between mb-2">
                              <h4 className="text-white font-bold text-lg">{finding.title}</h4>
                              <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                                finding.severity === 'Critical' ? 'bg-red-500/20 text-red-400' :
                                finding.severity === 'High' ? 'bg-orange-500/20 text-orange-400' :
                                finding.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                'bg-blue-500/20 text-blue-400'
                              }`}>
                                {finding.severity}
                              </span>
                            </div>
                            
                            <p className="text-slate-300 text-sm mb-4 leading-relaxed">
                              {finding.description}
                            </p>
                            
                            <div className="bg-slate-900/50 border border-slate-700/50 rounded-xl p-4">
                              <div className="flex items-start space-x-2">
                                <Sparkles className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                                <div>
                                  <div className="text-purple-300 font-semibold text-sm mb-1">Recommendation</div>
                                  <p className="text-slate-400 text-sm">{finding.recommendation}</p>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>

              {/* Right Sidebar - Recommendations & Quick Wins */}
              <div className="lg:col-span-4 space-y-6">
                {/* Quick Wins */}
                {response.quick_wins && response.quick_wins.length > 0 && (
                  <div className="bg-green-500/10 backdrop-blur-xl border border-green-500/30 rounded-2xl p-6">
                    <h4 className="text-green-400 text-lg font-semibold mb-4 flex items-center space-x-2">
                      <Zap className="w-5 h-5" />
                      <span>Quick Wins</span>
                    </h4>
                    <ul className="space-y-3">
                      {response.quick_wins.map((win, index) => (
                        <li key={index} className="text-slate-300 text-sm flex items-start space-x-3">
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
                    <h4 className="text-purple-400 text-lg font-semibold mb-4 flex items-center space-x-2">
                      <Shield className="w-5 h-5" />
                      <span>Security Improvements</span>
                    </h4>
                    <ul className="space-y-3">
                      {response.recommendations.map((rec, index) => (
                        <li key={index} className="text-slate-300 text-sm flex items-start space-x-3">
                          <AlertCircle className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Compliance Status */}
                {Object.keys(response.compliance_status).length > 0 && (
                  <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6">
                    <h4 className="text-white text-lg font-semibold mb-4">Compliance Status</h4>
                    <div className="space-y-3">
                      {Object.entries(response.compliance_status).map(([key, framework]: [string, any]) => (
                        <div key={key} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-xl">
                          <span className="text-slate-300 text-sm font-medium">{framework.name}</span>
                          <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                            framework.status === 'Compliant' ? 'bg-green-500/20 text-green-400' :
                            framework.status === 'Partial' ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-red-500/20 text-red-400'
                          }`}>
                            {framework.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ValidatePolicy;