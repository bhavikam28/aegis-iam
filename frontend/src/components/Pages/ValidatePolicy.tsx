import React, { useState } from 'react';
import { Search, AlertTriangle, XCircle, CheckCircle, Info, AlertCircle, Shield, Sparkles, Copy, Download, RefreshCw, Zap, Bot } from 'lucide-react';
import { validatePolicy, performAutonomousAudit } from '../../services/api';
import { SecurityFinding, ValidatePolicyRequest, ValidatePolicyResponse } from '../../types';

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
      // Call autonomous audit endpoint - uses MCP servers with system AWS credentials
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
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-purple-950/20 to-slate-950">
      {/* Animated Background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-20 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl animate-pulse-slow"></div>
        <div className="absolute bottom-20 left-20 w-96 h-96 bg-pink-500/10 rounded-full blur-3xl animate-pulse-slow" style={{ animationDelay: '2s' }}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-orange-500/5 rounded-full blur-3xl animate-pulse-slow" style={{ animationDelay: '4s' }}></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-8 py-12 sm:py-16">
        {!loading && !response && (
          <>
            {/* Header */}
            <div className="mb-12">
              <div className="inline-flex items-center space-x-2 bg-purple-500/10 border border-purple-500/30 rounded-full px-6 py-2 mb-6">
                <Sparkles className="w-4 h-4 text-purple-400" />
                <span className="text-purple-300 text-sm font-medium">Security Analyst</span>
              </div>
              
              <h1 className="text-5xl sm:text-6xl font-bold mb-6 leading-tight">
                <span className="text-white">Validate &</span>
                <br />
                <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-400 bg-clip-text text-transparent">
                  Audit Security
                </span>
              </h1>
              
              <p className="text-lg sm:text-xl text-slate-300 max-w-3xl leading-relaxed">
                Choose your analysis mode: Quick validation for single policies, or autonomous audit 
                for comprehensive account-wide security assessment using MCP servers.
              </p>
            </div>

            {/* MODE SELECTION */}
            <div className="max-w-5xl mx-auto mb-8">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Quick Validation Card */}
                <button
                  onClick={() => setMode('quick')}
                  className={`relative group p-8 rounded-3xl border-2 transition-all ${
                    mode === 'quick'
                      ? 'border-purple-500 bg-gradient-to-br from-purple-500/20 to-pink-500/10'
                      : 'border-slate-700 bg-slate-900/50 hover:border-purple-500/50'
                  }`}
                >
                  <div className="flex items-start space-x-4 mb-4">
                    <div className={`w-16 h-16 rounded-2xl flex items-center justify-center ${
                      mode === 'quick'
                        ? 'bg-gradient-to-br from-purple-500/30 to-pink-500/30 border border-purple-500/50'
                        : 'bg-slate-800/50 border border-slate-700'
                    }`}>
                      <Search className="w-8 h-8 text-purple-400" />
                    </div>
                    <div className="flex-1 text-left">
                      <h3 className="text-2xl font-bold text-white mb-2">Quick Validation</h3>
                      <p className="text-slate-400 text-sm leading-relaxed">
                        Analyze a single IAM policy or role. Fast, focused security analysis.
                      </p>
                    </div>
                  </div>
                  
                  <div className="space-y-2 text-sm text-slate-400">
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-purple-400" />
                      <span>Paste policy JSON or role ARN</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-purple-400" />
                      <span>Results in ~5 seconds</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-purple-400" />
                      <span>Uses MCP if role ARN provided</span>
                    </div>
                  </div>
                  
                  {mode === 'quick' && (
                    <div className="absolute top-4 right-4 w-8 h-8 bg-purple-500 rounded-full flex items-center justify-center">
                      <CheckCircle className="w-5 h-5 text-white" />
                    </div>
                  )}
                </button>

                {/* Autonomous Audit Card */}
                <button
                  onClick={() => setMode('audit')}
                  className={`relative group p-8 rounded-3xl border-2 transition-all ${
                    mode === 'audit'
                      ? 'border-orange-500 bg-gradient-to-br from-orange-500/20 to-purple-500/10'
                      : 'border-slate-700 bg-slate-900/50 hover:border-orange-500/50'
                  }`}
                >
                  <div className="flex items-start space-x-4 mb-4">
                    <div className={`w-16 h-16 rounded-2xl flex items-center justify-center ${
                      mode === 'audit'
                        ? 'bg-gradient-to-br from-orange-500/30 to-pink-500/30 border border-orange-500/50'
                        : 'bg-slate-800/50 border border-slate-700'
                    }`}>
                      <Bot className="w-8 h-8 text-orange-400" />
                    </div>
                    <div className="flex-1 text-left">
                      <h3 className="text-2xl font-bold text-white mb-2 flex items-center space-x-2">
                        <span>Full Account Audit</span>
                        <span className="text-xs px-2 py-1 bg-orange-500/20 text-orange-400 rounded-full border border-orange-500/30">MCP</span>
                      </h3>
                      <p className="text-slate-400 text-sm leading-relaxed">
                        AI agent autonomously scans your entire AWS account for security issues.
                      </p>
                    </div>
                  </div>
                  
                  <div className="space-y-2 text-sm text-slate-400">
                    <div className="flex items-center space-x-2">
                      <Zap className="w-4 h-4 text-orange-400" />
                      <span>Scans ALL IAM roles & policies</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Zap className="w-4 h-4 text-orange-400" />
                      <span>Autonomous AI decision-making</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Zap className="w-4 h-4 text-orange-400" />
                      <span>Uses system AWS credentials</span>
                    </div>
                  </div>
                  
                  {mode === 'audit' && (
                    <div className="absolute top-4 right-4 w-8 h-8 bg-orange-500 rounded-full flex items-center justify-center">
                      <CheckCircle className="w-5 h-5 text-white" />
                    </div>
                  )}
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
                // AUTONOMOUS AUDIT FORM (NO CREDENTIALS NEEDED!)
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
                }}
                className="px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white rounded-xl transition-all border border-slate-700 flex items-center space-x-2"
              >
                <RefreshCw className="w-4 h-4" />
                <span>New Analysis</span>
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
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