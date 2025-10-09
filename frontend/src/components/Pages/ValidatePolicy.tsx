import React, { useState } from 'react';
import { Search, AlertTriangle, XCircle, CheckCircle, Info, AlertCircle, Shield, Sparkles, Copy, Download, RefreshCw, Zap } from 'lucide-react';
import { validatePolicy } from '../../services/api';
import { SecurityFinding, ValidatePolicyRequest, ValidatePolicyResponse } from '../../types';

const ValidatePolicy: React.FC = () => {
  const [inputMode, setInputMode] = useState<'policy' | 'arn'>('policy');
  const [inputValue, setInputValue] = useState('');
  const [response, setResponse] = useState<ValidatePolicyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleCopy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSubmit = async () => {
    if (!inputValue.trim()) return;

    setLoading(true);
    setError(null);
    setResponse(null);

    try {
      const request: ValidatePolicyRequest = inputMode === 'policy' 
        ? { policy_json: inputValue }
        : { role_arn: inputValue };
      
      const result = await validatePolicy(request);
      setResponse(result);
    } catch (err) {
      console.error("Validation error:", err);
      setError(err instanceof Error ? err.message : 'Validation failed');
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

      <style>{`
        @keyframes pulse-slow {
          0%, 100% { opacity: 0.15; transform: scale(1); }
          50% { opacity: 0.25; transform: scale(1.05); }
        }
        .animate-pulse-slow {
          animation: pulse-slow 8s ease-in-out infinite;
        }
      `}</style>

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
                  Analyze Security
                </span>
              </h1>
              
              <p className="text-lg sm:text-xl text-slate-300 max-w-3xl leading-relaxed">
                Comprehensive security analysis of IAM policies. Identify vulnerabilities, 
                check compliance, and get actionable remediation guidance powered by AI.
              </p>
            </div>

            {/* Input Form */}
            <div className="max-w-4xl mx-auto">
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-3xl p-8 sm:p-10 shadow-2xl">
                {/* Input Mode Toggle */}
                <div className="mb-8">
                  <label className="block text-white text-lg font-semibold mb-4">Input Type</label>
                  <div className="grid grid-cols-2 gap-4">
                    <button
                      type="button"
                      onClick={() => setInputMode('policy')}
                      className={`px-6 py-4 rounded-2xl font-medium transition-all ${
                        inputMode === 'policy'
                          ? 'bg-gradient-to-r from-orange-500 via-pink-500 to-purple-600 text-white shadow-lg shadow-purple-500/25'
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
                      onClick={() => setInputMode('arn')}
                      className={`px-6 py-4 rounded-2xl font-medium transition-all ${
                        inputMode === 'arn'
                          ? 'bg-gradient-to-r from-orange-500 via-pink-500 to-purple-600 text-white shadow-lg shadow-purple-500/25'
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
                {inputMode === 'policy' ? (
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
                      We'll fetch and analyze the role's policies from AWS
                    </p>
                  </div>
                )}

                {/* Submit Button */}
                <button
                  onClick={handleSubmit}
                  disabled={loading || !inputValue.trim()}
                  className="w-full bg-gradient-to-r from-orange-500 via-pink-500 to-purple-600 text-white py-5 px-8 rounded-2xl font-semibold text-lg hover:from-orange-600 hover:via-pink-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-purple-500/25 hover:shadow-xl hover:shadow-purple-500/40 flex items-center justify-center space-x-3"
                >
                  <Search className="w-6 h-6" />
                  <span>Analyze Security Posture</span>
                  <Shield className="w-5 h-5" />
                </button>
              </div>

              {error && (
                <div className="mt-6 bg-red-500/10 border border-red-500/30 rounded-2xl p-6">
                  <div className="flex items-start space-x-3">
                    <XCircle className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <h4 className="text-red-400 font-semibold mb-1">Validation Error</h4>
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
                <Search className="w-12 h-12 text-purple-400 relative z-10" />
              </div>
              
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
                Deep Security Analysis
              </h2>
              
              <p className="text-lg sm:text-xl text-slate-300 mb-8 leading-relaxed">
                Scanning for vulnerabilities, compliance issues, and security best practices...
              </p>
              
              <div className="flex items-center justify-center space-x-2 mb-8">
                <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0ms', animationDuration: '1s' }}></div>
                <div className="w-2 h-2 bg-pink-400 rounded-full animate-bounce" style={{ animationDelay: '200ms', animationDuration: '1s' }}></div>
                <div className="w-2 h-2 bg-orange-400 rounded-full animate-bounce" style={{ animationDelay: '400ms', animationDuration: '1s' }}></div>
              </div>

              <div className="text-sm text-slate-500">
                This may take up to 30 seconds...
              </div>
            </div>
          </div>
        )}

        {/* Premium Results Display */}
        {!loading && response && (
          <div className="max-w-[1600px] mx-auto">
            <div className="flex items-center justify-between mb-12">
              <div>
                <h2 className="text-3xl font-bold text-white mb-2">
                  Security Analysis Complete
                </h2>
                <p className="text-slate-400">
                  Comprehensive security assessment of your IAM policy
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
              {/* Risk Score - Full Width Card */}
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
                  
                  {/* Risk Bar */}
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

                  {/* Grade Badge */}
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

                    {/* Quick Stats */}
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

              {/* Left Column: Findings */}
              <div className="lg:col-span-8 space-y-6">
                <div>
                  <h3 className="text-white text-2xl font-bold mb-6 flex items-center space-x-2">
                    <AlertTriangle className="w-6 h-6 text-orange-400" />
                    <span>Security Findings</span>
                  </h3>
                  
                  <div className="space-y-4 max-h-[800px] overflow-y-auto pr-2 custom-scrollbar">
                    {response.findings.length === 0 ? (
                      <div className="bg-green-500/10 border border-green-500/30 rounded-2xl p-8 text-center">
                        <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
                        <h4 className="text-green-400 text-xl font-bold mb-2">No Critical Issues Found</h4>
                        <p className="text-green-300">Your policy follows security best practices!</p>
                      </div>
                    ) : (
                      response.findings.map((finding, index) => {
                        const SeverityIcon = getSeverityIcon(finding.severity);
                        return (
                          <div
                            key={finding.id || index}
                            className={`bg-gradient-to-r ${getSeverityColor(finding.severity)} border rounded-2xl p-6 hover:shadow-lg transition-all`}
                          >
                            <div className="flex items-start space-x-4">
                              <div className="flex-shrink-0">
                                <div className="w-12 h-12 rounded-xl bg-current bg-opacity-20 flex items-center justify-center">
                                  <SeverityIcon className="w-6 h-6" />
                                </div>
                              </div>
                              
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center space-x-3 mb-2 flex-wrap">
                                  <h4 className="font-bold text-lg">{finding.title}</h4>
                                  <span className="text-xs px-3 py-1 rounded-full bg-current bg-opacity-20 font-medium">
                                    {finding.severity}
                                  </span>
                                  {finding.id && (
                                    <span className="text-xs px-3 py-1 rounded-full bg-current bg-opacity-10 font-mono">
                                      {finding.id}
                                    </span>
                                  )}
                                </div>
                                
                                <p className="text-sm mb-4 opacity-90 leading-relaxed">
                                  {finding.description}
                                </p>
                                
                                <div className="bg-current bg-opacity-10 rounded-xl p-4 border border-current border-opacity-20">
                                  <div className="flex items-center space-x-2 mb-2">
                                    <Sparkles className="w-4 h-4" />
                                    <p className="text-xs font-semibold">Recommended Fix:</p>
                                  </div>
                                  <p className="text-sm opacity-90 leading-relaxed whitespace-pre-wrap font-mono text-xs">
                                    {finding.recommendation}
                                  </p>
                                  {finding.recommendation.includes('{') && (
                                    <button
                                      onClick={() => handleCopy(finding.recommendation)}
                                      className="mt-3 px-3 py-1.5 bg-current bg-opacity-20 hover:bg-opacity-30 rounded-lg text-xs font-medium transition-all flex items-center space-x-1.5"
                                    >
                                      {copied ? <CheckCircle className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                                      <span>{copied ? 'Copied!' : 'Copy Fix'}</span>
                                    </button>
                                  )}
                                </div>

                                {finding.affectedStatement !== undefined && (
                                  <div className="mt-3 text-xs opacity-70">
                                    📍 Affects Statement #{finding.affectedStatement}
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              </div>

              {/* Right Column: Compliance & Recommendations */}
              <div className="lg:col-span-4 space-y-6">
                {/* Compliance Status */}
                {response.compliance_status && Object.keys(response.compliance_status).length > 0 && (
                  <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-6">
                    <h4 className="text-white text-xl font-bold mb-4 flex items-center space-x-2">
                      <Shield className="w-5 h-5 text-purple-400" />
                      <span>Compliance Status</span>
                    </h4>
                    <div className="space-y-3">
                      {Object.entries(response.compliance_status).map(([framework, status]: [string, any]) => {
                        const statusColor = 
                          status.status === 'Compliant' ? 'bg-green-500/20 text-green-400 border-green-500/30' :
                          status.status === 'Partial' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                          'bg-red-500/20 text-red-400 border-red-500/30';
                        
                        return (
                          <div key={framework} className="p-4 bg-slate-800/50 rounded-xl border border-slate-700/50 hover:border-purple-500/30 transition-all">
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-slate-300 font-medium">{status.name || framework.toUpperCase()}</span>
                              <span className={`text-xs px-3 py-1 rounded-full border ${statusColor}`}>
                                {status.status}
                              </span>
                            </div>
                            {status.gaps && status.gaps.length > 0 && (
                              <div className="mt-2 space-y-1">
                                {status.gaps.map((gap: string, idx: number) => (
                                  <div key={idx} className="text-xs text-slate-400 flex items-start space-x-2">
                                    <span className="text-orange-400">•</span>
                                    <span>{gap}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Security Improvements */}
                {response.recommendations && response.recommendations.length > 0 && (
                  <div className="bg-gradient-to-br from-orange-500/10 to-purple-500/10 backdrop-blur-xl border border-orange-500/30 rounded-2xl p-6">
                    <h4 className="text-orange-400 text-xl font-bold mb-4 flex items-center space-x-2">
                      <Zap className="w-5 h-5" />
                      <span>Priority Actions</span>
                    </h4>
                    <ul className="space-y-3">
                      {response.recommendations.slice(0, 5).map((rec, index) => (
                        <li key={index} className="text-slate-300 text-sm flex items-start space-x-3">
                          <div className="w-6 h-6 bg-orange-500/20 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5">
                            <span className="text-orange-400 font-bold text-xs">{index + 1}</span>
                          </div>
                          <span className="leading-relaxed">{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Quick Wins */}
                {response.quick_wins && response.quick_wins.length > 0 && (
                  <div className="bg-green-500/5 backdrop-blur-xl border border-green-500/30 rounded-2xl p-6">
                    <h4 className="text-green-400 text-xl font-bold mb-4 flex items-center space-x-2">
                      <CheckCircle className="w-5 h-5" />
                      <span>Quick Wins</span>
                    </h4>
                    <div className="space-y-2">
                      {response.quick_wins.map((win, index) => (
                        <div key={index} className="text-sm text-green-300 bg-green-500/10 rounded-lg p-3 border border-green-500/20">
                          ⚡ {win}
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