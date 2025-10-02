import React, { useState } from 'react';
import { Search, AlertTriangle, XCircle, CheckCircle, Info, AlertCircle, Shield, Sparkles } from 'lucide-react';
import { SecurityFinding } from '../../types';

// Mock types for demo
interface ValidatePolicyResponse {
  risk_score: number;
  findings: SecurityFinding[];
  compliance_status: {
    [key: string]: {
      name: string;
      status: 'Compliant' | 'Partial' | 'Non-Compliant';
    }
  };
  recommendations: string[];
}

const ValidatePolicy: React.FC = () => {
  const [inputMode, setInputMode] = useState<'policy' | 'arn'>('policy');
  const [inputValue, setInputValue] = useState('');
  const [response, setResponse] = useState<ValidatePolicyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!inputValue.trim()) return;

    setLoading(true);
    setError(null);

    // MOCK API CALL
    setTimeout(() => {
        setResponse({
            risk_score: 78,
            findings: [
                { id: 'IAM.1', title: 'Overly Permissive Actions', severity: 'High', description: 'Policy allows wildcard actions "s3:*".', recommendation: 'Specify individual S3 actions like s3:GetObject, s3:PutObject.' },
                { id: 'IAM.21', title: 'Resource Wildcard', severity: 'Critical', description: 'Policy applies to all resources "*".', recommendation: 'Restrict resources to specific ARNs.' },
                { id: 'CUSTOM.1', title: 'Missing Condition Block', severity: 'Medium', description: 'Policy lacks condition clauses for IP or MFA restrictions.', recommendation: 'Add a Condition block to limit access by IP address or require MFA.' },
            ],
            compliance_status: {
                pci: { name: 'PCI DSS', status: 'Non-Compliant' },
                hipaa: { name: 'HIPAA', status: 'Partial' },
                cis: { name: 'CIS Benchmark', status: 'Compliant' },
            },
            recommendations: [
                "Replace wildcard actions with specific permissions.",
                "Scope down resource ARNs to only what is necessary.",
                "Implement IP-based condition restrictions."
            ]
        });
        setLoading(false);
    }, 1500);
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

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-purple-950/20 to-slate-950">
      {/* Background Elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-20 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-20 left-20 w-96 h-96 bg-pink-500/10 rounded-full blur-3xl"></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-8 py-16">
        {/* Header */}
        <div className="mb-12">
          <div className="inline-flex items-center space-x-2 bg-purple-500/10 border border-purple-500/30 rounded-full px-6 py-2 mb-6">
            <Sparkles className="w-4 h-4 text-purple-400" />
            <span className="text-purple-300 text-sm font-medium">Security Analyst</span>
          </div>
          
          <h1 className="text-6xl font-bold mb-6">
            <span className="text-white">Validate &</span>
            <br />
            <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-400 bg-clip-text text-transparent">
              Analyze Security
            </span>
          </h1>
          
          <p className="text-xl text-slate-300 max-w-3xl leading-relaxed">
            Comprehensive security analysis of existing IAM policies and roles. Identify vulnerabilities, 
            check compliance, and get actionable remediation guidance.
          </p>
        </div>

        {!response ? (
          /* Input Form */
          <div className="max-w-4xl mx-auto">
            <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-3xl p-10">
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
                    Policy JSON
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
                    Role ARN
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
                    placeholder="Paste your IAM policy JSON here for security analysis..."
                    className="w-full h-64 px-6 py-5 bg-slate-800/50 border border-slate-600/50 rounded-2xl text-white text-base placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none resize-none font-mono"
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
                    className="w-full px-6 py-5 bg-slate-800/50 border border-slate-600/50 rounded-2xl text-white text-lg placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none font-mono"
                  />
                </div>
              )}

              {/* Submit Button */}
              <button
                onClick={handleSubmit}
                disabled={loading || !inputValue.trim()}
                className="w-full bg-gradient-to-r from-orange-500 via-pink-500 to-purple-600 text-white py-5 px-8 rounded-2xl font-semibold text-lg hover:from-orange-600 hover:via-pink-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-purple-500/25 hover:shadow-xl hover:shadow-purple-500/40 flex items-center justify-center space-x-3"
              >
                {loading ? (
                  <>
                    <div className="w-6 h-6 border-3 border-white border-t-transparent rounded-full animate-spin"></div>
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-6 h-6" />
                    <span>Validate & Analyze Security</span>
                    <Shield className="w-5 h-5" />
                  </>
                )}
              </button>
            </div>

            {error && (
              <div className="mt-6 bg-red-500/10 border border-red-500/30 rounded-2xl p-6">
                <p className="text-red-400">{error}</p>
              </div>
            )}
          </div>
        ) : (
          /* Results */
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Risk Score - Large Card */}
            <div className="lg:col-span-3">
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-white text-2xl font-bold mb-2">Security Risk Assessment</h3>
                    <p className="text-slate-400">Overall risk level based on security analysis</p>
                  </div>
                  <div className="text-center">
                    <div className={`text-6xl font-bold ${getRiskScoreColor(response.risk_score)}`}>
                      {response.risk_score}
                    </div>
                    <div className="text-slate-400 text-sm mt-2">/ 100</div>
                  </div>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-4 mt-6">
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
              </div>
            </div>

            {/* Findings */}
            <div className="lg:col-span-2">
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8">
                <h3 className="text-white text-2xl font-bold mb-6">Security Findings</h3>
                <div className="space-y-4 max-h-[600px] overflow-y-auto pr-2">
                  {response.findings.map((finding, index) => {
                    const SeverityIcon = getSeverityIcon(finding.severity);
                    return (
                      <div
                        key={finding.id || index}
                        className={`bg-gradient-to-r ${getSeverityColor(finding.severity)} border rounded-2xl p-6`}
                      >
                        <div className="flex items-start space-x-4">
                          <SeverityIcon className="w-6 h-6 mt-1 flex-shrink-0" />
                          <div className="flex-1">
                            <div className="flex items-center space-x-3 mb-2">
                              <h4 className="font-semibold text-lg">{finding.title}</h4>
                              <span className="text-xs px-3 py-1 rounded-full bg-current bg-opacity-20">
                                {finding.severity}
                              </span>
                            </div>
                            <p className="text-sm mb-4 opacity-90">{finding.description}</p>
                            <div className="bg-current bg-opacity-10 rounded-xl p-4">
                              <p className="text-xs font-semibold mb-2">Recommendation:</p>
                              <p className="text-sm opacity-90">{finding.recommendation}</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Compliance & Recommendations */}
            <div className="space-y-6">
              {/* Compliance Status */}
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8">
                <h3 className="text-white text-xl font-bold mb-6">Compliance Status</h3>
                <div className="space-y-3">
                  {Object.entries(response.compliance_status).map(([framework, status]) => (
                    <div key={framework} className="flex items-center justify-between p-4 bg-slate-800/50 rounded-xl">
                      <span className="text-slate-300 font-medium">{status.name}</span>
                      <span className={`text-xs px-3 py-1 rounded-full ${
                        status.status === 'Compliant' ? 'bg-green-500/20 text-green-400' :
                        status.status === 'Partial' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-red-500/20 text-red-400'
                      }`}>
                        {status.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommendations */}
              <div className="bg-gradient-to-br from-orange-500/10 to-purple-500/10 backdrop-blur-xl border border-orange-500/30 rounded-2xl p-8">
                <h3 className="text-orange-400 text-xl font-bold mb-4">Recommendations</h3>
                <ul className="space-y-3">
                  {response.recommendations.map((rec, index) => (
                    <li key={index} className="text-slate-300 text-sm flex items-start space-x-3">
                      <CheckCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* New Analysis Button */}
              <button
                onClick={() => setResponse(null)}
                className="w-full bg-slate-800 hover:bg-slate-700 text-white py-4 rounded-xl transition-all border border-slate-700"
              >
                Analyze Another Policy
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ValidatePolicy;