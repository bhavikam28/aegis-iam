import React, { useState } from 'react';
import { Search, AlertTriangle, XCircle, CheckCircle, Info, AlertCircle } from 'lucide-react';
import LoadingSpinner from '../UI/LoadingSpinner';
import CodeBlock from '../UI/CodeBlock';
import { ValidatePolicyRequest, ValidatePolicyResponse, SecurityFinding } from '../../types';
import { validatePolicy } from '../../services/api';

const ValidatePolicy: React.FC = () => {
  const [inputMode, setInputMode] = useState<'policy' | 'arn'>('policy');
  const [request, setRequest] = useState<ValidatePolicyRequest>({
    policy_json: '',
    role_arn: ''
  });
  const [response, setResponse] = useState<ValidatePolicyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const hasInput = inputMode === 'policy' ? request.policy_json?.trim() : request.role_arn?.trim();
    if (!hasInput) return;

    setLoading(true);
    setError(null);

    try {
      const result = await validatePolicy(request);
      setResponse(result);
    } catch (err) {
      setError('Failed to analyze policy security. Please verify your input and try again.');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: SecurityFinding['severity']) => {
    switch (severity) {
      case 'Critical': return 'text-red-400 bg-red-500/10 border-red-500/20';
      case 'High': return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
      case 'Medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
      case 'Low': return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
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
    <div className="p-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center space-x-3 mb-4">
          <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg flex items-center justify-center">
            <Search className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white">Validate & Analyze Security</h1>
            <p className="text-slate-400">Interactive security analysis of existing IAM policies and roles</p>
          </div>
        </div>
        
        <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-4">
          <div className="flex items-start space-x-3">
            <Search className="w-5 h-5 text-purple-400 mt-0.5" />
            <div>
              <h3 className="text-purple-400 font-medium">Interactive Security Analyst</h3>
              <p className="text-slate-300 text-sm mt-1">
                Submit an existing IAM policy or role ARN for comprehensive security analysis, 
                compliance checking, and risk assessment with actionable remediation guidance.
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        {/* Input Form */}
        <div className="space-y-6">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Input Mode Toggle */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-3">
                Input Type
              </label>
              <div className="flex space-x-1 bg-slate-900 border border-slate-700 rounded-lg p-1">
                <button
                  type="button"
                  onClick={() => setInputMode('policy')}
                  className={`flex-1 px-4 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                    inputMode === 'policy'
                      ? 'bg-orange-500 text-white shadow-md'
                      : 'text-slate-400 hover:text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  Policy JSON
                </button>
                <button
                  type="button"
                  onClick={() => setInputMode('arn')}
                  className={`flex-1 px-4 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                    inputMode === 'arn'
                      ? 'bg-orange-500 text-white shadow-md'
                      : 'text-slate-400 hover:text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  Role ARN
                </button>
              </div>
            </div>

            {/* Input Field */}
            {inputMode === 'policy' ? (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  IAM Policy JSON
                </label>
                <textarea
                  value={request.policy_json || ''}
                  onChange={(e) => setRequest({ ...request, policy_json: e.target.value })}
                  placeholder="Paste your IAM policy JSON here for security analysis..."
                  className="w-full h-48 px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:border-orange-500 focus:ring-1 focus:ring-orange-500 resize-none font-mono text-sm"
                  required={inputMode === 'policy'}
                />
              </div>
            ) : (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  IAM Role ARN
                </label>
                <input
                  type="text"
                  value={request.role_arn || ''}
                  onChange={(e) => setRequest({ ...request, role_arn: e.target.value })}
                  placeholder="arn:aws:iam::123456789012:role/MyRole"
                  className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:border-orange-500 focus:ring-1 focus:ring-orange-500 font-mono"
                  required={inputMode === 'arn'}
                />
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading || (!request.policy_json?.trim() && !request.role_arn?.trim())}
              className="w-full bg-gradient-to-r from-blue-500 to-blue-600 text-white py-3 px-6 rounded-lg font-medium hover:from-blue-600 hover:to-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center justify-center space-x-2"
            >
              <Search className="w-5 h-5" />
              <span>{loading ? 'Analyzing Security...' : 'Validate & Analyze Security'}</span>
            </button>
          </form>

          {/* Error Display */}
          {error && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                <span className="text-red-400 font-medium">Security Analysis Failed</span>
              </div>
              <p className="text-red-300 text-sm mt-1">{error}</p>
            </div>
          )}
        </div>

        {/* Results */}
        <div className="space-y-6">
          {loading ? (
            <div className="bg-slate-900 border border-slate-700 rounded-lg h-96 flex items-center justify-center">
              <LoadingSpinner message="Performing comprehensive security analysis..." />
            </div>
          ) : response ? (
            <>
              {/* Risk Score */}
              <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-white">Security Risk Assessment</h3>
                  <div className="flex items-center space-x-2">
                    <span className={`text-2xl font-bold ${getRiskScoreColor(response.risk_score)}`}>
                      {response.risk_score}
                    </span>
                    <span className="text-slate-400 text-sm">/ 100</span>
                  </div>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-3 mb-4">
                  <div
                    className={`h-3 rounded-full transition-all duration-1000 ${
                      response.risk_score <= 30 ? 'bg-green-500' :
                      response.risk_score <= 60 ? 'bg-yellow-500' :
                      response.risk_score <= 80 ? 'bg-orange-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${response.risk_score}%` }}
                  ></div>
                </div>
                <p className="text-slate-400 text-sm">
                  {response.risk_score <= 30 ? 'Low security risk - well-configured policy' :
                   response.risk_score <= 60 ? 'Moderate risk - some improvements needed' :
                   response.risk_score <= 80 ? 'High risk - significant security concerns' :
                   'Critical risk - immediate attention required'}
                </p>
              </div>

              {/* Security Findings */}
              {response.findings.length > 0 && (
                <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
                    <AlertTriangle className="w-5 h-5 text-orange-500" />
                    <span>Security Findings</span>
                    <span className="bg-orange-500/20 text-orange-400 text-xs px-2 py-1 rounded-full">
                      {response.findings.length}
                    </span>
                  </h3>
                  <div className="space-y-4 max-h-80 overflow-y-auto">
                    {response.findings.map((finding, index) => {
                      const SeverityIcon = getSeverityIcon(finding.severity);
                      return (
                        <div
                          key={finding.id || index}
                          className={`border rounded-lg p-4 ${getSeverityColor(finding.severity)}`}
                        >
                          <div className="flex items-start space-x-3">
                            <SeverityIcon className="w-5 h-5 mt-0.5" />
                            <div className="flex-1">
                              <div className="flex items-center space-x-2 mb-2">
                                <h4 className="font-medium">{finding.title}</h4>
                                <span className="text-xs px-2 py-0.5 rounded-full bg-current bg-opacity-20">
                                  {finding.severity}
                                </span>
                              </div>
                              <p className="text-sm mb-3 opacity-90">{finding.description}</p>
                              <div className="bg-current bg-opacity-10 rounded-md p-3">
                                <p className="text-xs font-medium mb-1">Recommendation:</p>
                                <p className="text-xs opacity-90">{finding.recommendation}</p>
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Compliance Status */}
              {Object.keys(response.compliance_status).length > 0 && (
                <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
                    <CheckCircle className="w-5 h-5 text-green-500" />
                    <span>Compliance Status</span>
                  </h3>
                  <div className="space-y-3">
                    {Object.entries(response.compliance_status).map(([framework, status]) => (
                      <div key={framework} className="flex items-center justify-between p-3 bg-slate-800 rounded-lg">
                        <span className="text-slate-300 font-medium">{status.name}</span>
                        <div className="flex items-center space-x-2">
                          <span className={`text-xs px-2 py-1 rounded-full ${
                            status.status === 'Compliant' ? 'bg-green-500/20 text-green-400' :
                            status.status === 'Partial' ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-red-500/20 text-red-400'
                          }`}>
                            {status.status}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendations */}
              {response.recommendations.length > 0 && (
                <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-6">
                  <h3 className="text-lg font-medium text-green-400 mb-4 flex items-center space-x-2">
                    <CheckCircle className="w-5 h-5" />
                    <span>Security Recommendations</span>
                  </h3>
                  <ul className="space-y-3">
                    {response.recommendations.map((recommendation, index) => (
                      <li key={index} className="text-green-200 text-sm flex items-start space-x-2">
                        <div className="w-1.5 h-1.5 bg-green-400 rounded-full mt-2 flex-shrink-0"></div>
                        <span>{recommendation}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          ) : (
            <div className="bg-slate-900 border border-slate-700 rounded-lg h-96 flex items-center justify-center">
              <div className="text-center">
                <Search className="w-16 h-16 text-slate-600 mx-auto mb-4" />
                <h3 className="text-xl font-medium text-slate-400 mb-2">Ready for Security Analysis</h3>
                <p className="text-slate-500">Submit an IAM policy or role ARN for comprehensive security validation</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ValidatePolicy;