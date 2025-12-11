import React, { useState, useEffect } from 'react';
import { Shield, Github, CheckCircle, AlertCircle, Info, Zap, Activity, RefreshCw, ExternalLink, FileText, AlertTriangle, Copy } from 'lucide-react';
import CollapsibleTile from '@/components/Common/CollapsibleTile';

interface CICDIntegrationProps {}

interface GitHubStatus {
  success: boolean;
  configured: boolean;
  app_id_set: boolean;
  private_key_set: boolean;
  webhook_secret_set: boolean;
  app_slug: string;
  install_url: string;
  webhook_url: string;
}

interface AnalysisResult {
  id: string;
  repo: string;
  pr_number?: number;
  commit_sha?: string;
  timestamp: string;
  risk_score: number;
  findings: Array<{
    severity: 'Critical' | 'High' | 'Medium' | 'Low';
    title: string;
    description: string;
  }>;
  policies_analyzed: number;
  files_analyzed: number;
  status: 'success' | 'error';
  message?: string;
}

const CICDIntegration: React.FC<CICDIntegrationProps> = () => {
  const [expandedSection, setExpandedSection] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [status, setStatus] = useState<GitHubStatus | null>(null);
  const [analysisResults, setAnalysisResults] = useState<AnalysisResult[]>([]);
  const [loadingResults, setLoadingResults] = useState(false);

  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  // Fetch recent analysis results
  useEffect(() => {
    fetchAnalysisResults();
    fetchStatus();
  }, []);

  const fetchAnalysisResults = async () => {
    setLoadingResults(true);
    try {
      const response = await fetch(`${apiUrl}/api/cicd/analyses`);
      if (response.ok) {
        const data = await response.json();
        setAnalysisResults(data.results || []);
      }
    } catch (error) {
      console.error('Failed to fetch analysis results:', error);
    } finally {
      setLoadingResults(false);
    }
  };

  const fetchStatus = async () => {
    try {
      const response = await fetch(`${apiUrl}/api/github/status`);
      if (response.ok) {
        const data = await response.json();
        setStatus(data);
      }
    } catch (error) {
      console.error('Failed to fetch GitHub status:', error);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const toggleSection = (section: string) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'High':
        return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'Medium':
        return 'text-amber-600 bg-amber-50 border-amber-200';
      case 'Low':
        return 'text-blue-600 bg-blue-50 border-blue-200';
      default:
        return 'text-slate-600 bg-slate-50 border-slate-200';
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 70) return 'text-emerald-600';
    if (score >= 40) return 'text-blue-600';
    if (score >= 20) return 'text-amber-600';
    return 'text-red-600';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50/30 to-indigo-50/30">
      {/* Background Elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-20 w-96 h-96 bg-blue-400/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-20 left-20 w-96 h-96 bg-purple-400/10 rounded-full blur-3xl"></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="mb-12 text-center">
          <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-200 rounded-full px-6 py-2 mb-6">
            <Shield className="w-4 h-4 text-blue-600" />
            <span className="text-blue-700 text-sm font-semibold">CI/CD Integration</span>
          </div>
          
          <h1 className="text-5xl font-extrabold mb-6">
            <span className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
              Proactive IAM Security
            </span>
            <br />
            <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
              in Your CI/CD Pipeline
            </span>
          </h1>
          
          <p className="text-xl text-slate-600 max-w-3xl mx-auto leading-relaxed font-medium">
            Automatically analyze IAM policies in pull requests and commits before they're merged. 
            Compare requested permissions against actual CloudTrail usage and prevent security issues proactively.
          </p>
        </div>

        {/* GitHub App Integration */}
        <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-8 shadow-xl mb-8">
          <div className="space-y-6">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center space-x-3">
                <Github className="w-8 h-8 text-slate-900" />
                <h2 className="text-3xl font-bold text-slate-900">GitHub App Integration</h2>
              </div>
            </div>

            <div className="bg-gradient-to-br from-emerald-50 to-teal-50 rounded-2xl p-6 border-2 border-emerald-200/50">
              <div className="flex items-center space-x-2 mb-4">
                <CheckCircle className="w-5 h-5 text-emerald-600" />
                <span className="text-emerald-700 font-semibold">One-Click Installation</span>
              </div>
              <p className="text-slate-700 mb-6">
                Install the Aegis IAM GitHub App on your repository. No YAML files, no secrets, no configuration needed!
                Works automatically on both Pull Requests and direct pushes to main/master branches.
              </p>
              
              <button
                onClick={async () => {
                  setConnecting(true);
                  try {
                    await fetchStatus();
                    const response = await fetch(`${apiUrl}/api/github/install`);
                    const data = await response.json();
                    if (data.success) {
                      if (data.demo_mode && data.install_url) {
                        alert(`${data.message}\n\n${data.instructions}`);
                        window.open(data.install_url, '_blank');
                      } else if (data.install_url) {
                        window.open(data.install_url, '_blank');
                      } else {
                        alert(data.message || 'GitHub App installation ready');
                      }
                    } else if (data.error) {
                      const userWantsToProceed = confirm(
                        `${data.error}\n\n${data.message || ''}\n\n` +
                        `Would you like to open GitHub App settings anyway?\n\n` +
                        `(To enable full functionality, add credentials to .env file)`
                      );
                      if (userWantsToProceed) {
                        const githubUrl = data.setup_url || 'https://github.com/settings/apps';
                        window.open(githubUrl, '_blank');
                      }
                    } else {
                      alert('GitHub App not configured. Please check backend configuration.');
                    }
                  } catch (error) {
                    console.error('Failed to connect GitHub:', error);
                    alert('Failed to connect GitHub. Please check if the backend is running and try again.');
                  } finally {
                    setConnecting(false);
                  }
                }}
                disabled={connecting}
                className="w-full bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white font-bold py-4 px-6 rounded-xl shadow-lg transition-all duration-300 flex items-center justify-center space-x-2 disabled:opacity-50"
              >
                {connecting ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                    <span>Connecting...</span>
                  </>
                ) : (
                  <>
                    <Github className="w-5 h-5" />
                    <span>Install GitHub App</span>
                  </>
                )}
              </button>
            </div>

            {status && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className={`rounded-xl p-4 border-2 ${status.configured ? 'border-emerald-200 bg-emerald-50' : 'border-amber-200 bg-amber-50'}`}>
                  <div className="flex items-center space-x-2 mb-1">
                    <Shield className="w-4 h-4 text-emerald-600" />
                    <p className="font-semibold text-slate-900">App Credentials</p>
                  </div>
                  <p className="text-sm text-slate-600">App ID: {status.app_id_set ? 'configured' : 'missing'}</p>
                  <p className="text-sm text-slate-600">Private Key: {status.private_key_set ? 'configured' : 'missing'}</p>
                  <p className="text-sm text-slate-600">Webhook Secret: {status.webhook_secret_set ? 'configured' : 'missing'}</p>
                </div>
                <div className="rounded-xl p-4 border-2 border-blue-200 bg-blue-50">
                  <p className="font-semibold text-slate-900 mb-2">Webhook URL</p>
                  <div className="flex items-center justify-between space-x-2">
                    <span className="text-sm text-slate-700 truncate">{status.webhook_url || `${apiUrl}/api/github/webhook`}</span>
                    <button
                      onClick={() => copyToClipboard(status.webhook_url || `${apiUrl}/api/github/webhook`, 'webhook')}
                      className="p-2 rounded-lg bg-white border border-slate-200 hover:bg-slate-50"
                    >
                      <Copy className="w-4 h-4 text-slate-600" />
                    </button>
                  </div>
                </div>
                <div className="rounded-xl p-4 border-2 border-slate-200 bg-white">
                  <p className="font-semibold text-slate-900 mb-2">Next Steps</p>
                  <ul className="space-y-1 text-sm text-slate-700 list-disc list-inside">
                    <li>Set env vars GITHUB_APP_ID / GITHUB_PRIVATE_KEY / GITHUB_WEBHOOK_SECRET</li>
                    <li>Install the app on your repo (opens GitHub)</li>
                    <li>Push or open a PR with IAM policy changes</li>
                  </ul>
                </div>
              </div>
            )}

            <div className="bg-blue-50 rounded-xl p-6 border-2 border-blue-200/50">
              <h3 className="text-xl font-bold text-slate-900 mb-4 flex items-center space-x-2">
                <Info className="w-6 h-6 text-blue-600" />
                <span>How It Works</span>
              </h3>
              <ul className="space-y-3 text-slate-700">
                <li className="flex items-start space-x-3">
                  <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold text-sm flex-shrink-0 mt-0.5">1</div>
                  <div>
                    <p className="font-semibold">Click "Install GitHub App"</p>
                    <p className="text-sm">You'll be redirected to GitHub to authorize the app</p>
                  </div>
                </li>
                <li className="flex items-start space-x-3">
                  <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold text-sm flex-shrink-0 mt-0.5">2</div>
                  <div>
                    <p className="font-semibold">Select Repository</p>
                    <p className="text-sm">Choose which repositories to install the app on</p>
                  </div>
                </li>
                <li className="flex items-start space-x-3">
                  <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold text-sm flex-shrink-0 mt-0.5">3</div>
                  <div>
                    <p className="font-semibold">Automatic Analysis</p>
                    <p className="text-sm">Every PR and push automatically triggers IAM policy analysis</p>
                  </div>
                </li>
                <li className="flex items-start space-x-3">
                  <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold text-sm flex-shrink-0 mt-0.5">4</div>
                  <div>
                    <p className="font-semibold">Get Results</p>
                    <p className="text-sm">Security analysis is posted as comments on PRs or commits, and visible here on the dashboard</p>
                  </div>
                </li>
              </ul>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-white/80 rounded-xl p-6 border-2 border-slate-200/50">
                <Zap className="w-8 h-8 text-emerald-600 mb-3" />
                <h4 className="font-bold text-slate-900 mb-2">Zero Config</h4>
                <p className="text-sm text-slate-600">No YAML files, no secrets, no code changes needed.</p>
              </div>
              <div className="bg-white/80 rounded-xl p-6 border-2 border-slate-200/50">
                <Shield className="w-8 h-8 text-emerald-600 mb-3" />
                <h4 className="font-bold text-slate-900 mb-2">Secure</h4>
                <p className="text-sm text-slate-600">OAuth-based authentication with scoped permissions.</p>
              </div>
              <div className="bg-white/80 rounded-xl p-6 border-2 border-slate-200/50">
                <Activity className="w-8 h-8 text-emerald-600 mb-3" />
                <h4 className="font-bold text-slate-900 mb-2">Automatic</h4>
                <p className="text-sm text-slate-600">Works on PRs and direct pushes to main/master.</p>
              </div>
            </div>
          </div>
        </div>

        {/* Analysis Results Section */}
        <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-8 shadow-xl">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-3">
              <FileText className="w-8 h-8 text-slate-900" />
              <h2 className="text-3xl font-bold text-slate-900">Recent Analysis Results</h2>
            </div>
            <button
              onClick={fetchAnalysisResults}
              disabled={loadingResults}
              className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${loadingResults ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>

          {loadingResults ? (
            <div className="text-center py-12">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
              <p className="mt-4 text-slate-600">Loading analysis results...</p>
            </div>
          ) : analysisResults.length === 0 ? (
            <div className="text-center py-12 bg-gradient-to-br from-slate-50 to-blue-50 rounded-2xl border-2 border-slate-200/50">
              <Info className="w-16 h-16 text-slate-400 mx-auto mb-4" />
              <h3 className="text-xl font-bold text-slate-700 mb-2">No Analysis Results Yet</h3>
              <p className="text-slate-600">
                Analysis results will appear here after you install the GitHub App and create PRs or push code.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {analysisResults.map((result) => (
                <CollapsibleTile
                  key={result.id}
                  title={
                    <div className="flex items-center justify-between w-full">
                      <div className="flex items-center space-x-3">
                        <Github className="w-5 h-5 text-slate-600" />
                        <span className="font-semibold">{result.repo}</span>
                        {result.pr_number && (
                          <span className="text-sm text-slate-500">PR #{result.pr_number}</span>
                        )}
                        {result.commit_sha && (
                          <span className="text-sm text-slate-500 font-mono">{result.commit_sha.substring(0, 7)}</span>
                        )}
                      </div>
                      <div className="flex items-center space-x-4">
                        <span className={`text-lg font-bold ${getRiskScoreColor(result.risk_score)}`}>
                          Risk: {result.risk_score}/100
                        </span>
                        <span className="text-sm text-slate-500">
                          {new Date(result.timestamp).toLocaleString()}
                        </span>
                      </div>
                    </div>
                  }
                  subtitle={`${result.policies_analyzed} policies analyzed • ${result.findings.length} findings`}
                  variant={result.status === 'error' ? 'error' : result.risk_score >= 70 ? 'success' : result.risk_score >= 40 ? 'info' : 'warning'}
                  defaultExpanded={false}
                >
                  <div className="space-y-4">
                    {result.status === 'error' && (
                      <div className="bg-red-50 border-2 border-red-200 rounded-xl p-4">
                        <div className="flex items-center space-x-2 text-red-700">
                          <AlertCircle className="w-5 h-5" />
                          <span className="font-semibold">Error</span>
                        </div>
                        <p className="text-red-600 mt-2">{result.message || 'Analysis failed'}</p>
                      </div>
                    )}

                    {result.findings.length > 0 ? (
                      <div className="space-y-3">
                        <h4 className="font-bold text-slate-900 text-lg">Security Findings</h4>
                        {result.findings.map((finding, idx) => (
                          <div
                            key={idx}
                            className={`border-2 rounded-xl p-4 ${getSeverityColor(finding.severity)}`}
                          >
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-bold text-sm uppercase">{finding.severity}</span>
                            </div>
                            <h5 className="font-semibold text-slate-900 mb-1">{finding.title}</h5>
                            <p className="text-sm text-slate-700">{finding.description}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="bg-emerald-50 border-2 border-emerald-200 rounded-xl p-4">
                        <div className="flex items-center space-x-2 text-emerald-700">
                          <CheckCircle className="w-5 h-5" />
                          <span className="font-semibold">No Security Issues Found</span>
                        </div>
                        <p className="text-emerald-600 mt-2">All analyzed policies follow security best practices.</p>
                      </div>
                    )}

                    <div className="flex items-center space-x-4 pt-4 border-t-2 border-slate-200">
                      <div className="text-sm text-slate-600">
                        <span className="font-semibold">Files Analyzed:</span> {result.files_analyzed}
                      </div>
                      <div className="text-sm text-slate-600">
                        <span className="font-semibold">Policies Analyzed:</span> {result.policies_analyzed}
                      </div>
                      {result.pr_number && (
                        <a
                          href={`https://github.com/${result.repo}/pull/${result.pr_number}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center space-x-1 text-blue-600 hover:text-blue-700 text-sm"
                        >
                          <span>View PR</span>
                          <ExternalLink className="w-4 h-4" />
                        </a>
                      )}
                    </div>
                  </div>
                </CollapsibleTile>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CICDIntegration;
