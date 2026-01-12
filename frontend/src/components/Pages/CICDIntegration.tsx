import React, { useState, useEffect } from 'react';
import { Shield, Github, CheckCircle, AlertCircle, Info, Zap, Activity, RefreshCw, ExternalLink, FileText, AlertTriangle, Copy, Sparkles, Key, FileCode } from 'lucide-react';
import CollapsibleTile from '@/components/Common/CollapsibleTile';
import { API_URL } from '@/config/api';

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

interface CICDIntegrationProps {
  demoMode?: boolean;
}

const CICDIntegration: React.FC<CICDIntegrationProps> = ({ demoMode = false }) => {
  const [expandedSection, setExpandedSection] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [status, setStatus] = useState<GitHubStatus | null>(null);
  const [analysisResults, setAnalysisResults] = useState<AnalysisResult[]>([]);
  const [loadingResults, setLoadingResults] = useState(false);

  // Use centralized API URL configuration
  const apiUrl = API_URL;

  // Demo mode: ALWAYS load demo data when in demo mode (including after refresh)
  useEffect(() => {
    if (demoMode) {
      // Always restore demo data - use a flag to prevent infinite loops
      const loadDemoData = async () => {
        if (analysisResults.length === 0) {
          const { mockCICDAnalysisResponse } = await import('@/utils/demoData');
          setAnalysisResults([mockCICDAnalysisResponse()]);
        }
      };
      loadDemoData();
      
      // Always set demo status
      setStatus({
        success: true,
        configured: true,
        app_id_set: true,
        private_key_set: true,
        webhook_secret_set: true,
        app_slug: 'aegis-iam',
        install_url: 'https://github.com/apps/aegis-iam/installations/new',
        webhook_url: 'https://aegis-iam-backend.onrender.com/api/github/webhook'
      });
    } else {
      // Fetch recent analysis results
      fetchAnalysisResults();
      fetchStatus();
    }
  }, [demoMode]); // Removed analysisResults.length to prevent infinite loops

  const fetchAnalysisResults = async () => {
    // In demo mode, restore demo data instead of fetching
    if (demoMode) {
      setLoadingResults(true);
      setTimeout(() => {
        import('@/utils/demoData').then(({ mockCICDAnalysisResponse }) => {
          setAnalysisResults([mockCICDAnalysisResponse()]);
          setLoadingResults(false);
        });
      }, 500);
      return;
    }
    
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
    <div className="min-h-screen relative overflow-hidden">
      {/* Demo Mode Banner */}
      {demoMode && (
        <div className="relative z-30 bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 text-white py-3 px-4 shadow-lg">
          <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-center gap-3">
            <div className="flex items-center gap-3">
              <Sparkles className="w-5 h-5" />
              <span className="font-bold text-sm sm:text-base text-center">
                Demo Mode: Static showcase with sample data. No API calls, no costs.
              </span>
            </div>
            <button
              onClick={() => window.open('https://github.com/bhavikam28/aegis-iam#-run-locally-recommended-for-full-functionality', '_blank')}
              className="bg-white/20 hover:bg-white/30 px-4 py-1.5 rounded-lg font-semibold text-sm transition-colors whitespace-nowrap"
            >
              Run Locally (Full Access)
            </button>
          </div>
        </div>
      )}
      
      {/* Premium Animated Background - Matching Website Theme */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 right-0 w-[800px] h-[800px] bg-gradient-to-br from-blue-400/8 via-purple-400/6 to-pink-400/4 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 left-0 w-[700px] h-[700px] bg-gradient-to-tr from-amber-400/6 via-orange-400/4 to-red-400/3 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '2s' }}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-br from-emerald-400/5 via-cyan-400/4 to-blue-400/3 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '4s' }}></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 sm:py-20">
        {/* Header */}
        <div className="mb-16 text-center animate-fadeIn">
          <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-200 rounded-full px-6 py-2 mb-6 backdrop-blur-sm">
            <Shield className="w-4 h-4 text-blue-600" />
            <span className="text-blue-700 text-sm font-semibold">CI/CD Integration</span>
          </div>
          
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold mb-6 leading-tight tracking-tight">
            <span className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent">
              Proactive IAM Security
            </span>
            <br />
            <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
              in Your CI/CD Pipeline
            </span>
          </h1>
          
          <p className="text-base sm:text-lg lg:text-xl text-slate-600 max-w-3xl mx-auto leading-relaxed font-medium">
            Automatically analyze IAM policies in pull requests and commits before they're merged. 
            Compare requested permissions against actual CloudTrail usage and prevent security issues proactively.
          </p>
        </div>

        {/* GitHub App Integration */}
        <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-xl mb-8 animate-fadeIn">
          <div className="space-y-6">
            <div className="flex items-center space-x-3 mb-6">
              <div className="w-12 h-12 bg-gradient-to-br from-slate-900 to-slate-700 rounded-xl flex items-center justify-center shadow-lg">
                <Github className="w-6 h-6 text-white" />
              </div>
              <h2 className="text-2xl sm:text-3xl font-bold text-slate-900">GitHub App Integration</h2>
            </div>

            <div className="bg-gradient-to-br from-blue-50 to-purple-50 rounded-2xl p-6 border-2 border-blue-200">
              <div className="flex items-center space-x-2 mb-4">
                <Zap className="w-5 h-5 text-blue-600" />
                <span className="text-slate-900 font-bold text-lg">One-Click Installation</span>
              </div>
              <p className="text-slate-700 mb-6 leading-relaxed">
                Install the Aegis IAM GitHub App on your repository. <strong>No YAML files, no secrets, no configuration needed!</strong>
              </p>
              <p className="text-slate-700 mb-6 leading-relaxed">
                Works automatically on both <span className="font-semibold text-slate-900">Pull Requests</span> and direct pushes to <span className="font-semibold text-slate-900">main/master</span> branches.
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
                className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-bold py-4 px-6 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 flex items-center justify-center space-x-2 disabled:opacity-50 transform hover:scale-[1.02]"
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
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className={`rounded-2xl p-6 border-2 shadow-sm ${status.configured ? 'border-blue-200 bg-gradient-to-br from-blue-50 to-cyan-50' : 'border-amber-200 bg-gradient-to-br from-amber-50 to-yellow-50'}`}>
                  <div className="flex items-center space-x-2 mb-3">
                    <Shield className={`w-5 h-5 ${status.configured ? 'text-blue-600' : 'text-amber-600'}`} />
                    <p className="font-bold text-slate-900">App Credentials</p>
                  </div>
                  <div className="space-y-1.5">
                    <div className="flex items-center space-x-2">
                      {status.app_id_set ? <CheckCircle className="w-4 h-4 text-green-600" /> : <AlertCircle className="w-4 h-4 text-amber-600" />}
                      <p className="text-sm text-slate-700 font-medium">App ID: {status.app_id_set ? 'Configured' : 'Missing'}</p>
                    </div>
                    <div className="flex items-center space-x-2">
                      {status.private_key_set ? <CheckCircle className="w-4 h-4 text-green-600" /> : <AlertCircle className="w-4 h-4 text-amber-600" />}
                      <p className="text-sm text-slate-700 font-medium">Private Key: {status.private_key_set ? 'Configured' : 'Missing'}</p>
                    </div>
                    <div className="flex items-center space-x-2">
                      {status.webhook_secret_set ? <CheckCircle className="w-4 h-4 text-green-600" /> : <AlertCircle className="w-4 h-4 text-amber-600" />}
                      <p className="text-sm text-slate-700 font-medium">Webhook: {status.webhook_secret_set ? 'Configured' : 'Missing'}</p>
                    </div>
                  </div>
                </div>
                <div className="rounded-2xl p-6 border-2 border-purple-200 bg-gradient-to-br from-purple-50 to-pink-50 shadow-sm">
                  <p className="font-bold text-slate-900 mb-3 flex items-center gap-2">
                    <Activity className="w-5 h-5 text-purple-600" />
                    Webhook URL
                  </p>
                  <div className="flex items-center justify-between space-x-2 bg-white rounded-lg px-3 py-2 border border-slate-200">
                    <span className="text-xs text-slate-700 truncate font-mono">{status.webhook_url || `${apiUrl}/api/github/webhook`}</span>
                    <button
                      onClick={() => copyToClipboard(status.webhook_url || `${apiUrl}/api/github/webhook`, 'webhook')}
                      className="p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
                      title="Copy webhook URL"
                    >
                      <Copy className="w-4 h-4 text-slate-600" />
                    </button>
                  </div>
                </div>
                <div className="rounded-2xl p-6 border-2 border-slate-200 bg-gradient-to-br from-slate-50 to-blue-50 shadow-sm">
                  <p className="font-bold text-slate-900 mb-3 flex items-center gap-2">
                    <Info className="w-5 h-5 text-slate-700" />
                    Quick Start
                  </p>
                  <ul className="space-y-2 text-sm text-slate-700">
                    <li className="flex items-start gap-2">
                      <span className="text-blue-600 font-bold">1.</span>
                      <span>Click "Install GitHub App" above</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-blue-600 font-bold">2.</span>
                      <span>Select your repository</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-blue-600 font-bold">3.</span>
                      <span>Create PR with IAM changes</span>
                    </li>
                  </ul>
                </div>
              </div>
            )}

            {/* How It Works Section */}
            <div className="bg-gradient-to-br from-slate-50 to-blue-50 rounded-2xl p-8 border-2 border-slate-200">
              <h3 className="text-2xl font-bold text-slate-900 mb-6 flex items-center space-x-2">
                <Info className="w-7 h-7 text-blue-600" />
                <span>How It Works</span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="flex items-start space-x-4">
                  <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-purple-600 text-white rounded-xl flex items-center justify-center font-bold text-lg flex-shrink-0 shadow-lg">1</div>
                  <div>
                    <p className="font-bold text-slate-900 mb-1">Click "Install GitHub App"</p>
                    <p className="text-sm text-slate-600">You'll be redirected to GitHub to authorize the app</p>
                  </div>
                </div>
                <div className="flex items-start space-x-4">
                  <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-purple-600 text-white rounded-xl flex items-center justify-center font-bold text-lg flex-shrink-0 shadow-lg">2</div>
                  <div>
                    <p className="font-bold text-slate-900 mb-1">Select Repository</p>
                    <p className="text-sm text-slate-600">Choose which repositories to install the app on</p>
                  </div>
                </div>
                <div className="flex items-start space-x-4">
                  <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-purple-600 text-white rounded-xl flex items-center justify-center font-bold text-lg flex-shrink-0 shadow-lg">3</div>
                  <div>
                    <p className="font-bold text-slate-900 mb-1">Automatic Analysis</p>
                    <p className="text-sm text-slate-600">Every PR and push automatically triggers IAM policy analysis</p>
                  </div>
                </div>
                <div className="flex items-start space-x-4">
                  <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-purple-600 text-white rounded-xl flex items-center justify-center font-bold text-lg flex-shrink-0 shadow-lg">4</div>
                  <div>
                    <p className="font-bold text-slate-900 mb-1">Get Results</p>
                    <p className="text-sm text-slate-600">Security analysis posted as comments on PRs and visible on this dashboard</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Feature Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="group bg-white rounded-2xl p-6 border-2 border-slate-200 hover:border-blue-300 hover:shadow-xl transition-all duration-300">
                <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform shadow-lg">
                  <Zap className="w-6 h-6 text-white" />
                </div>
                <h4 className="font-bold text-slate-900 mb-2 text-lg">Zero Config</h4>
                <p className="text-sm text-slate-600 leading-relaxed">No YAML files, no secrets, no code changes needed. Just install and go!</p>
              </div>
              <div className="group bg-white rounded-2xl p-6 border-2 border-slate-200 hover:border-purple-300 hover:shadow-xl transition-all duration-300">
                <div className="w-12 h-12 bg-gradient-to-br from-purple-500 to-pink-500 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform shadow-lg">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <h4 className="font-bold text-slate-900 mb-2 text-lg">Secure</h4>
                <p className="text-sm text-slate-600 leading-relaxed">OAuth-based authentication with scoped permissions. Your code stays safe.</p>
              </div>
              <div className="group bg-white rounded-2xl p-6 border-2 border-slate-200 hover:border-blue-300 hover:shadow-xl transition-all duration-300">
                <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-500 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform shadow-lg">
                  <Activity className="w-6 h-6 text-white" />
                </div>
                <h4 className="font-bold text-slate-900 mb-2 text-lg">Automatic</h4>
                <p className="text-sm text-slate-600 leading-relaxed">Works on PRs and direct pushes to main/master. Set it and forget it!</p>
              </div>
            </div>
          </div>
        </div>

        {/* Analysis Results Section */}
        <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-xl animate-fadeIn">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
            <div className="flex items-center space-x-3">
              <div className="w-12 h-12 bg-gradient-to-br from-blue-600 to-purple-600 rounded-xl flex items-center justify-center shadow-lg">
                <FileText className="w-6 h-6 text-white" />
              </div>
              <h2 className="text-2xl sm:text-3xl font-bold text-slate-900">Recent Analysis Results</h2>
            </div>
            <button
              onClick={fetchAnalysisResults}
              disabled={loadingResults}
              className="flex items-center justify-center space-x-2 px-5 py-2.5 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-xl transition-all shadow-lg hover:shadow-xl disabled:opacity-50 font-semibold transform hover:scale-105"
            >
              <RefreshCw className={`w-4 h-4 ${loadingResults ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>

          {loadingResults ? (
            <div className="text-center py-16 bg-gradient-to-br from-slate-50 to-blue-50 rounded-2xl border-2 border-slate-200">
              <div className="animate-spin rounded-full h-16 w-16 border-4 border-blue-200 border-t-blue-600 mx-auto"></div>
              <p className="mt-6 text-slate-700 font-medium text-lg">Loading analysis results...</p>
            </div>
          ) : analysisResults.length === 0 ? (
            <div className="text-center py-16 bg-gradient-to-br from-slate-50 via-blue-50 to-purple-50 rounded-2xl border-2 border-slate-200">
              <div className="w-20 h-20 bg-gradient-to-br from-blue-100 to-purple-100 rounded-full flex items-center justify-center mx-auto mb-6">
                <Info className="w-10 h-10 text-blue-600" />
              </div>
              <h3 className="text-2xl font-bold text-slate-900 mb-3">No Analysis Results Yet</h3>
              <p className="text-slate-600 max-w-md mx-auto leading-relaxed mb-6">
                Analysis results will appear here after you install the GitHub App and create PRs or push code with IAM policy changes.
              </p>
              <div className="flex flex-col sm:flex-row gap-3 justify-center items-center text-sm text-slate-600">
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-600" />
                  <span>Install GitHub App</span>
                </div>
                <div className="hidden sm:block text-slate-400">→</div>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-600" />
                  <span>Create PR or Push</span>
                </div>
                <div className="hidden sm:block text-slate-400">→</div>
                <div className="flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-blue-600" />
                  <span>See Results Here</span>
                </div>
              </div>
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
                      <div className="space-y-4">
                        <div className="flex items-center justify-between mb-4">
                          <h4 className="font-bold text-slate-900 text-lg flex items-center gap-2">
                            <AlertTriangle className="w-5 h-5 text-amber-600" />
                            Security Findings
                          </h4>
                          <div className="text-sm text-slate-600">
                            <span className="font-semibold">{result.findings.length}</span> issue{result.findings.length !== 1 ? 's' : ''} found
                          </div>
                        </div>
                        {result.findings.map((finding, idx) => (
                          <div
                            key={idx}
                            className={`border-2 rounded-xl p-5 ${getSeverityColor(finding.severity)} transition-all hover:shadow-md`}
                          >
                            <div className="flex items-start justify-between mb-3">
                              <div className="flex items-center gap-2">
                                <span className={`font-bold text-xs uppercase px-2.5 py-1 rounded-lg ${
                                  finding.severity === 'Critical' ? 'bg-red-100 text-red-700' :
                                  finding.severity === 'High' ? 'bg-orange-100 text-orange-700' :
                                  finding.severity === 'Medium' ? 'bg-amber-100 text-amber-700' :
                                  'bg-yellow-100 text-yellow-700'
                                }`}>
                                  {finding.severity}
                                </span>
                                {finding.type && (
                                  <span className="text-xs text-slate-500 bg-slate-100 px-2 py-1 rounded">
                                    {finding.type}
                                  </span>
                                )}
                              </div>
                            </div>
                            <h5 className="font-bold text-slate-900 mb-2 text-base">{finding.title}</h5>
                            <p className="text-sm text-slate-700 mb-3 leading-relaxed">{finding.description}</p>
                            
                            {/* Additional details if available */}
                            {(finding as any).recommendation && (
                              <div className="mt-3 pt-3 border-t border-slate-200">
                                <p className="text-xs font-semibold text-slate-600 mb-1.5 flex items-center gap-1">
                                  <CheckCircle className="w-3.5 h-3.5 text-blue-600" />
                                  Recommendation
                                </p>
                                <p className="text-sm text-slate-700 bg-blue-50 rounded-lg p-3 border border-blue-100">
                                  {(finding as any).recommendation}
                                </p>
                              </div>
                            )}
                            
                            {(finding as any).affected_permissions && (finding as any).affected_permissions.length > 0 && (
                              <div className="mt-3 pt-3 border-t border-slate-200">
                                <p className="text-xs font-semibold text-slate-600 mb-1.5 flex items-center gap-1">
                                  <Key className="w-3.5 h-3.5 text-purple-600" />
                                  Affected Permissions
                                </p>
                                <div className="flex flex-wrap gap-1.5">
                                  {(finding as any).affected_permissions.slice(0, 5).map((perm: string, permIdx: number) => (
                                    <span key={permIdx} className="text-xs bg-purple-50 text-purple-700 px-2 py-1 rounded border border-purple-200 font-mono">
                                      {perm}
                                    </span>
                                  ))}
                                  {(finding as any).affected_permissions.length > 5 && (
                                    <span className="text-xs text-slate-500 px-2 py-1">
                                      +{(finding as any).affected_permissions.length - 5} more
                                    </span>
                                  )}
                                </div>
                              </div>
                            )}
                            
                            {(finding as any).impact && (
                              <div className="mt-3 pt-3 border-t border-slate-200">
                                <p className="text-xs font-semibold text-slate-600 mb-1.5 flex items-center gap-1">
                                  <AlertCircle className="w-3.5 h-3.5 text-red-600" />
                                  Impact
                                </p>
                                <p className="text-sm text-slate-700 italic">
                                  {(finding as any).impact}
                                </p>
                              </div>
                            )}
                            
                            {(finding as any).policy_snippet && (
                              <div className="mt-3 pt-3 border-t border-slate-200">
                                <p className="text-xs font-semibold text-slate-600 mb-1.5 flex items-center gap-1">
                                  <FileCode className="w-3.5 h-3.5 text-slate-600" />
                                  Policy Snippet
                                </p>
                                <pre className="text-xs bg-slate-900 text-slate-100 p-3 rounded-lg overflow-x-auto border border-slate-700 font-mono">
                                  {(finding as any).policy_snippet}
                                </pre>
                              </div>
                            )}
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

                    {/* Analysis Summary */}
                    <div className="bg-gradient-to-br from-slate-50 to-blue-50 rounded-xl p-5 border-2 border-slate-200 mt-4">
                      <h5 className="font-bold text-slate-900 mb-4 flex items-center gap-2">
                        <Info className="w-4 h-4 text-blue-600" />
                        Analysis Summary
                      </h5>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-4">
                        <div className="bg-white rounded-lg p-3 border border-slate-200">
                          <p className="text-xs text-slate-500 mb-1 font-medium">Files Analyzed</p>
                          <p className="text-xl font-bold text-slate-900">{result.files_analyzed}</p>
                        </div>
                        <div className="bg-white rounded-lg p-3 border border-slate-200">
                          <p className="text-xs text-slate-500 mb-1 font-medium">Policies Analyzed</p>
                          <p className="text-xl font-bold text-slate-900">{result.policies_analyzed}</p>
                        </div>
                        <div className="bg-white rounded-lg p-3 border border-slate-200">
                          <p className="text-xs text-slate-500 mb-1 font-medium">Total Findings</p>
                          <p className="text-xl font-bold text-slate-900">{result.findings.length}</p>
                        </div>
                        <div className="bg-white rounded-lg p-3 border border-slate-200">
                          <p className="text-xs text-slate-500 mb-1 font-medium">Risk Score</p>
                          <p className={`text-xl font-bold ${getRiskScoreColor(result.risk_score)}`}>
                            {result.risk_score}/100
                          </p>
                        </div>
                      </div>
                      
                      {/* Severity Breakdown */}
                      {result.findings.length > 0 && (
                        <div className="mt-4 pt-4 border-t border-slate-200">
                          <p className="text-xs font-semibold text-slate-600 mb-2">Severity Breakdown</p>
                          <div className="flex flex-wrap gap-2">
                            {['Critical', 'High', 'Medium', 'Low'].map((severity) => {
                              const count = result.findings.filter(f => f.severity === severity).length;
                              if (count === 0) return null;
                              return (
                                <span
                                  key={severity}
                                  className={`text-xs font-semibold px-3 py-1.5 rounded-lg ${
                                    severity === 'Critical' ? 'bg-red-100 text-red-700' :
                                    severity === 'High' ? 'bg-orange-100 text-orange-700' :
                                    severity === 'Medium' ? 'bg-amber-100 text-amber-700' :
                                    'bg-yellow-100 text-yellow-700'
                                  }`}
                                >
                                  {severity}: {count}
                                </span>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Action Links */}
                    <div className="flex flex-wrap items-center gap-3 pt-4 border-t-2 border-slate-200">
                      {result.pr_number && (
                        <a
                          href={`https://github.com/${result.repo}/pull/${result.pr_number}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-lg transition-all shadow-md hover:shadow-lg text-sm font-semibold"
                        >
                          <Github className="w-4 h-4" />
                          <span>View Pull Request</span>
                          <ExternalLink className="w-4 h-4" />
                        </a>
                      )}
                      {result.commit_sha && (
                        <a
                          href={`https://github.com/${result.repo}/commit/${result.commit_sha}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center space-x-2 px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg transition-all text-sm font-semibold"
                        >
                          <span>View Commit</span>
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
