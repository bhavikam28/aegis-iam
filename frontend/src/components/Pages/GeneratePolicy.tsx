import React, { useState, useEffect } from 'react';
import { Shield, Send, RefreshCw, User, Bot, MessageSquare, Lock, ArrowRight, CheckCircle, ChevronDown, ChevronUp, AlertCircle, Download, Copy, Sparkles, Info, AlertTriangle } from 'lucide-react';
import { generatePolicy, sendFollowUp } from '../../services/api';
import { GeneratePolicyResponse, ChatMessage } from '../../types';

const GeneratePolicy: React.FC = () => {
  const [description, setDescription] = useState('');
  const [restrictive, setRestrictive] = useState(true);
  const [compliance, setCompliance] = useState('general');
  const [response, setResponse] = useState<GeneratePolicyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [followUpMessage, setFollowUpMessage] = useState('');
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isChatExpanded, setIsChatExpanded] = useState(true);
  const [copied, setCopied] = useState(false);
  const [showInitialForm, setShowInitialForm] = useState(true);

  const complianceFrameworks = [
    { value: 'general', label: 'General Security' },
    { value: 'pci-dss', label: 'PCI DSS' },
    { value: 'hipaa', label: 'HIPAA' },
    { value: 'sox', label: 'SOX' },
    { value: 'gdpr', label: 'GDPR' },
    { value: 'cis', label: 'CIS Benchmarks' }
  ];

  useEffect(() => {
    if (response?.conversation_history) {
      setChatHistory(response.conversation_history);
    }
  }, [response]);

  const handleCopyPolicy = async () => {
    if (response?.policy) {
      await navigator.clipboard.writeText(JSON.stringify(response.policy, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownloadPolicy = () => {
    if (response?.policy) {
      const blob = new Blob([JSON.stringify(response.policy, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'secure-iam-policy.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  };

  const cleanMarkdown = (text: string): string => {
    return text
      .replace(/\*\*/g, '')
      .replace(/\*/g, '')
      .replace(/`/g, '')
      .replace(/###/g, '')
      .replace(/##/g, '')
      .replace(/json\n/g, '')
      .replace(/```/g, '')
      .trim();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!description.trim()) return;

    setLoading(true);
    setError(null);
    setResponse(null);
    setShowInitialForm(false);
    
    try {
      const result = await generatePolicy({
        description,
        restrictive,
        compliance
      });
      setResponse(result);
      setConversationId(result.conversation_id || null);
    } catch (err) {
      console.error("Error generating policy:", err);
      setError(err instanceof Error ? err.message : 'Failed to generate policy');
      setShowInitialForm(true);
    } finally {
      setLoading(false);
    }
  };

  const handleFollowUp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!followUpMessage.trim() || !conversationId) return;

    setLoading(true);
    setError(null);
    
    try {
      const result = await sendFollowUp(followUpMessage, conversationId);
      setResponse(result);
      setFollowUpMessage('');
    } catch (err) {
      console.error("Error sending follow-up:", err);
      setError(err instanceof Error ? err.message : 'Failed to refine policy');
    } finally {
      setLoading(false);
    }
  };

  const handleNewConversation = () => {
    setResponse(null);
    setConversationId(null);
    setFollowUpMessage('');
    setChatHistory([]);
    setDescription('');
    setError(null);
    setShowInitialForm(true);
  };

  // Check if we have a complete policy (not just asking questions)
  const hasPolicy = response?.policy !== null && 
                    response?.policy !== undefined && 
                    typeof response?.policy === 'object' &&
                    Object.keys(response?.policy || {}).length > 0 &&
                    response?.is_question !== true;

  // Get score - from multiple possible locations
  const securityScore = response?.security_score || 0;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Initial Form */}
      {showInitialForm && !response && (
        <div className="relative overflow-hidden">
          <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-purple-500/10 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-pink-500/8 rounded-full blur-3xl"></div>
          
          <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-12 sm:pt-20 pb-16 sm:pb-32">
            <div className="mb-12 sm:mb-16">
              <div className="inline-flex items-center space-x-2 bg-purple-500/10 border border-purple-500/30 rounded-full px-4 sm:px-6 py-2 mb-4 sm:mb-6">
                <Shield className="w-4 h-4 text-purple-400" />
                <span className="text-purple-400 text-xs sm:text-sm font-medium">AI-Powered Security</span>
              </div>
              
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-white mb-4 sm:mb-6 leading-tight">
                Generate Secure<br />
                <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-500 bg-clip-text text-transparent">
                  IAM Policies
                </span>
              </h1>
              
              <p className="text-base sm:text-xl text-slate-400 max-w-3xl leading-relaxed">
                Describe your permission needs in plain English. Our AI automatically generates 
                secure, least-privilege IAM policies following AWS best practices.
              </p>
            </div>

            <div className="max-w-4xl mx-auto">
              <form onSubmit={handleSubmit}>
                <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl sm:rounded-3xl p-6 sm:p-10 shadow-2xl">
                  <div className="mb-6 sm:mb-8">
                    <label className="block text-white text-base sm:text-lg font-semibold mb-3 sm:mb-4">
                      What permissions do you need?
                    </label>
                    <textarea
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="Example: Lambda function to read from S3 bucket customer-uploads-prod and write to DynamoDB table transaction-logs..."
                      className="w-full h-32 sm:h-40 px-4 sm:px-6 py-3 sm:py-5 bg-slate-800/50 border border-slate-700/50 rounded-xl sm:rounded-2xl text-white text-base sm:text-lg placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none resize-none transition-all"
                      required
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 sm:gap-6 mb-6 sm:mb-8">
                    <div className="flex items-center space-x-3 sm:space-x-4 bg-slate-800/30 rounded-xl sm:rounded-2xl p-4 sm:p-6 border border-slate-700/50">
                      <div className="w-10 h-10 sm:w-12 sm:h-12 bg-purple-500/10 rounded-lg sm:rounded-xl flex items-center justify-center flex-shrink-0 border border-purple-500/30">
                        <Lock className="w-5 h-5 sm:w-6 sm:h-6 text-purple-400" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center space-x-2 sm:space-x-3 mb-1">
                          <input
                            id="restrictive"
                            type="checkbox"
                            checked={restrictive}
                            onChange={(e) => setRestrictive(e.target.checked)}
                            className="w-4 h-4 sm:w-5 sm:h-5 bg-slate-700 border-slate-600 rounded text-purple-500 focus:ring-purple-500 cursor-pointer flex-shrink-0"
                          />
                          <label htmlFor="restrictive" className="text-white text-sm sm:text-base font-medium cursor-pointer truncate">
                            Maximum Security
                          </label>
                        </div>
                        <p className="text-slate-400 text-xs sm:text-sm">Least-privilege mode</p>
                      </div>
                    </div>

                    <div className="bg-slate-800/30 rounded-xl sm:rounded-2xl p-4 sm:p-6 border border-slate-700/50">
                      <label className="block text-white text-sm sm:text-base font-medium mb-2 sm:mb-3">Compliance</label>
                      <select
                        value={compliance}
                        onChange={(e) => setCompliance(e.target.value)}
                        className="w-full px-3 sm:px-4 py-2 sm:py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg sm:rounded-xl text-white text-sm sm:text-base focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none cursor-pointer"
                      >
                        {complianceFrameworks.map(framework => (
                          <option key={framework.value} value={framework.value}>
                            {framework.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={loading || !description.trim()}
                    className="w-full bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 hover:from-orange-700 hover:via-pink-600 hover:to-purple-700 text-white py-4 sm:py-5 px-6 sm:px-8 rounded-xl sm:rounded-2xl font-semibold text-base sm:text-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-purple-500/25 hover:shadow-xl hover:shadow-purple-500/40 flex items-center justify-center space-x-2 sm:space-x-3 group"
                  >
                    <Shield className="w-5 h-5 sm:w-6 sm:h-6" />
                    <span>Generate Secure Policy</span>
                    <ArrowRight className="w-4 h-4 sm:w-5 sm:h-5 group-hover:translate-x-1 transition-transform" />
                  </button>
                </div>
              </form>

              {error && (
                <div className="mt-6 bg-red-500/10 border border-red-500/30 rounded-xl sm:rounded-2xl p-4 sm:p-6">
                  <p className="text-red-400 text-sm sm:text-base">{error}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Professional Loading State */}
      {!showInitialForm && loading && (
        <div className="relative overflow-hidden min-h-screen flex items-center justify-center">
          <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-purple-500/10 rounded-full blur-3xl animate-pulse"></div>
          <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-pink-500/10 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
          
          <div className="relative text-center px-8 max-w-2xl">
            <div className="inline-flex items-center justify-center w-24 h-24 mb-8 relative">
              <div className="absolute inset-0 bg-gradient-to-br from-orange-500/20 via-pink-500/20 to-purple-600/20 rounded-full animate-ping"></div>
              <div className="absolute inset-0 bg-gradient-to-br from-orange-500 via-pink-500 to-purple-600 rounded-full opacity-20 animate-pulse"></div>
              <Shield className="w-12 h-12 text-purple-400 relative z-10" />
            </div>
            
            <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
              Aegis AI Analyzing
            </h2>
            
            <p className="text-lg sm:text-xl text-slate-300 mb-8 leading-relaxed">
              Crafting your secure IAM policy with least-privilege principles...
            </p>
            
            <div className="flex items-center justify-center space-x-2 mb-8">
              <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0ms', animationDuration: '1s' }}></div>
              <div className="w-2 h-2 bg-pink-400 rounded-full animate-bounce" style={{ animationDelay: '200ms', animationDuration: '1s' }}></div>
              <div className="w-2 h-2 bg-orange-400 rounded-full animate-bounce" style={{ animationDelay: '400ms', animationDuration: '1s' }}></div>
            </div>

            <div className="text-sm text-slate-500">
              This may take a few moments...
            </div>
          </div>
        </div>
      )}

      {/* CLEAN Information Request Page */}
      {!showInitialForm && !loading && response && response.is_question && (
        <div className="relative overflow-hidden min-h-screen">
          <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-purple-500/10 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-pink-500/8 rounded-full blur-3xl"></div>
          
          <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
            <div className="text-center mb-12">
              <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-2xl mb-6 border border-purple-500/30">
                <Bot className="w-10 h-10 text-purple-400" />
              </div>
              
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
                {response.validation_issues && response.validation_issues.length > 0 
                  ? "Let's Fix These Issues" 
                  : "Just a Few More Details"}
              </h2>
              
              <p className="text-lg text-slate-400">
                {response.validation_issues && response.validation_issues.length > 0
                  ? "I found some invalid information in your request"
                  : "To generate the most secure policy, I need some additional information"}
              </p>
            </div>

            {/* Validation Issues - If present */}
            {response.validation_issues && response.validation_issues.length > 0 && (
              <div className="mb-6 space-y-4">
                {response.validation_issues.map((issue, idx) => (
                  <div key={idx} className="bg-gradient-to-br from-orange-500/10 to-red-500/10 border border-orange-500/30 rounded-2xl p-6">
                    <div className="flex items-start space-x-4">
                      <div className="w-12 h-12 bg-orange-500/20 rounded-xl flex items-center justify-center flex-shrink-0 border border-orange-500/30">
                        <AlertTriangle className="w-6 h-6 text-orange-400" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h4 className="text-orange-300 font-bold">
                            {issue.type === 'invalid_region' ? '🌍 Invalid Region' :
                             issue.type === 'invalid_account_id' ? '🔢 Invalid Account ID' :
                             issue.type === 'invalid_resource_name' ? '📦 Invalid Resource Name' :
                             issue.type === 'invalid_arn' ? '🔗 Invalid ARN Format' :
                             '⚠️ Input Issue'}
                          </h4>
                        </div>
                        
                        <div className="bg-slate-950/50 rounded-lg p-3 mb-3">
                          <div className="text-xs text-slate-500 mb-1">You provided:</div>
                          <code className="text-sm text-red-300 font-mono">{issue.found}</code>
                        </div>
                        
                        <p className="text-slate-300 text-sm mb-3 leading-relaxed">
                          <span className="font-semibold text-orange-300">Problem:</span> {issue.problem}
                        </p>
                        
                        <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
                          <div className="flex items-start space-x-2">
                            <Sparkles className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                            <div>
                              <div className="text-xs text-green-400 font-semibold mb-1">Suggestion:</div>
                              <p className="text-slate-200 text-sm">{issue.suggestion}</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Agent's Question - SEPARATE BOX */}
            <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8 mb-6">
              <div className="flex items-start space-x-4 mb-4">
                <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center flex-shrink-0 border border-purple-500/30">
                  <Bot className="w-6 h-6 text-purple-400" />
                </div>
                <div className="flex-1">
                  <h3 className="text-white font-semibold mb-2">Aegis AI</h3>
                  <div className="text-slate-300 leading-relaxed whitespace-pre-wrap">
                    {cleanMarkdown(response.explanation)}
                  </div>
                </div>
              </div>
            </div>

            {/* Response Form - SEPARATE BOX */}
            <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8 mb-6">
              <form onSubmit={handleFollowUp}>
                <label className="block text-white font-medium mb-4">
                  Your Response
                </label>
                <textarea
                  value={followUpMessage}
                  onChange={(e) => setFollowUpMessage(e.target.value)}
                  placeholder="Provide the requested information..."
                  className="w-full h-32 px-6 py-4 bg-slate-800/50 border border-slate-700/50 rounded-xl text-white placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none resize-none mb-4"
                  disabled={loading}
                />
                <button
                  type="submit"
                  disabled={loading || !followUpMessage.trim()}
                  className="w-full bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 hover:from-orange-700 hover:via-pink-600 hover:to-purple-700 text-white py-4 px-6 rounded-xl font-semibold disabled:opacity-50 transition-all shadow-lg shadow-purple-500/25 hover:shadow-xl hover:shadow-purple-500/40 flex items-center justify-center space-x-2 sm:space-x-3 group"
                >
                  {loading ? (
                    <>
                      <div className="w-5 h-5 border-3 border-white border-t-transparent rounded-full animate-spin"></div>
                      <span>Processing...</span>
                    </>
                  ) : (
                    <>
                      <Send className="w-5 h-5" />
                      <span>Submit Information</span>
                    </>
                  )}
                </button>
              </form>
            </div>

            {/* Quick Tips - SEPARATE BOX */}
            <div className="bg-purple-500/10 backdrop-blur-xl border border-purple-500/30 rounded-2xl p-6 mb-6">
              <div className="flex items-start space-x-3">
                <Sparkles className="w-5 h-5 text-purple-400" />
                <div>
                  <h4 className="text-purple-300 font-semibold mb-2">Quick Tips</h4>
                  <ul className="space-y-1 text-slate-400 text-sm">
                    <li>• Be as specific as possible with AWS Account IDs and regions</li>
                    <li>• If you don't have the information right now, I can use placeholders</li>
                    <li>• You can always refine the policy after it's generated</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Start Over Button - SEPARATE BOX */}
            <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl overflow-hidden">
              <button
                onClick={handleNewConversation}
                className="w-full px-6 py-4 bg-slate-800 hover:bg-slate-700 text-white transition-all flex items-center justify-center space-x-2"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Start Over</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* PREMIUM Results with Separate Boxes */}
      {!showInitialForm && !loading && response && !response.is_question && hasPolicy && (
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="flex items-center justify-between mb-12">
            <div>
              <h2 className="text-3xl font-bold text-white mb-2">
                Policy Generated Successfully
              </h2>
              <p className="text-slate-400">
                Review your secure IAM policy below
              </p>
            </div>
            <button
              onClick={handleNewConversation}
              className="px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white rounded-xl transition-all border border-slate-700 flex items-center space-x-2"
            >
              <RefreshCw className="w-4 h-4" />
              <span>New Policy</span>
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
            {/* Security Score - SEPARATE BOX (Full Width) */}
            <div className="lg:col-span-12">
              <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8">
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <h3 className="text-white text-2xl font-bold mb-2">Security Score</h3>
                    <p className="text-slate-400">Based on AWS best practices</p>
                  </div>
                  <div className="text-center">
                    <div className={`text-6xl font-bold ${
                      securityScore >= 90 ? 'text-green-400' :
                      securityScore >= 80 ? 'text-yellow-400' :
                      securityScore >= 70 ? 'text-orange-400' : 'text-red-400'
                    }`}>
                      {securityScore}
                    </div>
                    <div className="text-slate-400 text-sm mt-2">/ 100</div>
                  </div>
                </div>
                
                <div className="w-full bg-slate-800 rounded-full h-4">
                  <div
                    className={`h-4 rounded-full transition-all duration-1000 ${
                      securityScore >= 90 ? 'bg-gradient-to-r from-green-500 to-green-400' :
                      securityScore >= 80 ? 'bg-gradient-to-r from-yellow-500 to-yellow-400' :
                      securityScore >= 70 ? 'bg-gradient-to-r from-orange-500 to-pink-500' :
                      'bg-gradient-to-r from-red-500 to-pink-500'
                    }`}
                    style={{ width: `${securityScore}%` }}
                  ></div>
                </div>
              </div>
            </div>

            {/* LEFT COLUMN - Main Content */}
            <div className="lg:col-span-8 space-y-6">
              {/* IAM Policy Box */}
              <div>
                <h3 className="text-white text-xl font-semibold mb-4">IAM Policy</h3>
                <div className="bg-slate-900 border border-purple-500/20 rounded-2xl overflow-hidden">
                  <div className="flex items-center justify-between px-6 py-4 border-b border-purple-500/20 bg-slate-800/50">
                    <div className="flex items-center space-x-3">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                        <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                        <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                      </div>
                      <span className="text-sm text-slate-400">secure-iam-policy.json</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <button 
                        onClick={handleCopyPolicy}
                        className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm text-white transition-all flex items-center space-x-2"
                      >
                        {copied ? (
                          <>
                            <CheckCircle className="w-4 h-4 text-green-400" />
                            <span>Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-4 h-4" />
                            <span>Copy</span>
                          </>
                        )}
                      </button>
                      <button 
                        onClick={handleDownloadPolicy}
                        className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg text-sm text-white transition-all flex items-center space-x-2"
                      >
                        <Download className="w-4 h-4" />
                        <span>Download</span>
                      </button>
                    </div>
                  </div>
                  <div className="p-6 overflow-x-auto max-h-[500px]">
                    <pre className="text-sm text-slate-300 font-mono leading-relaxed">
                      {JSON.stringify(response.policy, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>

              {/* Trust Policy Box */}
              {response.trust_policy && (
                <div>
                  <h3 className="text-white text-xl font-semibold mb-4 flex items-center space-x-2">
                    <span>🤝 Trust Policy</span>
                  </h3>
                  <div className="bg-slate-900 border border-green-500/20 rounded-2xl overflow-hidden">
                    <div className="flex items-center justify-between px-6 py-4 border-b border-green-500/20 bg-slate-800/50">
                      <div className="flex items-center space-x-3">
                        <div className="flex items-center space-x-2">
                          <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                          <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                          <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                        </div>
                        <span className="text-sm text-slate-400">trust-policy.json</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <button 
                          onClick={async () => {
                            await navigator.clipboard.writeText(JSON.stringify(response.trust_policy, null, 2));
                          }}
                          className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm text-white transition-all flex items-center space-x-2"
                        >
                          <Copy className="w-4 h-4" />
                          <span>Copy</span>
                        </button>
                        <button 
                          onClick={() => {
                            const blob = new Blob([JSON.stringify(response.trust_policy, null, 2)], { type: 'application/json' });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = 'trust-policy.json';
                            document.body.appendChild(a);
                            a.click();
                            document.body.removeChild(a);
                            URL.revokeObjectURL(url);
                          }}
                          className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-sm text-white transition-all flex items-center space-x-2"
                        >
                          <Download className="w-4 h-4" />
                          <span>Download</span>
                        </button>
                      </div>
                    </div>
                    <div className="p-6 overflow-x-auto max-h-[400px]">
                      <pre className="text-sm text-slate-300 font-mono leading-relaxed">
                        {JSON.stringify(response.trust_policy, null, 2)}
                      </pre>
                    </div>
                  </div>
                  
                  {/* Info box explaining trust policy */}
                  <div className="mt-4 bg-green-500/10 border border-green-500/30 rounded-xl p-4">
                    <div className="flex items-start space-x-3">
                      <Info className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" />
                      <div>
                        <div className="text-sm font-semibold text-green-300 mb-1">About Trust Policy</div>
                        <p className="text-sm text-slate-300">
                          The Trust Policy defines <strong>WHO</strong> can assume this IAM role. Without it, 
                          nobody (not even AWS services) can use the permissions policy above. Both policies 
                          work together to create a complete, functional IAM role.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Refine Policy Input */}
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-6">
                <label className="block text-white font-medium mb-3">Refine Policy</label>
                <form onSubmit={handleFollowUp} className="flex space-x-3">
                  <input
                    type="text"
                    value={followUpMessage}
                    onChange={(e) => setFollowUpMessage(e.target.value)}
                    placeholder="Add restrictions, conditions, or modifications..."
                    className="flex-1 px-4 py-3 bg-slate-800/50 border border-slate-700/50 rounded-xl text-white placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none"
                    disabled={loading}
                  />
                  <button
                    type="submit"
                    disabled={loading || !followUpMessage.trim()}
                    className="px-5 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-xl disabled:opacity-50 transition-all shadow-lg shadow-purple-500/25"
                  >
                    <Send className="w-5 h-5" />
                  </button>
                </form>
              </div>

              {/* Suggested Refinements */}
              {response.refinement_suggestions && response.refinement_suggestions.length > 0 && (
                <div className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 backdrop-blur-xl border border-purple-500/30 rounded-2xl p-6">
                  <div className="flex items-center space-x-2 mb-4">
                    <Sparkles className="w-5 h-5 text-purple-400" />
                    <h4 className="text-white font-semibold">Suggested Refinements</h4>
                  </div>
                  <div className="grid grid-cols-1 gap-3">
                    {response.refinement_suggestions.map((suggestion, index) => (
                      <button
                        key={index}
                        onClick={() => setFollowUpMessage(suggestion)}
                        className="group px-4 py-3 bg-slate-800/50 hover:bg-purple-500/20 border border-purple-500/30 hover:border-purple-500/50 rounded-xl text-sm text-slate-300 hover:text-white transition-all flex items-center justify-between text-left"
                      >
                        <div className="flex items-center space-x-3">
                          <div className="w-8 h-8 bg-purple-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                            <Sparkles className="w-4 h-4 text-purple-400" />
                          </div>
                          <span>{suggestion}</span>
                        </div>
                        <ArrowRight className="w-4 h-4 text-purple-400 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* RIGHT SIDEBAR */}
            <div className="lg:col-span-4 space-y-6">
              {/* Security Features */}
              {response.security_features && response.security_features.length > 0 && (
                <div className="bg-green-500/5 backdrop-blur-xl border border-green-500/30 rounded-2xl p-6">
                  <h4 className="text-green-400 text-lg font-semibold mb-4 flex items-center space-x-2">
                    <CheckCircle className="w-5 h-5" />
                    <span>Security Features</span>
                  </h4>
                  <ul className="space-y-3">
                    {response.security_features.map((feature, index) => (
                      <li key={index} className="text-slate-300 text-sm flex items-start space-x-3">
                        <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                        <span>{cleanMarkdown(feature)}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Security Considerations */}
              {response.security_notes && response.security_notes.length > 0 && (
                <div className="bg-orange-500/5 backdrop-blur-xl border border-orange-500/30 rounded-2xl p-6">
                  <h4 className="text-orange-400 text-lg font-semibold mb-4 flex items-center space-x-2">
                    <AlertCircle className="w-5 h-5" />
                    <span>Considerations</span>
                  </h4>
                  <ul className="space-y-3">
                    {response.security_notes.map((note, index) => (
                      <li key={index} className="text-slate-300 text-sm flex items-start space-x-3">
                        <AlertCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                        <span>{cleanMarkdown(note)}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>

          {/* Policy Explanation - IMPROVED VISUAL VERSION - FULL WIDTH */}
          <div className="mt-8 bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8">
            <h4 className="text-white text-2xl font-bold mb-2 flex items-center space-x-2">
              <Shield className="w-6 h-6 text-purple-400" />
              <span>What This Policy Does</span>
            </h4>
            <p className="text-slate-400 mb-8">Quick overview of each permission granted</p>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {(() => {
                if (!response.explanation || response.explanation.trim() === '') {
                  return (
                    <div className="col-span-2 text-slate-400 text-center py-8">
                      No detailed explanation available
                    </div>
                  );
                }

                const sections = response.explanation
                  .split(/(?=^\d+\.\s+)/m)
                  .filter(section => section.trim());
                
                if (sections.length === 0) {
                  return (
                    <div className="col-span-2 text-slate-400 text-center py-8">
                      Unable to parse explanation
                    </div>
                  );
                }

                // Helper function to get icon based on title
                const getIcon = (title: string) => {
                  const lowerTitle = title.toLowerCase();
                  if (lowerTitle.includes('s3') || lowerTitle.includes('bucket')) {
                    return '🪣';
                  }
                  if (lowerTitle.includes('dynamo')) {
                    return '🗄️';
                  }
                  if (lowerTitle.includes('cloudwatch') || lowerTitle.includes('log')) {
                    return '📊';
                  }
                  if (lowerTitle.includes('lambda')) {
                    return '⚡';
                  }
                  return '🔒';
                };

                return sections.map((section, index) => {
                  const match = section.match(/^(\d+)\.\s+(.+?)(?:\n|$)([\s\S]*)/);
                  if (!match) return null;
                  
                  const [, num, title, content] = match;
                  
                  // Parse content into key-value pairs
                  const details: { [key: string]: string } = {};
                  const lines = content.split('\n').map(line => line.trim()).filter(line => line.length > 0);
                  
                  lines.forEach(line => {
                    const colonIndex = line.indexOf(':');
                    if (colonIndex > 0 && colonIndex < 30) {
                      const key = line.substring(0, colonIndex).replace(/^-\s*/, '').trim();
                      const value = line.substring(colonIndex + 1).trim();
                      details[key] = value;
                    }
                  });
                  
                  return (
                    <div key={index} className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 rounded-2xl p-6 border border-slate-700/50 hover:border-purple-500/30 transition-all group">
                      {/* Header */}
                      <div className="flex items-start space-x-4 mb-4">
                        <div className="text-4xl">{getIcon(title)}</div>
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-1">
                            <span className="text-xs font-bold text-purple-400">STATEMENT {num}</span>
                          </div>
                          <h5 className="text-white font-bold text-lg leading-tight">{title.trim()}</h5>
                        </div>
                      </div>
                      
                      {/* Key Details */}
                      <div className="space-y-3">
                        {details['Permission'] && (
                          <div className="bg-slate-900/50 rounded-lg p-3">
                            <div className="text-xs text-slate-500 mb-1">Permission</div>
                            <div className="text-sm text-slate-200 font-mono break-all">{details['Permission']}</div>
                          </div>
                        )}
                        
                        {details['Purpose'] && (
                          <div>
                            <div className="text-xs text-slate-400 font-semibold mb-1">What it does</div>
                            <div className="text-sm text-slate-300">{details['Purpose']}</div>
                          </div>
                        )}
                        
                        {details['Security'] && (
                          <div className="flex items-start space-x-2 bg-green-500/5 border border-green-500/20 rounded-lg p-3">
                            <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                            <div className="text-xs text-green-300">{details['Security']}</div>
                          </div>
                        )}
                        
                        {details['Why this ARN'] && (
                          <div className="text-xs text-slate-500 italic">
                            💡 {details['Why this ARN']}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                }).filter(Boolean);
              })()}
            </div>
            
            {/* Quick Summary */}
            <div className="mt-6 bg-purple-500/5 border border-purple-500/20 rounded-xl p-4 flex items-start space-x-3">
              <Info className="w-5 h-5 text-purple-400 mt-0.5 flex-shrink-0" />
              <div className="flex-1">
                <div className="text-sm font-semibold text-purple-300 mb-1">Summary</div>
                <div className="text-sm text-slate-300">
                  This policy grants secure access with minimum necessary permissions. All actions are scoped to specific resources following AWS best practices.
                </div>
              </div>
            </div>
          </div>

          {/* Conversation History - FULL WIDTH BELOW GRID */}
          {chatHistory && chatHistory.length > 0 && (
            <div className="mt-8 bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl overflow-hidden">
              <button
                onClick={() => setIsChatExpanded(!isChatExpanded)}
                className="w-full px-6 py-4 flex items-center justify-between hover:bg-slate-800/50 transition-all"
              >
                <div className="flex items-center space-x-3">
                  <MessageSquare className="w-5 h-5 text-purple-400" />
                  <span className="text-white font-semibold text-sm">Conversation ({chatHistory.length} messages)</span>
                </div>
                {isChatExpanded ? (
                  <ChevronUp className="w-5 h-5 text-slate-400" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-slate-400" />
                )}
              </button>
              
              {isChatExpanded && (
                <div className="px-6 py-6 space-y-4 max-h-[600px] overflow-y-auto border-t border-slate-700/50 bg-slate-800/20">
                  {chatHistory.map((msg, index) => (
                    <div key={index} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                      <div className={`flex items-start space-x-3 ${msg.content.startsWith('```json') ? 'w-full' : 'max-w-[70%]'} ${msg.role === 'user' ? 'flex-row-reverse space-x-reverse' : ''}`}>
                        <div className={`w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 ${
                          msg.role === 'user' 
                            ? 'bg-gradient-to-br from-orange-500/20 to-pink-500/20 border border-orange-500/30' 
                            : 'bg-gradient-to-br from-purple-500/20 to-pink-500/20 border border-purple-500/30'
                        }`}>
                          {msg.role === 'user' ? (
                            <User className="w-5 h-5 text-orange-400" />
                          ) : (
                            <Bot className="w-5 h-5 text-purple-400" />
                          )}
                        </div>
                        
                        <div className={`flex-1 rounded-2xl px-5 py-4 ${
                          msg.role === 'user'
                            ? 'bg-gradient-to-br from-orange-600/20 to-pink-600/20 border border-orange-500/30'
                            : 'bg-slate-800/80 border border-slate-700/50'
                        }`}>
                          <div className="flex items-center space-x-2 mb-2">
                            <span className={`text-xs font-semibold ${
                              msg.role === 'user' ? 'text-orange-300' : 'text-purple-300'
                            }`}>
                              {msg.role === 'user' ? 'You' : 'Aegis AI'}
                            </span>
                            <span className="text-xs text-slate-500">•</span>
                            <span className="text-xs text-slate-500">now</span>
                          </div>
                          {/* Check if content is JSON code block */}
                          {msg.content.startsWith('```json') ? (
                            <div className="bg-slate-900/70 rounded-xl p-4 overflow-x-auto border border-slate-700/50">
                              <pre className="text-[10px] text-slate-300 font-mono leading-relaxed whitespace-pre">
                                {(() => {
                                  try {
                                    const jsonStr = msg.content.replace(/```json\n?/, '').replace(/\n?```$/, '').trim();
                                    const parsed = JSON.parse(jsonStr);
                                    return JSON.stringify(parsed, null, 2);
                                  } catch (e) {
                                    // If parsing fails, show as-is
                                    return msg.content.replace(/```json\n?/, '').replace(/\n?```$/, '').trim();
                                  }
                                })()}
                              </pre>
                            </div>
                          ) : (
                            <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-wrap break-words">
                              {msg.content}
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default GeneratePolicy;