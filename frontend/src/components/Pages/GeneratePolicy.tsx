import React, { useState, useEffect } from 'react';
import { Shield, Send, RefreshCw, User, Bot, MessageSquare, Lock, Zap, ArrowRight, CheckCircle, ChevronDown, ChevronUp, AlertCircle } from 'lucide-react';
import { generatePolicy, sendFollowUp } from '../../services/api';
import { GeneratePolicyResponse, ChatMessage } from '../../types';

const GeneratePolicy: React.FC = () => {
  const [description, setDescription] = useState('');
  const [service, setService] = useState('S3');
  const [restrictive, setRestrictive] = useState(true);
  const [compliance, setCompliance] = useState('general');
  const [response, setResponse] = useState<GeneratePolicyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [followUpMessage, setFollowUpMessage] = useState('');
  const [isRefining, setIsRefining] = useState(false);
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isChatExpanded, setIsChatExpanded] = useState(false);

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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!description.trim()) return;

    setLoading(true);
    setError(null);
    setResponse(null); // Clear previous response
    
    try {
      const result = await generatePolicy({
        description,
        service,
        restrictive,
        compliance
      });
      
      setResponse(result);
      setConversationId(result.conversation_id || null);
      setIsRefining(true);
    } catch (err) {
      console.error("Error generating policy:", err);
      setError(err instanceof Error ? err.message : 'Failed to generate policy');
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
      const result = await sendFollowUp(followUpMessage, conversationId, service);
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
    setIsRefining(false);
    setFollowUpMessage('');
    setChatHistory([]);
    setDescription('');
    setError(null);
  };

  const handleSuggestionClick = (suggestion: string) => {
    setFollowUpMessage(suggestion);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {!isRefining && !response && (
        <div className="relative overflow-hidden">
          <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-purple-500/10 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-pink-500/8 rounded-full blur-3xl"></div>
          
          <div className="relative max-w-7xl mx-auto px-8 pt-20 pb-32">
            <div className="mb-16">
              <div className="inline-flex items-center space-x-2 bg-purple-500/10 border border-purple-500/30 rounded-full px-6 py-2 mb-6">
                <Shield className="w-4 h-4 text-purple-400" />
                <span className="text-purple-400 text-sm font-medium">AI-Powered Security</span>
              </div>
              
              <h1 className="text-6xl font-bold text-white mb-6 leading-tight">
                Generate Secure<br />
                <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-500 bg-clip-text text-transparent">
                  IAM Policies
                </span>
              </h1>
              
              <p className="text-xl text-slate-400 max-w-3xl leading-relaxed">
                Describe your permission needs in plain English. Our AI automatically generates 
                secure, least-privilege IAM policies following AWS best practices.
              </p>
            </div>

            <div className="max-w-4xl mx-auto">
              <form onSubmit={handleSubmit}>
                <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-3xl p-10 shadow-2xl">
                  <div className="mb-8">
                    <label className="block text-white text-lg font-semibold mb-4">
                      What permissions do you need?
                    </label>
                    <textarea
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="Example: I need read-only access to an S3 bucket named company-documents..."
                      className="w-full h-40 px-6 py-5 bg-slate-800/50 border border-slate-700/50 rounded-2xl text-white text-lg placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none resize-none transition-all"
                      required
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-6 mb-8">
                    <div className="flex items-center space-x-4 bg-slate-800/30 rounded-2xl p-6 border border-slate-700/50">
                      <div className="w-12 h-12 bg-purple-500/10 rounded-xl flex items-center justify-center flex-shrink-0 border border-purple-500/30">
                        <Lock className="w-6 h-6 text-purple-400" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-1">
                          <input
                            id="restrictive"
                            type="checkbox"
                            checked={restrictive}
                            onChange={(e) => setRestrictive(e.target.checked)}
                            className="w-5 h-5 bg-slate-700 border-slate-600 rounded text-purple-500 focus:ring-purple-500 cursor-pointer"
                          />
                          <label htmlFor="restrictive" className="text-white font-medium cursor-pointer">
                            Maximum Security
                          </label>
                        </div>
                        <p className="text-slate-400 text-sm">Least-privilege mode</p>
                      </div>
                    </div>

                    <div className="bg-slate-800/30 rounded-2xl p-6 border border-slate-700/50">
                      <label className="block text-white font-medium mb-3">Compliance</label>
                      <select
                        value={compliance}
                        onChange={(e) => setCompliance(e.target.value)}
                        className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-xl text-white focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none cursor-pointer"
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
                    className="w-full bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 hover:from-orange-700 hover:via-pink-600 hover:to-purple-700 text-white py-5 px-8 rounded-2xl font-semibold text-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-purple-500/25 hover:shadow-xl hover:shadow-purple-500/40 flex items-center justify-center space-x-3 group"
                  >
                    {loading ? (
                      <>
                        <div className="w-6 h-6 border-3 border-white border-t-transparent rounded-full animate-spin"></div>
                        <span>Generating...</span>
                      </>
                    ) : (
                      <>
                        <Shield className="w-6 h-6" />
                        <span>Generate Secure Policy</span>
                        <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                      </>
                    )}
                  </button>
                </div>
              </form>

              {error && (
                <div className="mt-6 bg-red-500/10 border border-red-500/30 rounded-2xl p-6">
                  <p className="text-red-400">{error}</p>
                </div>
              )}

              <div className="flex items-center justify-center space-x-8 mt-12 text-slate-400">
                <div className="flex items-center space-x-2">
                  <Shield className="w-5 h-5 text-purple-400" />
                  <span>Least Privilege</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Zap className="w-5 h-5 text-pink-400" />
                  <span>AI-Powered</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Lock className="w-5 h-5 text-orange-400" />
                  <span>AWS Compliant</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {(isRefining || response) && (
        <div className="max-w-[1600px] mx-auto px-8 py-12">
          <div className="flex items-center justify-between mb-12">
            <div>
              <h2 className="text-3xl font-bold text-white mb-2">Policy Generated</h2>
              <p className="text-slate-400">Review and refine your secure IAM policy</p>
            </div>
            <button
              onClick={handleNewConversation}
              className="flex items-center space-x-2 px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white rounded-xl transition-all border border-slate-700"
            >
              <RefreshCw className="w-4 h-4" />
              <span>New Policy</span>
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
            <div className="lg:col-span-2 space-y-6">
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl overflow-hidden">
                <div className="bg-slate-800/50 px-6 py-4 border-b border-purple-500/20">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <MessageSquare className="w-5 h-5 text-purple-400" />
                      <h3 className="text-white font-semibold">Conversation</h3>
                      <span className="text-slate-400 text-sm">({chatHistory.length})</span>
                    </div>
                    <button
                      onClick={() => setIsChatExpanded(!isChatExpanded)}
                      className="flex items-center space-x-2 px-3 py-2 bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/30 rounded-lg text-sm text-purple-300 hover:text-purple-200 transition-all"
                      title={isChatExpanded ? 'Collapse chat' : 'Expand chat'}
                    >
                      <span className="font-medium">{isChatExpanded ? 'Collapse' : 'Expand'}</span>
                      {isChatExpanded ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>
                
                <div className={`p-6 space-y-4 overflow-y-auto transition-all duration-300 ${
                  isChatExpanded ? 'max-h-[800px]' : 'max-h-[400px]'
                }`}>
                  {chatHistory.length === 0 ? (
                    <div className="text-center py-8 text-slate-400">
                      <Bot className="w-12 h-12 mx-auto mb-3 text-slate-600" />
                      <p>Start refining your policy by asking questions below</p>
                    </div>
                  ) : (
                    chatHistory.map((message, index) => (
                      <div key={index} className="flex items-start space-x-3">
                        {message.role === 'user' ? (
                          <div className="w-10 h-10 bg-orange-500/20 rounded-xl flex items-center justify-center flex-shrink-0 border border-orange-500/30">
                            <User className="w-5 h-5 text-orange-400" />
                          </div>
                        ) : (
                          <div className="w-10 h-10 bg-slate-700/50 rounded-xl flex items-center justify-center flex-shrink-0 border border-slate-600/50">
                            <Bot className="w-5 h-5 text-slate-400" />
                          </div>
                        )}
                        
                        <div className="flex-1">
                          <div className={`rounded-xl p-4 ${
                            message.role === 'user' 
                              ? 'bg-orange-500/10 border border-orange-500/30' 
                              : 'bg-slate-800/50 border border-slate-700/50'
                          }`}>
                            <p className="text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">
                              {message.content}
                            </p>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

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

              {response?.refinement_suggestions && response.refinement_suggestions.length > 0 && (
                <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-6">
                  <h4 className="text-white font-medium mb-4">Quick Refinements</h4>
                  <div className="space-y-2">
                    {response.refinement_suggestions.map((suggestion, index) => (
                      <button
                        key={index}
                        onClick={() => handleSuggestionClick(suggestion)}
                        className="w-full text-left px-4 py-3 bg-slate-800/50 hover:bg-slate-700/50 text-slate-300 rounded-xl text-sm transition-all border border-slate-700/50 hover:border-purple-500/30 flex items-start space-x-2"
                      >
                        {suggestion.startsWith('⚠️') ? (
                          <AlertCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                        ) : (
                          <Shield className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                        )}
                        <span>{suggestion.replace('⚠️ ', '')}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="lg:col-span-3 space-y-6">
              {loading && !response ? (
                <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl h-[600px] flex items-center justify-center">
                  <div className="text-center max-w-md">
                    <div className="relative mb-6">
                      <div className="w-20 h-20 border-4 border-slate-700 border-t-purple-500 rounded-full animate-spin mx-auto"></div>
                      <Shield className="w-8 h-8 text-purple-400 absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2" />
                    </div>
                    
                    <div className="space-y-2">
                      <p className="text-white text-lg font-semibold">
                        🤖 Aegis is working on your policy...
                      </p>
                      <p className="text-slate-400">
                        Analyzing security requirements and generating least-privilege policy
                      </p>
                    </div>
                    
                    <div className="mt-8 space-y-3 text-left">
                      <div className="flex items-center space-x-3">
                        <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                        <span className="text-slate-300 text-sm">Understanding requirements</span>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="w-2 h-2 bg-purple-400 rounded-full animate-pulse"></div>
                        <span className="text-slate-300 text-sm">Applying AWS best practices</span>
                      </div>
                      <div className="flex items-center space-x-3">
                        <div className="w-2 h-2 bg-slate-600 rounded-full"></div>
                        <span className="text-slate-500 text-sm">Validating security posture</span>
                      </div>
                    </div>
                  </div>
                </div>
              ) : response ? (
                <>
                  <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8">
                    <div className="flex items-center justify-between mb-6">
                      <div>
                        <h3 className="text-white text-2xl font-bold mb-2">Security Score</h3>
                        <p className="text-slate-400">Based on AWS security best practices</p>
                      </div>
                      <div className="text-center">
                        <div className={`text-6xl font-bold ${
                          response.security_score >= 90 ? 'text-green-400' :
                          response.security_score >= 80 ? 'text-yellow-400' :
                          response.security_score >= 70 ? 'text-orange-400' :
                          'text-red-400'
                        }`}>
                          {response.security_score}
                        </div>
                        <div className="text-slate-400 text-sm mt-2">/ 100</div>
                      </div>
                    </div>
                    
                    <div className="w-full bg-slate-800 rounded-full h-4 mb-6">
                      <div
                        className={`h-4 rounded-full transition-all duration-1000 ${
                          response.security_score >= 90 ? 'bg-gradient-to-r from-green-500 to-green-400' :
                          response.security_score >= 80 ? 'bg-gradient-to-r from-yellow-500 to-yellow-400' :
                          response.security_score >= 70 ? 'bg-gradient-to-r from-orange-500 to-pink-500' :
                          'bg-gradient-to-r from-red-500 to-pink-500'
                        }`}
                        style={{ width: `${response.security_score}%` }}
                      ></div>
                    </div>

                    {response.score_explanation && (
                      <div className="mt-6 pt-6 border-t border-slate-700">
                        <div className="text-slate-300 text-sm leading-relaxed whitespace-pre-line">
                          {response.score_explanation}
                        </div>
                      </div>
                    )}
                    
                    {response.score_breakdown && Object.keys(response.score_breakdown).length > 0 && (
                      <div className="mt-4 pt-4 border-t border-slate-700">
                        <p className="text-slate-400 text-sm mb-3 font-semibold">Score Breakdown:</p>
                        <div className="space-y-2">
                          {Object.entries(response.score_breakdown).map(([key, value]: [string, any]) => (
                            <div key={key} className="flex items-center justify-between text-sm">
                              <span className="text-slate-300">
                                {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                              </span>
                              <span className={`font-medium ${
                                Number(value) < 0 ? 'text-red-400' : 'text-green-400'
                              }`}>
                                {value} pts
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  <div>
                    <h3 className="text-white text-xl font-semibold mb-4">IAM Policy</h3>
                    <div className="bg-slate-900 border border-purple-500/20 rounded-2xl overflow-hidden">
                      <div className="flex items-center justify-between px-6 py-4 border-b border-purple-500/20 bg-slate-800/50">
                        <div className="flex items-center space-x-3">
                          <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                          <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                          <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                          <span className="text-sm text-slate-400 ml-2">secure-iam-policy.json</span>
                        </div>
                        <button 
                          onClick={() => {
                            navigator.clipboard.writeText(JSON.stringify(response.policy, null, 2));
                          }}
                          className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg text-sm text-white transition-all"
                        >
                          Copy
                        </button>
                      </div>
                      <div className="p-6 overflow-x-auto">
                        <pre className="text-sm text-slate-300 font-mono leading-relaxed">
                          {JSON.stringify(response.policy, null, 2)}
                        </pre>
                      </div>
                    </div>
                  </div>

                  <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8">
                    <h4 className="text-white text-lg font-semibold mb-4">Explanation</h4>
                    <p className="text-slate-300 leading-relaxed whitespace-pre-wrap">
                      {response.explanation}
                    </p>
                  </div>

                  {response.security_features && response.security_features.length > 0 && (
                    <div className="bg-purple-500/5 backdrop-blur-xl border border-purple-500/30 rounded-2xl p-8">
                      <h4 className="text-purple-400 text-lg font-semibold mb-4">Security Features</h4>
                      <ul className="space-y-3">
                        {response.security_features.map((feature, index) => (
                          <li key={index} className="text-slate-300 text-sm flex items-start space-x-3">
                            {feature.startsWith('✅') ? (
                              <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                            ) : feature.startsWith('⚠️') ? (
                              <AlertCircle className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                            ) : (
                              <Shield className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                            )}
                            <span>{feature.replace('✅ ', '').replace('⚠️ ', '')}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {response.security_notes && response.security_notes.length > 0 && (
                    <div className="bg-orange-500/5 backdrop-blur-xl border border-orange-500/30 rounded-2xl p-8">
                      <h4 className="text-orange-400 text-lg font-semibold mb-4">Security Considerations</h4>
                      <ul className="space-y-3">
                        {response.security_notes.map((note, index) => (
                          <li key={index} className="text-slate-300 text-sm flex items-start space-x-3">
                            <AlertCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                            <span>{note}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default GeneratePolicy;