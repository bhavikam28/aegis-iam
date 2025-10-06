import React, { useState, useEffect } from 'react';
import { Shield, Send, RefreshCw, User, Bot, MessageSquare, Lock, Zap, ArrowRight, CheckCircle, ChevronDown, ChevronUp, AlertCircle, Download, Copy, Sparkles } from 'lucide-react';
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

  // Extract JSON policy from agent response text
  const extractPolicyFromText = (text: string): any => {
    try {
      const jsonMatch = text.match(/\{[\s\S]*"Version"[\s\S]*"Statement"[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
    } catch (e) {
      console.error("Could not extract policy from text", e);
    }
    return null;
  };

  // Extract sections from agent response
  const parseAgentResponse = (text: string) => {
    const sections = {
      explanation: '',
      securityScore: 0,
      securityNotes: [] as string[],
      securityFeatures: [] as string[],
      scoreExplanation: '',
      refinementSuggestions: [] as string[]
    };

    // Extract Security Score
    const scoreMatch = text.match(/Security Score:\s*(\d+)/i);
    if (scoreMatch) {
      sections.securityScore = parseInt(scoreMatch[1]);
    }

    // Extract Policy Explanation (before Security Score)
    const explanationMatch = text.match(/Policy Explanation:([\s\S]*?)(?:Security Score:|Security Notes:|$)/i);
    if (explanationMatch) {
      sections.explanation = cleanMarkdown(explanationMatch[1]);
    }

    // Extract Security Notes
    const notesMatch = text.match(/Security Notes:([\s\S]*?)(?:Security Features:|Score Explanation:|$)/i);
    if (notesMatch) {
      const notes = notesMatch[1].split('\n').filter(line => line.trim().startsWith('-'));
      sections.securityNotes = notes.map(note => cleanMarkdown(note.replace(/^-\s*/, '')));
    }

    // Extract Security Features
    const featuresMatch = text.match(/Security Features:([\s\S]*?)(?:Score Explanation:|Refinement Suggestions:|$)/i);
    if (featuresMatch) {
      const features = featuresMatch[1].split('\n').filter(line => line.trim().startsWith('-'));
      sections.securityFeatures = features.map(feature => cleanMarkdown(feature.replace(/^-\s*/, '')));
    }

    // Extract Score Explanation
    const scoreExpMatch = text.match(/Score Explanation:([\s\S]*?)(?:Refinement Suggestions:|$)/i);
    if (scoreExpMatch) {
      sections.scoreExplanation = cleanMarkdown(scoreExpMatch[1]);
    }

    // Extract Refinement Suggestions
    const refineMatch = text.match(/Refinement Suggestions:([\s\S]*?)$/i);
    if (refineMatch) {
      const suggestions = refineMatch[1].split('\n').filter(line => line.trim().match(/^\d+\./));
      sections.refinementSuggestions = suggestions.map(sug => cleanMarkdown(sug.replace(/^\d+\.\s*/, '')));
    }

    return sections;
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

  const handleSuggestionClick = (suggestion: string) => {
    setFollowUpMessage(cleanMarkdown(suggestion));
  };

  // Check if we have a policy
  const hasPolicy = response?.policy !== null && response?.policy !== undefined;
  
  // Parse agent response if it's in text format
  let parsedResponse = null;
  let extractedPolicy = null;
  
  if (response && hasPolicy) {
    // If explanation contains structured text, parse it
    if (typeof response.explanation === 'string' && response.explanation.includes('Policy Explanation:')) {
      parsedResponse = parseAgentResponse(response.explanation);
      extractedPolicy = extractPolicyFromText(response.explanation) || response.policy;
    }
  }

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
                    {loading ? (
                      <>
                        <div className="w-5 h-5 sm:w-6 sm:h-6 border-3 border-white border-t-transparent rounded-full animate-spin"></div>
                        <span>Analyzing...</span>
                      </>
                    ) : (
                      <>
                        <Shield className="w-5 h-5 sm:w-6 sm:h-6" />
                        <span>Generate Secure Policy</span>
                        <ArrowRight className="w-4 h-4 sm:w-5 sm:h-5 group-hover:translate-x-1 transition-transform" />
                      </>
                    )}
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

      {/* Conversation/Policy View */}
      {!showInitialForm && response && (
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-8 sm:mb-12 gap-4">
            <div>
              <h2 className="text-2xl sm:text-3xl font-bold text-white mb-2">
                {hasPolicy ? 'Policy Generated' : 'Policy Generation'}
              </h2>
              <p className="text-slate-400 text-sm sm:text-base">
                {hasPolicy ? 'Review and refine your secure IAM policy' : 'Conversing with Aegis AI Agent'}
              </p>
            </div>
            <button
              onClick={handleNewConversation}
              className="flex items-center justify-center space-x-2 px-4 sm:px-6 py-2 sm:py-3 bg-slate-800 hover:bg-slate-700 text-white rounded-lg sm:rounded-xl transition-all border border-slate-700 text-sm sm:text-base"
            >
              <RefreshCw className="w-4 h-4" />
              <span>New Policy</span>
            </button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 sm:gap-8">
            {/* Left Panel - Conversation & Controls */}
            <div className="lg:col-span-2 space-y-4 sm:space-y-6">
              {/* Conversation Box */}
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-xl sm:rounded-2xl overflow-hidden">
                <div className="bg-slate-800/50 px-4 sm:px-6 py-3 sm:py-4 border-b border-purple-500/20">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2 sm:space-x-3">
                      <MessageSquare className="w-4 h-4 sm:w-5 sm:h-5 text-purple-400" />
                      <h3 className="text-white font-semibold text-sm sm:text-base">Conversation</h3>
                      <span className="text-slate-400 text-xs sm:text-sm">({chatHistory.length})</span>
                    </div>
                    <button
                      onClick={() => setIsChatExpanded(!isChatExpanded)}
                      className="flex items-center space-x-1 sm:space-x-2 px-2 sm:px-3 py-1 sm:py-2 bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/30 rounded-lg text-xs sm:text-sm text-purple-300 hover:text-purple-200 transition-all"
                    >
                      <span className="font-medium hidden sm:inline">{isChatExpanded ? 'Collapse' : 'Expand'}</span>
                      {isChatExpanded ? (
                        <ChevronUp className="w-3 h-3 sm:w-4 sm:h-4" />
                      ) : (
                        <ChevronDown className="w-3 h-3 sm:w-4 sm:h-4" />
                      )}
                    </button>
                  </div>
                </div>
                
                <div className={`p-4 sm:p-6 space-y-3 sm:space-y-4 overflow-y-auto transition-all duration-300 ${
                  isChatExpanded ? 'max-h-[600px] sm:max-h-[800px]' : 'max-h-[300px] sm:max-h-[400px]'
                }`}>
                  {chatHistory.map((message, index) => (
                    <div key={index} className="flex items-start space-x-2 sm:space-x-3">
                      {message.role === 'user' ? (
                        <div className="w-8 h-8 sm:w-10 sm:h-10 bg-orange-500/20 rounded-lg sm:rounded-xl flex items-center justify-center flex-shrink-0 border border-orange-500/30">
                          <User className="w-4 h-4 sm:w-5 sm:h-5 text-orange-400" />
                        </div>
                      ) : (
                        <div className="w-8 h-8 sm:w-10 sm:h-10 bg-slate-700/50 rounded-lg sm:rounded-xl flex items-center justify-center flex-shrink-0 border border-slate-600/50">
                          <Bot className="w-4 h-4 sm:w-5 sm:h-5 text-slate-400" />
                        </div>
                      )}
                      
                      <div className="flex-1 min-w-0">
                        <div className={`rounded-lg sm:rounded-xl p-3 sm:p-4 ${
                          message.role === 'user' 
                            ? 'bg-orange-500/10 border border-orange-500/30' 
                            : 'bg-slate-800/50 border border-slate-700/50'
                        }`}>
                          <p className="text-slate-300 text-xs sm:text-sm leading-relaxed whitespace-pre-wrap break-words">
                            {cleanMarkdown(message.content)}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                  
                  {loading && (
                    <div className="flex items-start space-x-2 sm:space-x-3">
                      <div className="w-8 h-8 sm:w-10 sm:h-10 bg-slate-700/50 rounded-lg sm:rounded-xl flex items-center justify-center flex-shrink-0 border border-slate-600/50">
                        <Bot className="w-4 h-4 sm:w-5 sm:h-5 text-slate-400" />
                      </div>
                      <div className="flex-1">
                        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg sm:rounded-xl p-3 sm:p-4">
                          <div className="flex items-center space-x-2">
                            <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
                            <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
                            <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Continue Conversation Box */}
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-xl sm:rounded-2xl p-4 sm:p-6">
                <label className="block text-white font-medium mb-2 sm:mb-3 text-sm sm:text-base">
                  {hasPolicy ? 'Refine Policy' : 'Continue Conversation'}
                </label>
                <form onSubmit={handleFollowUp} className="flex space-x-2 sm:space-x-3">
                  <input
                    type="text"
                    value={followUpMessage}
                    onChange={(e) => setFollowUpMessage(e.target.value)}
                    placeholder={hasPolicy ? "Add restrictions, conditions, or modifications..." : "Provide more details..."}
                    className="flex-1 px-3 sm:px-4 py-2 sm:py-3 bg-slate-800/50 border border-slate-700/50 rounded-lg sm:rounded-xl text-white text-sm sm:text-base placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none"
                    disabled={loading}
                  />
                  <button
                    type="submit"
                    disabled={loading || !followUpMessage.trim()}
                    className="px-4 sm:px-5 py-2 sm:py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg sm:rounded-xl disabled:opacity-50 transition-all shadow-lg shadow-purple-500/25 flex-shrink-0"
                  >
                    <Send className="w-4 h-4 sm:w-5 sm:h-5" />
                  </button>
                </form>
              </div>

              {/* Suggestions Box */}
              {((parsedResponse?.refinementSuggestions && parsedResponse.refinementSuggestions.length > 0) || 
                (response?.refinement_suggestions && response.refinement_suggestions.length > 0)) && (
                <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-xl sm:rounded-2xl p-4 sm:p-6">
                  <h4 className="text-white font-medium mb-3 sm:mb-4 text-sm sm:text-base flex items-center space-x-2">
                    <Sparkles className="w-4 h-4 text-purple-400" />
                    <span>Suggestions</span>
                  </h4>
                  <div className="space-y-2">
                    {(parsedResponse?.refinementSuggestions || response?.refinement_suggestions || []).map((suggestion, index) => (
                      <button
                        key={index}
                        onClick={() => handleSuggestionClick(suggestion)}
                        className="w-full text-left px-3 sm:px-4 py-2 sm:py-3 bg-slate-800/50 hover:bg-slate-700/50 text-slate-300 rounded-lg sm:rounded-xl text-xs sm:text-sm transition-all border border-slate-700/50 hover:border-purple-500/30 flex items-start space-x-2"
                      >
                        <Shield className="w-3 h-3 sm:w-4 sm:h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                        <span className="break-words">{cleanMarkdown(suggestion)}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Right Panel - Policy Display */}
            <div className="lg:col-span-3 space-y-4 sm:space-y-6">
              {hasPolicy ? (
                <>
                  {/* Security Score Box */}
                  <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-purple-500/20 rounded-xl sm:rounded-2xl p-6 sm:p-8">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 sm:mb-6 gap-4">
                      <div>
                        <h3 className="text-white text-xl sm:text-2xl font-bold mb-2">Security Score</h3>
                        <p className="text-slate-400 text-xs sm:text-sm">Based on AWS security best practices</p>
                      </div>
                      <div className="text-center">
                        <div className={`text-5xl sm:text-6xl font-bold ${
                          (parsedResponse?.securityScore || response.security_score) >= 90 ? 'text-green-400' :
                          (parsedResponse?.securityScore || response.security_score) >= 80 ? 'text-yellow-400' :
                          (parsedResponse?.securityScore || response.security_score) >= 70 ? 'text-orange-400' :
                          'text-red-400'
                        }`}>
                          {parsedResponse?.securityScore || response.security_score}
                        </div>
                        <div className="text-slate-400 text-xs sm:text-sm mt-2">/ 100</div>
                      </div>
                    </div>
                    
                    <div className="w-full bg-slate-800 rounded-full h-3 sm:h-4 mb-4 sm:mb-6">
                      <div
                        className={`h-3 sm:h-4 rounded-full transition-all duration-1000 ${
                          (parsedResponse?.securityScore || response.security_score) >= 90 ? 'bg-gradient-to-r from-green-500 to-green-400' :
                          (parsedResponse?.securityScore || response.security_score) >= 80 ? 'bg-gradient-to-r from-yellow-500 to-yellow-400' :
                          (parsedResponse?.securityScore || response.security_score) >= 70 ? 'bg-gradient-to-r from-orange-500 to-pink-500' :
                          'bg-gradient-to-r from-red-500 to-pink-500'
                        }`}
                        style={{ width: `${parsedResponse?.securityScore || response.security_score}%` }}
                      ></div>
                    </div>

                    {(parsedResponse?.scoreExplanation || response.score_explanation) && (
                      <div className="mt-4 sm:mt-6 pt-4 sm:pt-6 border-t border-slate-700">
                        <div className="text-slate-300 text-xs sm:text-sm leading-relaxed">
                          {parsedResponse?.scoreExplanation || response.score_explanation}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* IAM Policy Box */}
                  <div>
                    <h3 className="text-white text-lg sm:text-xl font-semibold mb-3 sm:mb-4">IAM Policy</h3>
                    <div className="bg-slate-900 border border-purple-500/20 rounded-xl sm:rounded-2xl overflow-hidden">
                      <div className="flex items-center justify-between px-4 sm:px-6 py-3 sm:py-4 border-b border-purple-500/20 bg-slate-800/50">
                        <div className="flex items-center space-x-2 sm:space-x-3">
                          <div className="hidden sm:flex items-center space-x-2">
                            <div className="w-2 h-2 sm:w-3 sm:h-3 bg-red-500 rounded-full"></div>
                            <div className="w-2 h-2 sm:w-3 sm:h-3 bg-yellow-500 rounded-full"></div>
                            <div className="w-2 h-2 sm:w-3 sm:h-3 bg-green-500 rounded-full"></div>
                          </div>
                          <span className="text-xs sm:text-sm text-slate-400 truncate">secure-iam-policy.json</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <button 
                            onClick={handleCopyPolicy}
                            className="px-3 sm:px-4 py-1.5 sm:py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-xs sm:text-sm text-white transition-all flex items-center space-x-1.5 sm:space-x-2"
                          >
                            {copied ? (
                              <>
                                <CheckCircle className="w-3 h-3 sm:w-4 sm:h-4 text-green-400" />
                                <span className="hidden sm:inline">Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3 sm:w-4 sm:h-4" />
                                <span className="hidden sm:inline">Copy</span>
                              </>
                            )}
                          </button>
                          <button 
                            onClick={handleDownloadPolicy}
                            className="px-3 sm:px-4 py-1.5 sm:py-2 bg-purple-600 hover:bg-purple-700 rounded-lg text-xs sm:text-sm text-white transition-all flex items-center space-x-1.5 sm:space-x-2"
                          >
                            <Download className="w-3 h-3 sm:w-4 sm:h-4" />
                            <span className="hidden sm:inline">Download</span>
                          </button>
                        </div>
                      </div>
                      <div className="p-4 sm:p-6 overflow-x-auto">
                        <pre className="text-xs sm:text-sm text-slate-300 font-mono leading-relaxed">
                          {JSON.stringify(extractedPolicy || response.policy, null, 2)}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* Explanation Box */}
                  <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-xl sm:rounded-2xl p-6 sm:p-8">
                    <h4 className="text-white text-base sm:text-lg font-semibold mb-3 sm:mb-4 flex items-center space-x-2">
                      <Shield className="w-5 h-5 text-purple-400" />
                      <span>Policy Explanation</span>
                    </h4>
                    <div className="text-slate-300 text-sm sm:text-base leading-relaxed whitespace-pre-wrap">
                      {parsedResponse?.explanation || cleanMarkdown(response.explanation)}
                    </div>
                  </div>

                  {/* Security Features Box */}
                  {((parsedResponse?.securityFeatures && parsedResponse.securityFeatures.length > 0) || 
                    (response.security_features && response.security_features.length > 0)) && (
                    <div className="bg-purple-500/5 backdrop-blur-xl border border-purple-500/30 rounded-xl sm:rounded-2xl p-6 sm:p-8">
                      <h4 className="text-purple-400 text-base sm:text-lg font-semibold mb-3 sm:mb-4 flex items-center space-x-2">
                        <CheckCircle className="w-5 h-5" />
                        <span>Security Features</span>
                      </h4>
                      <ul className="space-y-2 sm:space-y-3">
                        {(parsedResponse?.securityFeatures || response.security_features || []).map((feature, index) => (
                          <li key={index} className="text-slate-300 text-xs sm:text-sm flex items-start space-x-2 sm:space-x-3">
                            <CheckCircle className="w-3 h-3 sm:w-4 sm:h-4 text-green-400 mt-0.5 flex-shrink-0" />
                            <span className="break-words">{cleanMarkdown(feature)}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Security Notes Box */}
                  {((parsedResponse?.securityNotes && parsedResponse.securityNotes.length > 0) || 
                    (response.security_notes && response.security_notes.length > 0)) && (
                    <div className="bg-orange-500/5 backdrop-blur-xl border border-orange-500/30 rounded-xl sm:rounded-2xl p-6 sm:p-8">
                      <h4 className="text-orange-400 text-base sm:text-lg font-semibold mb-3 sm:mb-4 flex items-center space-x-2">
                        <AlertCircle className="w-5 h-5" />
                        <span>Security Considerations</span>
                      </h4>
                      <ul className="space-y-2 sm:space-y-3">
                        {(parsedResponse?.securityNotes || response.security_notes || []).map((note, index) => (
                          <li key={index} className="text-slate-300 text-xs sm:text-sm flex items-start space-x-2 sm:space-x-3">
                            <AlertCircle className="w-3 h-3 sm:w-4 sm:h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                            <span className="break-words">{cleanMarkdown(note)}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              ) : (
                /* Agent is asking for more information */
                <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-xl sm:rounded-2xl p-6 sm:p-8">
                  <div className="flex items-start space-x-3 sm:space-x-4 mb-6">
                    <div className="w-12 h-12 sm:w-16 sm:h-16 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-xl flex items-center justify-center flex-shrink-0 border border-purple-500/30">
                      <Bot className="w-6 h-6 sm:w-8 sm:h-8 text-purple-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-white text-xl sm:text-2xl font-bold mb-2">Aegis AI Assistant</h3>
                      <p className="text-slate-400 text-sm sm:text-base">Your AI security expert is working with you</p>
                    </div>
                  </div>
                  
                  <div className="bg-slate-800/50 rounded-xl p-6 sm:p-8 mb-6 border border-slate-700/50">
                    <div className="text-slate-300 text-sm sm:text-base leading-relaxed whitespace-pre-wrap">
                      {cleanMarkdown(response.explanation)}
                    </div>
                  </div>

                  {/* Quick Tips Box */}
                  <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-4 sm:p-6">
                    <div className="flex items-start space-x-3 mb-3">
                      <Shield className="w-5 h-5 text-purple-400 mt-0.5 flex-shrink-0" />
                      <div>
                        <h4 className="text-purple-300 font-semibold mb-2 text-sm sm:text-base">Quick Tips</h4>
                        <ul className="space-y-2 text-slate-400 text-xs sm:text-sm">
                          <li>• Provide specific AWS Account IDs and regions when possible</li>
                          <li>• If you don't have details yet, I can use placeholders and note what to update</li>
                          <li>• You can always refine the policy after it's generated</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default GeneratePolicy;