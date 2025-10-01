import React, { useState } from 'react';
import { Shield, Send, RefreshCw, User, Bot, MessageSquare, Sparkles, Lock, Zap, ArrowRight } from 'lucide-react';
import LoadingSpinner from '../UI/LoadingSpinner';
import SecurityScore from '../UI/SecurityScore';
import CodeBlock from '../UI/CodeBlock';
import { GeneratePolicyRequest, GeneratePolicyResponse, ChatMessage } from '../../types';
import { generatePolicy, sendFollowUp } from '../../services/api';

const GeneratePolicy: React.FC = () => {
  const [request, setRequest] = useState<GeneratePolicyRequest>({
    description: '',
    service: '',
    restrictive: true,
    compliance: 'general'
  });
  const [response, setResponse] = useState<GeneratePolicyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [followUpMessage, setFollowUpMessage] = useState('');
  const [isRefining, setIsRefining] = useState(false);
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([]);

  const complianceFrameworks = [
    { value: 'general', label: 'General Security' },
    { value: 'pci-dss', label: 'PCI DSS' },
    { value: 'hipaa', label: 'HIPAA' },
    { value: 'sox', label: 'SOX' },
    { value: 'gdpr', label: 'GDPR' },
    { value: 'cis', label: 'CIS Benchmarks' }
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResponse(null);
    setConversationId(null);
    setIsRefining(false);
    setChatHistory([]);

    try {
      const result = await generatePolicy({
        description: request.description,
        service: 'auto',
        restrictive: request.restrictive,
        compliance: request.compliance
      });

      setResponse(result);
      if (result.conversation_id) {
        setConversationId(result.conversation_id);
        setIsRefining(true);
        
        if (result.conversation_history) {
          setChatHistory(result.conversation_history);
        }
      }

    } catch (err) {
      console.error("An error occurred while generating the policy:", err);
      setError("Failed to generate policy. Please check the console for details.");

    } finally {
      setLoading(false);
    }
  };

  const handleFollowUp = async () => {
    if (!followUpMessage.trim() || !conversationId) return;

    setLoading(true);
    setError(null);

    try {
      const result = await sendFollowUp(followUpMessage, conversationId, 'auto');
      setResponse(result);
      setFollowUpMessage('');
      
      if (result.conversation_history) {
        setChatHistory(result.conversation_history);
      }

    } catch (err) {
      console.error("An error occurred while sending follow-up:", err);
      setError("Failed to process follow-up message.");

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
    setRequest({
      description: '',
      service: '',
      restrictive: true,
      compliance: 'general'
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Hero Section - Only show when not refining */}
      {!isRefining && !response && (
        <div className="relative overflow-hidden">
          {/* Background Gradient Orbs */}
          <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-orange-500/10 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-blue-500/10 rounded-full blur-3xl"></div>
          
          <div className="relative max-w-7xl mx-auto px-8 pt-20 pb-32">
            {/* Header */}
            <div className="text-center mb-16">
              <div className="inline-flex items-center space-x-2 bg-orange-500/10 border border-orange-500/20 rounded-full px-6 py-2 mb-6">
                <Sparkles className="w-4 h-4 text-orange-400" />
                <span className="text-orange-400 text-sm font-medium">AI-Powered Security</span>
              </div>
              
              <h1 className="text-6xl font-bold text-white mb-6 leading-tight">
                Generate Secure<br />
                <span className="bg-gradient-to-r from-orange-400 to-red-500 bg-clip-text text-transparent">
                  IAM Policies
                </span>
              </h1>
              
              <p className="text-xl text-slate-400 max-w-2xl mx-auto leading-relaxed">
                Describe your permission needs in plain English. Our AI automatically generates 
                secure, least-privilege IAM policies following AWS best practices.
              </p>
            </div>

            {/* Main Input Card */}
            <div className="max-w-4xl mx-auto">
              <form onSubmit={handleSubmit}>
                <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-3xl p-10 shadow-2xl">
                  {/* Large Text Input */}
                  <div className="mb-8">
                    <label className="block text-white text-lg font-semibold mb-4">
                      What permissions do you need?
                    </label>
                    <textarea
                      value={request.description}
                      onChange={(e) => setRequest({ ...request, description: e.target.value })}
                      placeholder="Example: I need read-only access to an S3 bucket named company-documents..."
                      className="w-full h-40 px-6 py-5 bg-slate-800/50 border border-slate-600/50 rounded-2xl text-white text-lg placeholder-slate-500 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none resize-none transition-all"
                      required
                    />
                  </div>

                  {/* Options Row */}
                  <div className="grid grid-cols-2 gap-6 mb-8">
                    {/* Security Toggle */}
                    <div className="flex items-center space-x-4 bg-slate-800/30 rounded-2xl p-6 border border-slate-700/50">
                      <div className="w-12 h-12 bg-green-500/10 rounded-xl flex items-center justify-center flex-shrink-0">
                        <Lock className="w-6 h-6 text-green-400" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-1">
                          <input
                            id="restrictive"
                            type="checkbox"
                            checked={request.restrictive}
                            onChange={(e) => setRequest({ ...request, restrictive: e.target.checked })}
                            className="w-5 h-5 bg-slate-700 border-slate-600 rounded text-orange-500 focus:ring-orange-500 cursor-pointer"
                          />
                          <label htmlFor="restrictive" className="text-white font-medium cursor-pointer">
                            Maximum Security
                          </label>
                        </div>
                        <p className="text-slate-400 text-sm">Least-privilege mode</p>
                      </div>
                    </div>

                    {/* Compliance Dropdown */}
                    <div className="bg-slate-800/30 rounded-2xl p-6 border border-slate-700/50">
                      <label className="block text-white font-medium mb-3">Compliance</label>
                      <select
                        value={request.compliance}
                        onChange={(e) => setRequest({ ...request, compliance: e.target.value })}
                        className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-xl text-white focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none cursor-pointer"
                      >
                        {complianceFrameworks.map(framework => (
                          <option key={framework.value} value={framework.value}>
                            {framework.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {/* Submit Button */}
                  <button
                    type="submit"
                    disabled={loading || !request.description.trim()}
                    className="w-full bg-gradient-to-r from-orange-500 to-red-600 text-white py-5 px-8 rounded-2xl font-semibold text-lg hover:from-orange-600 hover:to-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-orange-500/25 hover:shadow-xl hover:shadow-orange-500/40 flex items-center justify-center space-x-3 group"
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

              {/* Trust Indicators */}
              <div className="flex items-center justify-center space-x-8 mt-12 text-slate-400">
                <div className="flex items-center space-x-2">
                  <Shield className="w-5 h-5 text-green-400" />
                  <span>Least Privilege</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Zap className="w-5 h-5 text-blue-400" />
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

      {/* Results View - Clean Layout */}
      {(isRefining || response) && (
        <div className="max-w-[1600px] mx-auto px-8 py-12">
          {/* Top Bar */}
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
            {/* Left Sidebar - Chat (2 columns) */}
            <div className="lg:col-span-2 space-y-6">
              {/* Chat History */}
              <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl overflow-hidden">
                <div className="bg-slate-800/50 px-6 py-4 border-b border-slate-700/50">
                  <div className="flex items-center space-x-3">
                    <MessageSquare className="w-5 h-5 text-orange-400" />
                    <h3 className="text-white font-semibold">Conversation</h3>
                    <span className="text-slate-400 text-sm">({chatHistory.length})</span>
                  </div>
                </div>
                
                <div className="p-6 space-y-4 max-h-[500px] overflow-y-auto custom-scrollbar">
                  {chatHistory.map((message, index) => (
                    <div key={message.timestamp || index} className="flex items-start space-x-3">
                      {message.role === 'user' ? (
                        <div className="w-10 h-10 bg-blue-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                          <User className="w-5 h-5 text-blue-400" />
                        </div>
                      ) : (
                        <div className="w-10 h-10 bg-orange-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                          <Bot className="w-5 h-5 text-orange-400" />
                        </div>
                      )}
                      
                      <div className="flex-1">
                        <div className={`rounded-xl p-4 ${
                          message.role === 'user' 
                            ? 'bg-blue-500/10 border border-blue-500/20' 
                            : 'bg-slate-800/50 border border-slate-700/50'
                        }`}>
                          <p className="text-slate-300 text-sm leading-relaxed">
                            {message.content.length > 200 && message.role === 'assistant'
                              ? `${message.content.substring(0, 200)}...`
                              : message.content
                            }
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Refine Input */}
              <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6">
                <label className="block text-white font-medium mb-3">Refine Policy</label>
                <div className="flex space-x-3">
                  <input
                    type="text"
                    value={followUpMessage}
                    onChange={(e) => setFollowUpMessage(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleFollowUp()}
                    placeholder="Add restrictions, conditions, or modifications..."
                    className="flex-1 px-4 py-3 bg-slate-800/50 border border-slate-600/50 rounded-xl text-white placeholder-slate-500 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none"
                    disabled={loading}
                  />
                  <button
                    onClick={handleFollowUp}
                    disabled={loading || !followUpMessage.trim()}
                    className="px-5 py-3 bg-orange-500 hover:bg-orange-600 text-white rounded-xl disabled:opacity-50 transition-all"
                  >
                    <Send className="w-5 h-5" />
                  </button>
                </div>
              </div>

              {/* Quick Actions */}
              {response?.refinement_suggestions && response.refinement_suggestions.length > 0 && (
                <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6">
                  <h4 className="text-white font-medium mb-4">Quick Refinements</h4>
                  <div className="space-y-2">
                    {response.refinement_suggestions.map((suggestion, index) => (
                      <button
                        key={index}
                        onClick={() => setFollowUpMessage(suggestion)}
                        className="w-full text-left px-4 py-3 bg-slate-800/50 hover:bg-slate-700/50 text-slate-300 rounded-xl text-sm transition-all border border-slate-700/50"
                      >
                        {suggestion}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Right Main Area - Policy (3 columns) */}
            <div className="lg:col-span-3 space-y-6">
              {loading && !response ? (
                <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl h-[600px] flex items-center justify-center">
                  <LoadingSpinner message="Generating secure policy..." />
                </div>
              ) : response ? (
                <>
                  {/* Security Score */}
                  <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-8">
                    <SecurityScore score={response.security_score} className="mb-6" />
                  </div>

                  {/* Policy Code */}
                  <div>
                    <h3 className="text-white text-xl font-semibold mb-4">IAM Policy</h3>
                    <CodeBlock 
                      code={JSON.stringify(response.policy, null, 2)}
                      filename="secure-iam-policy.json"
                    />
                  </div>

                  {/* Explanation */}
                  <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-8">
                    <h4 className="text-white text-lg font-semibold mb-4">Explanation</h4>
                    <p className="text-slate-300 leading-relaxed whitespace-pre-line">
                      {response.explanation}
                    </p>
                  </div>
                </>
              ) : null}
            </div>
          </div>
        </div>
      )}

      {/* Error Toast */}
      {error && (
        <div className="fixed bottom-8 right-8 bg-red-500/10 backdrop-blur-xl border border-red-500/30 rounded-2xl p-6 max-w-md shadow-2xl animate-slideIn">
          <p className="text-red-400 font-medium">{error}</p>
        </div>
      )}
    </div>
  );
};

export default GeneratePolicy;