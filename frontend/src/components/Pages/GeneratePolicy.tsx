import React, { useState } from 'react';
import { Shield, Send, RefreshCw, User, Bot, MessageSquare, Lock, Zap, ArrowRight, CheckCircle } from 'lucide-react';

// Mock types for demo
interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

interface PolicyResponse {
  policy: any;
  explanation: string;
  security_score: number;
  security_notes: string[];
  refinement_suggestions?: string[];
  conversation_history?: ChatMessage[];
}

const GeneratePolicy: React.FC = () => {
  const [description, setDescription] = useState('');
  const [restrictive, setRestrictive] = useState(true);
  const [compliance, setCompliance] = useState('general');
  const [response, setResponse] = useState<PolicyResponse | null>(null);
  const [loading, setLoading] = useState(false);
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
    
    // Simulate API call
    setTimeout(() => {
      const mockResponse: PolicyResponse = {
        policy: {
          Version: "2012-10-17",
          Statement: [{
            Effect: "Allow",
            Action: ["s3:GetObject", "s3:PutObject"],
            Resource: "arn:aws:s3:::my-bucket/*"
          }]
        },
        explanation: "This policy provides least-privilege access to S3 bucket operations.",
        security_score: 95,
        security_notes: ["Policy follows least-privilege principle"],
        refinement_suggestions: [
          "Add IP-based restrictions",
          "Limit to specific S3 prefix",
          "Add MFA requirement"
        ]
      };
      
      setResponse(mockResponse);
      setConversationId('demo-123');
      setIsRefining(true);
      setLoading(false);
    }, 1500);
  };

  const handleNewConversation = () => {
    setResponse(null);
    setConversationId(null);
    setIsRefining(false);
    setFollowUpMessage('');
    setChatHistory([]);
    setDescription('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Hero Section - Only show when not refining */}
      {!isRefining && !response && (
                  <div className="relative overflow-hidden">
          {/* Background Elements */}
          <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-orange-500/10 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-red-500/8 rounded-full blur-3xl"></div>
          
          <div className="relative max-w-7xl mx-auto px-8 pt-20 pb-32">
            {/* Header */}
            <div className="text-center mb-16">
              <div className="inline-flex items-center space-x-2 bg-orange-500/10 border border-orange-500/30 rounded-full px-6 py-2 mb-6">
                <Shield className="w-4 h-4 text-orange-400" />
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
                <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800/50 rounded-3xl p-10 shadow-2xl">
                  {/* Large Text Input */}
                  <div className="mb-8">
                    <label className="block text-white text-lg font-semibold mb-4">
                      What permissions do you need?
                    </label>
                    <textarea
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="Example: I need read-only access to an S3 bucket named company-documents..."
                      className="w-full h-40 px-6 py-5 bg-slate-800/50 border border-slate-700/50 rounded-2xl text-white text-lg placeholder-slate-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 focus:outline-none resize-none transition-all"
                      required
                    />
                  </div>

                  {/* Options Row */}
                  <div className="grid grid-cols-2 gap-6 mb-8">
                    {/* Security Toggle */}
                    <div className="flex items-center space-x-4 bg-slate-800/30 rounded-2xl p-6 border border-slate-700/50">
                      <div className="w-12 h-12 bg-orange-500/10 rounded-xl flex items-center justify-center flex-shrink-0 border border-orange-500/30">
                        <Lock className="w-6 h-6 text-orange-400" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-1">
                          <input
                            id="restrictive"
                            type="checkbox"
                            checked={restrictive}
                            onChange={(e) => setRestrictive(e.target.checked)}
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
                        value={compliance}
                        onChange={(e) => setCompliance(e.target.value)}
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
                    disabled={loading || !description.trim()}
                    className="w-full bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 text-white py-5 px-8 rounded-2xl font-semibold text-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-orange-500/25 hover:shadow-xl hover:shadow-orange-500/40 flex items-center justify-center space-x-3 group"
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
                  <Shield className="w-5 h-5 text-orange-400" />
                  <span>Least Privilege</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Zap className="w-5 h-5 text-orange-400" />
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
              <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800/50 rounded-2xl overflow-hidden">
                <div className="bg-slate-800/50 px-6 py-4 border-b border-slate-700/50">
                  <div className="flex items-center space-x-3">
                    <MessageSquare className="w-5 h-5 text-orange-400" />
                    <h3 className="text-white font-semibold">Conversation</h3>
                    <span className="text-slate-400 text-sm">({chatHistory.length})</span>
                  </div>
                </div>
                
                <div className="p-6 space-y-4 max-h-[500px] overflow-y-auto">
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
                            <p className="text-slate-300 text-sm leading-relaxed">
                              {message.content}
                            </p>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Refine Input */}
              <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800/50 rounded-2xl p-6">
                <label className="block text-white font-medium mb-3">Refine Policy</label>
                <div className="flex space-x-3">
                  <input
                    type="text"
                    value={followUpMessage}
                    onChange={(e) => setFollowUpMessage(e.target.value)}
                    placeholder="Add restrictions, conditions, or modifications..."
                    className="flex-1 px-4 py-3 bg-slate-800/50 border border-slate-700/50 rounded-xl text-white placeholder-slate-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 focus:outline-none"
                    disabled={loading}
                  />
                  <button
                    disabled={loading || !followUpMessage.trim()}
                    className="px-5 py-3 bg-orange-600 hover:bg-orange-700 text-white rounded-xl disabled:opacity-50 transition-all shadow-lg shadow-orange-500/25"
                  >
                    <Send className="w-5 h-5" />
                  </button>
                </div>
              </div>

              {/* Quick Actions */}
              {response?.refinement_suggestions && response.refinement_suggestions.length > 0 && (
                <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800/50 rounded-2xl p-6">
                  <h4 className="text-white font-medium mb-4">Quick Refinements</h4>
                  <div className="space-y-2">
                    {response.refinement_suggestions.map((suggestion, index) => (
                      <button
                        key={index}
                        onClick={() => setFollowUpMessage(suggestion)}
                        className="w-full text-left px-4 py-3 bg-slate-800/50 hover:bg-slate-700/50 text-slate-300 rounded-xl text-sm transition-all border border-slate-700/50 hover:border-orange-500/30"
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
                <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800/50 rounded-2xl h-[600px] flex items-center justify-center">
                  <div className="text-center">
                    <div className="w-16 h-16 border-4 border-slate-700 border-t-blue-500 rounded-full animate-spin mx-auto mb-4"></div>
                    <p className="text-slate-400">Generating secure policy...</p>
                  </div>
                </div>
              ) : response ? (
                <>
                  {/* Security Score */}
                  <div className="bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-xl border border-slate-800/50 rounded-2xl p-8">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-white text-2xl font-bold mb-2">Security Score</h3>
                        <p className="text-slate-400">Based on AWS security best practices</p>
                      </div>
                      <div className="text-center">
                        <div className="text-6xl font-bold text-orange-400">
                          {response.security_score}
                        </div>
                        <div className="text-slate-400 text-sm mt-2">/ 100</div>
                      </div>
                    </div>
                    <div className="w-full bg-slate-800 rounded-full h-4 mt-6">
                      <div
                        className="bg-gradient-to-r from-orange-500 to-red-500 h-4 rounded-full transition-all duration-1000"
                        style={{ width: `${response.security_score}%` }}
                      ></div>
                    </div>
                  </div>

                  {/* Policy Code */}
                  <div>
                    <h3 className="text-white text-xl font-semibold mb-4">IAM Policy</h3>
                    <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
                      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-800/50">
                        <div className="flex items-center space-x-3">
                          <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                          <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                          <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                          <span className="text-sm text-slate-400 ml-2">secure-iam-policy.json</span>
                        </div>
                        <button className="px-4 py-2 bg-orange-600 hover:bg-orange-700 rounded-lg text-sm text-white transition-all">
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

                  {/* Explanation */}
                  <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800/50 rounded-2xl p-8">
                    <h4 className="text-white text-lg font-semibold mb-4">Explanation</h4>
                    <p className="text-slate-300 leading-relaxed">
                      {response.explanation}
                    </p>
                  </div>

                  {/* Security Notes */}
                  {response.security_notes && response.security_notes.length > 0 && (
                    <div className="bg-orange-500/5 backdrop-blur-xl border border-orange-500/30 rounded-2xl p-8">
                      <h4 className="text-orange-400 text-lg font-semibold mb-4">Security Features</h4>
                      <ul className="space-y-3">
                        {response.security_notes.map((note, index) => (
                          <li key={index} className="text-slate-300 text-sm flex items-start space-x-3">
                            <CheckCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
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