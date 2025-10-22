import React, { useState, useEffect, useRef } from 'react';
import { Shield, Send, RefreshCw, User, Bot, MessageSquare, Lock, ArrowRight, CheckCircle, AlertCircle, Download, Copy, Sparkles, Info, X, Minimize2, ChevronUp, ChevronDown, Maximize2 } from 'lucide-react';
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
  const [copied, setCopied] = useState(false);
  const [copiedTrust, setCopiedTrust] = useState(false);
  const [showInitialForm, setShowInitialForm] = useState(true);
  const [showScoreBreakdown, setShowScoreBreakdown] = useState(false);
  const [isChatbotOpen, setIsChatbotOpen] = useState(false);
  const [isChatbotExpanded, setIsChatbotExpanded] = useState(false);
  const [isRefining, setIsRefining] = useState(false); // Track if we're refining via chatbot
  const [renderError, setRenderError] = useState<Error | null>(null);
  
  // Collapsible sections state
  const [showPermissionsPolicy, setShowPermissionsPolicy] = useState(true);
  const [showTrustPolicy, setShowTrustPolicy] = useState(true);
  const [showExplanation, setShowExplanation] = useState(true);
  const [showRefinementSuggestions, setShowRefinementSuggestions] = useState(true);
  const [showPermissionsSuggestions, setShowPermissionsSuggestions] = useState(true);
  const [showTrustSuggestions, setShowTrustSuggestions] = useState(true);
  
  const chatEndRef = useRef<HTMLDivElement>(null);

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

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatHistory]);

  // Add initial greeting when chatbot opens
  useEffect(() => {
    if (isChatbotOpen && response && chatHistory.length === 0) {
      const permissionsScore = response?.permissions_score || 0;
      const trustScore = response?.trust_score || 0;
      
      const initialGreeting: ChatMessage = {
        role: 'assistant',
        content: `👋 Hello! I'm Aegis AI Agent.

I've generated your IAM policies:
- **Permissions Policy** (Score: ${permissionsScore}/100)
- **Trust Policy** (Score: ${trustScore}/100)

How can I help you further? I can:
✨ Explain any permission statement
🔒 Add security conditions (MFA, IP restrictions)
📝 Refine policies based on your needs
🎯 Answer questions about AWS IAM

What would you like to do?`,
        timestamp: new Date().toISOString()
      };
      
      setChatHistory([initialGreeting]);
    }
  }, [isChatbotOpen, response]);

  const handleCopyPolicy = async () => {
    if (response?.policy) {
      await navigator.clipboard.writeText(JSON.stringify(response.policy, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleCopyTrustPolicy = async () => {
    if (response?.trust_policy) {
      await navigator.clipboard.writeText(JSON.stringify(response.trust_policy, null, 2));
      setCopiedTrust(true);
      setTimeout(() => setCopiedTrust(false), 2000);
    }
  };

  const handleCopyJSON = async (jsonString: string) => {
    await navigator.clipboard.writeText(jsonString);
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

  const stripMarkdown = (text: string): string => {
    if (!text) return '';
    return text
      .replace(/\*\*(.+?)\*\*/g, '$1')
      .replace(/\*(.+?)\*/g, '$1')
      .replace(/_(.+?)_/g, '$1')
      .replace(/`(.+?)`/g, '$1')
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

  const handleFollowUp = async (e: React.FormEvent, isFromChatbot: boolean = false) => {
    e.preventDefault();
    if (!followUpMessage.trim() || !conversationId) return;

    setLoading(true);
    if (isFromChatbot) {
      setIsRefining(true); // Only mark as refining if from chatbot
    }
    setError(null);
    
    // Add user message to chat
    const userMessage: ChatMessage = {
      role: 'user',
      content: followUpMessage,
      timestamp: new Date().toISOString()
    };
    setChatHistory(prev => [...prev, userMessage]);
    
    const currentMessage = followUpMessage;
    setFollowUpMessage('');
    
    try {
      const result = await sendFollowUp(currentMessage, conversationId);
      
      // Create response content
      let responseContent = result.final_answer || 'Policy updated successfully.';
      
      // Check if user is asking for policies in JSON format
      const msgLower = currentMessage.toLowerCase();
      const isAskingForPolicies = msgLower.includes('policy') || 
                                   msgLower.includes('policies') ||
                                   msgLower.includes('json') ||
                                   msgLower.includes('show') ||
                                   msgLower.includes('give me') ||
                                   msgLower.includes('get') ||
                                   msgLower.includes('both') ||
                                   msgLower.includes('format');
      
      // If user is asking for policies, return BOTH in JSON format from current response state
      if (isAskingForPolicies && response) {
        const policiesResponse: any = {};
        
        // Always include BOTH policies from the current response state
        if (response.policy) {
          policiesResponse.permissions_policy = response.policy;
        }
        if (response.trust_policy) {
          policiesResponse.trust_policy = response.trust_policy;
        }
        
        // Only return JSON if we have at least one policy
        if (Object.keys(policiesResponse).length > 0) {
          responseContent = JSON.stringify(policiesResponse, null, 2);
        }
      }
      
      // Add assistant response to chat
      const assistantMessage: ChatMessage = {
        role: 'assistant',
        content: responseContent,
        timestamp: new Date().toISOString()
      };
      setChatHistory(prev => [...prev, assistantMessage]);
      
      // Update response if new policy generated
      if (result.policy) {
        setResponse(result);
      }
    } catch (err) {
      console.error("Error sending follow-up:", err);
      setError(err instanceof Error ? err.message : 'Failed to refine policy');
    } finally {
      setLoading(false);
      setIsRefining(false); // Done refining
    }
  };

  const handleNewConversation = () => {
    // Clear all state
    setResponse(null);
    setConversationId(null);
    setFollowUpMessage('');
    setChatHistory([]);
    setShowInitialForm(true);
    setError(null);
    setIsChatbotOpen(false);
    setIsRefining(false);
    
    // Clear localStorage for fresh start
    localStorage.removeItem('aegis_response');
    localStorage.removeItem('aegis_conversation_id');
    localStorage.removeItem('aegis_chat_history');
    localStorage.removeItem('aegis_show_initial_form');
  };

  const hasPolicy = response?.policy !== null && 
                    response?.policy !== undefined && 
                    typeof response?.policy === 'object' &&
                    Object.keys(response?.policy || {}).length > 0 &&
                    response?.is_question !== true;

  const permissionsScore = response?.permissions_score || 0;
  const trustScore = response?.trust_score || 0;

  const getServiceIcon = (title: string) => {
    return '🔒';
  };

  const parseExplanation = (explanation: string) => {
    try {
      if (!explanation || explanation.trim() === '') {
        console.log('parseExplanation: Empty explanation');
        return [];
      }
      
      console.log('parseExplanation: Input length:', explanation.length);
      console.log('parseExplanation: First 200 chars:', explanation.substring(0, 200));
      
      const sections = explanation
        .split(/(?=^\d+\.\s+)/m)
        .filter(section => section.trim());
      
      console.log('parseExplanation: Found', sections.length, 'sections');
      
      const parsed = sections.map(section => {
        const match = section.match(/^(\d+)\.\s+(.+?)(?:\n|$)([\s\S]*)/);
        if (!match) {
          console.log('parseExplanation: Failed to match section:', section.substring(0, 100));
          return null;
        }
        
        const [, num, title, content] = match;
        const details: { [key: string]: string } = {};
        const lines = content.split('\n').map(line => line.trim()).filter(line => line.length > 0);
        
        lines.forEach(line => {
          const colonIndex = line.indexOf(':');
          if (colonIndex > 0 && colonIndex < 50) {
            let key = line.substring(0, colonIndex)
              .replace(/\*\*/g, '')
              .replace(/\*/g, '')
              .replace(/^-\s*/, '')
              .trim();
            
            const value = line.substring(colonIndex + 1).trim();
            
            if (key && value) {
              details[key] = value;
            }
          }
        });
        
        if (Object.keys(details).length === 0 && content.trim()) {
          details['Purpose'] = content.trim();
        }
        
        return { num, title: stripMarkdown(title.trim()), details };
      }).filter((item): item is { num: string; title: string; details: { [key: string]: string } } => item !== null);
      
      console.log('parseExplanation: Successfully parsed', parsed.length, 'sections');
      return parsed;
    } catch (error) {
      console.error('parseExplanation: Error parsing explanation:', error);
      console.error('parseExplanation: Explanation text:', explanation);
      return [];
    }
  };

  // Check if message content is JSON
  const isJSON = (str: string): boolean => {
    const trimmed = str.trim();
    return (trimmed.startsWith('{') || trimmed.startsWith('[')) && (trimmed.endsWith('}') || trimmed.endsWith(']'));
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900">
      {/* Animated Background Orbs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-purple-500/15 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-pink-500/12 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] bg-orange-500/8 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '2s' }}></div>
      </div>

      {/* INITIAL FORM */}
      {showInitialForm && !response && (
        <div className="relative">
          <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-12 sm:pt-20 pb-16 sm:pb-32">
            <div className="mb-12 sm:mb-16">
              <div className="inline-flex items-center space-x-2 bg-purple-500/10 border border-purple-500/30 rounded-full px-4 sm:px-6 py-2 mb-4 sm:mb-6 backdrop-blur-xl">
                <Shield className="w-4 h-4 text-purple-400" />
                <span className="text-purple-400 text-xs sm:text-sm font-medium">AI-Powered Security</span>
              </div>
              
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black text-white mb-4 sm:mb-6 leading-tight">
                Generate Secure<br />
                <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-500 bg-clip-text text-transparent">
                  IAM Policies
                </span>
              </h1>
              
              <p className="text-base sm:text-xl text-slate-300 max-w-3xl leading-relaxed">
                Describe your permission needs in plain English. Our AI automatically generates 
                secure, least-privilege IAM policies following AWS best practices.
              </p>
            </div>

            <div className="max-w-4xl mx-auto">
              <form onSubmit={handleSubmit}>
                <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-3xl p-8 sm:p-10 shadow-2xl shadow-purple-500/10">
                  <div className="mb-8">
                    <label className="block text-white text-lg font-bold mb-4">
                      What permissions do you need?
                    </label>
                    <textarea
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="Example: Lambda function to read from S3 bucket customer-uploads-prod and write to DynamoDB table transaction-logs..."
                      className="w-full h-40 px-6 py-5 bg-slate-800/50 border border-slate-700/50 rounded-2xl text-white text-base placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none resize-none transition-all duration-300 ease-out"
                      required
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-8">
                    <div className="flex items-center space-x-4 bg-slate-800/30 rounded-2xl p-6 border border-slate-700/50 transition-all duration-300 hover:border-purple-500/30">
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
                            className="w-5 h-5 bg-slate-700 border-slate-600 rounded text-purple-500 focus:ring-purple-500 cursor-pointer flex-shrink-0"
                          />
                          <label htmlFor="restrictive" className="text-white text-base font-semibold cursor-pointer">
                            Maximum Security
                          </label>
                        </div>
                        <p className="text-slate-400 text-sm">Least-privilege mode</p>
                      </div>
                    </div>

                    <div className="bg-slate-800/30 rounded-2xl p-6 border border-slate-700/50 transition-all duration-300 hover:border-purple-500/30">
                      <label className="block text-white text-base font-semibold mb-3">Compliance Framework</label>
                      <select
                        value={compliance}
                        onChange={(e) => setCompliance(e.target.value)}
                        className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-xl text-white text-base focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none cursor-pointer transition-all duration-300"
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
                    className="w-full bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 hover:from-orange-700 hover:via-pink-600 hover:to-purple-700 text-white py-5 px-8 rounded-2xl font-bold text-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 ease-out shadow-2xl shadow-purple-500/25 hover:shadow-purple-500/40 hover:scale-[1.02] flex items-center justify-center space-x-3 group"
                  >
                    <Shield className="w-6 h-6" />
                    <span>Generate Secure Policy</span>
                    <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform duration-300" />
                  </button>
                </div>
              </form>

              {error && (
                <div className="mt-6 bg-red-500/10 border border-red-500/30 rounded-2xl p-6 backdrop-blur-xl">
                  <p className="text-red-400 text-base">{error}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* LOADING STATE */}
      {!showInitialForm && loading && !response && (
        <div className="relative min-h-screen flex items-center justify-center">
          <div className="text-center px-8 max-w-3xl">
            <div className="inline-flex items-center justify-center w-32 h-32 mb-10 relative">
              <div className="absolute inset-0 border-4 border-transparent border-t-purple-500 border-r-pink-500 rounded-full animate-spin"></div>
              <div className="absolute inset-2 border-4 border-transparent border-t-pink-500 border-r-orange-500 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '2s' }}></div>
              <div className="absolute inset-0 bg-gradient-to-br from-purple-500/20 via-pink-500/20 to-orange-500/20 rounded-full animate-ping"></div>
              <Shield className="w-16 h-16 text-purple-400 relative z-10 animate-pulse" />
            </div>
            
            <h2 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-orange-400 mb-4 animate-pulse leading-tight pb-2">
              Aegis AI Analyzing
            </h2>
            
            <p className="text-2xl text-slate-300 mb-8 leading-relaxed font-medium max-w-2xl mx-auto">
              Crafting your secure IAM policy with least-privilege principles...
            </p>
            
            <div className="flex flex-col items-center space-y-4 mb-10">
              <div className="flex items-center space-x-3 px-6 py-3 bg-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-full">
                <div className="w-2 h-2 bg-purple-400 rounded-full animate-pulse"></div>
                <span className="text-sm font-semibold text-slate-300">Analyzing AWS services...</span>
              </div>
              <div className="flex items-center space-x-3 px-6 py-3 bg-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-full">
                <div className="w-2 h-2 bg-pink-400 rounded-full animate-pulse" style={{ animationDelay: '0.5s' }}></div>
                <span className="text-sm font-semibold text-slate-300">Calculating security scores...</span>
              </div>
              <div className="flex items-center space-x-3 px-6 py-3 bg-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-full">
                <div className="w-2 h-2 bg-orange-400 rounded-full animate-pulse" style={{ animationDelay: '1s' }}></div>
                <span className="text-sm font-semibold text-slate-300">Generating policies...</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* LOADING STATE AFTER MORE INFO PAGE - Only show if NOT refining via chatbot */}
      {!showInitialForm && loading && response && response.is_question && !isRefining && (
        <div className="relative min-h-screen flex items-center justify-center">
          <div className="text-center px-8 max-w-3xl">
            <div className="inline-flex items-center justify-center w-32 h-32 mb-10 relative">
              <div className="absolute inset-0 border-4 border-transparent border-t-purple-500 border-r-pink-500 rounded-full animate-spin"></div>
              <div className="absolute inset-2 border-4 border-transparent border-t-pink-500 border-r-orange-500 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '2s' }}></div>
              <div className="absolute inset-0 bg-gradient-to-br from-purple-500/20 via-pink-500/20 to-orange-500/20 rounded-full animate-ping"></div>
              <Shield className="w-16 h-16 text-purple-400 relative z-10 animate-pulse" />
            </div>
            
            <h2 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-orange-400 mb-4 animate-pulse leading-tight pb-2">
              Aegis AI Analyzing
            </h2>
            
            <p className="text-2xl text-slate-300 mb-8 leading-relaxed font-medium max-w-2xl mx-auto">
              Crafting your secure IAM policy with least-privilege principles...
            </p>
            
            <div className="flex flex-col items-center space-y-4 mb-10">
              <div className="flex items-center space-x-3 px-6 py-3 bg-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-full">
                <div className="w-2 h-2 bg-purple-400 rounded-full animate-pulse"></div>
                <span className="text-sm font-semibold text-slate-300">Analyzing AWS services...</span>
              </div>
              <div className="flex items-center space-x-3 px-6 py-3 bg-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-full">
                <div className="w-2 h-2 bg-pink-400 rounded-full animate-pulse" style={{ animationDelay: '0.5s' }}></div>
                <span className="text-sm font-semibold text-slate-300">Calculating security scores...</span>
              </div>
              <div className="flex items-center space-x-3 px-6 py-3 bg-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-full">
                <div className="w-2 h-2 bg-orange-400 rounded-full animate-pulse" style={{ animationDelay: '1s' }}></div>
                <span className="text-sm font-semibold text-slate-300">Generating policies...</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MORE INFORMATION NEEDED PAGE */}
      {!showInitialForm && !loading && response && response.is_question && (
        <div className="relative min-h-screen">
          <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
            <div className="text-center mb-12">
              <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-orange-500/20 to-yellow-500/20 rounded-2xl mb-6 border border-orange-500/30 backdrop-blur-xl">
                <AlertCircle className="w-10 h-10 text-orange-400" />
              </div>
              
              <h2 className="text-4xl font-black text-white mb-4">
                Just a Few More Details
              </h2>
              
              <p className="text-lg text-slate-300">
                To generate the most secure policy, I need some additional information
              </p>
            </div>

            <div className="bg-slate-900/50 backdrop-blur-xl border border-orange-500/20 rounded-2xl p-8 mb-6 shadow-2xl">
              <div className="text-slate-300 leading-relaxed whitespace-pre-wrap text-base">
                {cleanMarkdown(response.explanation || response.final_answer)}
              </div>
            </div>

            <div className="bg-slate-900/50 backdrop-blur-xl border border-orange-500/20 rounded-2xl p-8 mb-6 shadow-2xl">
              <form onSubmit={handleFollowUp}>
                <label className="block text-white font-bold text-lg mb-4">
                  Your Response
                </label>
                <textarea
                  value={followUpMessage}
                  onChange={(e) => setFollowUpMessage(e.target.value)}
                  placeholder="Provide the requested information..."
                  className="w-full h-32 px-6 py-4 bg-slate-800/50 border border-slate-700/50 rounded-xl text-white placeholder-slate-500 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none resize-none mb-4 transition-all duration-300"
                  disabled={loading}
                />
                <button
                  type="submit"
                  disabled={loading || !followUpMessage.trim()}
                  className="w-full bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 hover:from-orange-700 hover:via-pink-600 hover:to-purple-700 text-white py-4 px-6 rounded-xl font-bold disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-2xl flex items-center justify-center space-x-2 hover:scale-[1.02]"
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

            <button
              onClick={handleNewConversation}
              className="w-full px-6 py-4 bg-slate-800/50 hover:bg-slate-700/50 border border-slate-700/50 text-white rounded-2xl transition-all duration-300 flex items-center justify-center space-x-2 backdrop-blur-xl"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Start Over</span>
            </button>
          </div>
        </div>
      )}

      {/* RESULTS DISPLAY */}
      {!showInitialForm && response && hasPolicy && (
        <div className="relative min-h-screen">
          <div className="relative max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
            {/* HEADER */}
            <div className="mb-16">
              <div className="text-center mb-8">
                <div className="inline-flex items-center justify-center mb-6">
                  <div className="relative">
                    <div className="absolute inset-0 bg-gradient-to-br from-purple-500/30 to-pink-500/30 rounded-3xl blur-2xl"></div>
                    <div className="relative bg-gradient-to-br from-purple-500/10 to-pink-500/10 backdrop-blur-xl border-2 border-purple-500/30 rounded-3xl p-4">
                      <Shield className="w-12 h-12 text-purple-400" />
                    </div>
                  </div>
                </div>
                
                <h2 className="text-4xl sm:text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-orange-400 mb-6 leading-normal pb-1">
                  Policies Generated Successfully
                </h2>
                
                <p className="text-slate-300 text-base max-w-2xl mx-auto leading-relaxed mb-6">
                  Review your IAM policies below. Use the <span className="text-purple-400 font-semibold">Aegis AI chatbot</span> to refine them before deployment.
                </p>
                
                <div className="flex items-center justify-center gap-3">
                  <div className="flex items-center space-x-2 px-3 py-1.5 bg-purple-500/10 border border-purple-500/30 rounded-full backdrop-blur-xl">
                    <CheckCircle className="w-3.5 h-3.5 text-purple-400" />
                    <span className="text-xs text-purple-300 font-medium">Permissions Policy</span>
                  </div>
                  <div className="flex items-center space-x-2 px-3 py-1.5 bg-green-500/10 border border-green-500/30 rounded-full backdrop-blur-xl">
                    <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                    <span className="text-xs text-green-300 font-medium">Trust Policy</span>
                  </div>
                </div>
              </div>
              
              <div className="flex justify-center mt-8">
                <button
                  onClick={handleNewConversation}
                  className="group relative px-6 py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white font-bold rounded-xl transition-all duration-300 shadow-2xl shadow-purple-500/25 hover:shadow-purple-500/40 hover:scale-105 flex items-center space-x-2"
                >
                  <RefreshCw className="w-4 h-4 group-hover:rotate-180 transition-transform duration-500" />
                  <span>Generate New Policy</span>
                </button>
              </div>
            </div>

            {/* SECURITY SCORES SECTION */}
            <div className="mb-16">
              {/* Header with Toggle */}
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-white text-2xl font-black flex items-center space-x-3">
                  <Shield className="w-7 h-7 text-purple-400" />
                  <span>Security Scores</span>
                </h3>
                <button
                  onClick={() => setShowScoreBreakdown(!showScoreBreakdown)}
                  className="group flex items-center space-x-2 px-4 py-2 bg-slate-800/50 hover:bg-slate-700/50 border border-slate-700/50 rounded-xl transition-all duration-300"
                >
                  <span className="text-sm font-semibold text-slate-300 group-hover:text-white transition-colors duration-300">
                    {showScoreBreakdown ? 'Hide Details' : 'Show Details'}
                  </span>
                  {showScoreBreakdown ? (
                    <ChevronUp className="w-4 h-4 text-slate-400 group-hover:text-white transition-colors duration-300" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-slate-400 group-hover:text-white transition-colors duration-300" />
                  )}
                </button>
              </div>

              {/* Score Cards Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Permissions Policy Score Card */}
                <div className="bg-gradient-to-br from-orange-500/10 to-red-500/10 backdrop-blur-xl border-2 border-orange-500/30 rounded-2xl p-8 shadow-2xl shadow-orange-500/10 hover-lift animate-fadeInUp opacity-0">
                  <h3 className="text-orange-400 text-sm font-bold uppercase tracking-wider mb-6">Permissions Policy</h3>
                
                <div className="flex items-end justify-between mb-6">
                  <div className="text-6xl font-black text-white">{permissionsScore}</div>
                  <div className="text-slate-400 text-xl font-medium">/100</div>
                </div>
                
                <div className="w-full bg-slate-800/50 rounded-full h-3 mb-6 overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-orange-500 to-red-500 h-3 rounded-full transition-all duration-1000 ease-out animate-glowPulse"
                    style={{ width: `${permissionsScore}%` }}
                  ></div>
                </div>
                
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-400 font-medium">Security Grade</span>
                    <span className="text-3xl font-black text-orange-400">
                      {permissionsScore >= 90 ? 'A' : permissionsScore >= 80 ? 'B' : permissionsScore >= 70 ? 'C' : permissionsScore >= 60 ? 'D' : 'F'}
                    </span>
                  </div>

                  {/* Collapsible Breakdown */}
                  {showScoreBreakdown && (
                  <div className="mt-6 pt-6 border-t border-orange-500/20 space-y-6 animate-in slide-in-from-top duration-300">
                    {response.score_breakdown?.permissions?.positive?.length > 0 && (
                      <div>
                        <div className="flex items-center space-x-2 mb-4">
                          <CheckCircle className="w-5 h-5 text-green-400" />
                          <span className="text-base font-bold text-green-400">Strengths</span>
                        </div>
                        <ul className="space-y-3">
                          {response.score_breakdown.permissions.positive.map((item, idx) => (
                            <li key={idx} className="text-sm text-slate-200 flex items-start space-x-3 leading-relaxed">
                              <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                              <span>{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    {response.score_breakdown?.permissions?.improvements?.length > 0 && (
                      <div>
                        <div className="flex items-center space-x-2 mb-4">
                          <AlertCircle className="w-5 h-5 text-orange-400" />
                          <span className="text-base font-bold text-orange-400">Room for Improvement</span>
                        </div>
                        <ul className="space-y-3">
                          {response.score_breakdown.permissions.improvements.map((item, idx) => (
                            <li key={idx} className="text-sm text-slate-200 flex items-start space-x-3 leading-relaxed">
                              <AlertCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                              <span>{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                  )}
                </div>

                {/* Trust Policy Score Card */}
                <div className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 backdrop-blur-xl border-2 border-green-500/30 rounded-2xl p-8 shadow-2xl shadow-green-500/10 hover-lift animate-fadeInUp opacity-0 delay-100">
                  <h3 className="text-green-400 text-sm font-bold uppercase tracking-wider mb-6">Trust Policy</h3>
                
                <div className="flex items-end justify-between mb-6">
                  <div className="text-6xl font-black text-white">{trustScore}</div>
                  <div className="text-slate-400 text-xl font-medium">/100</div>
                </div>
                
                <div className="w-full bg-slate-800/50 rounded-full h-3 mb-6 overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-green-500 to-emerald-500 h-3 rounded-full transition-all duration-1000 ease-out animate-glowPulse"
                    style={{ width: `${trustScore}%` }}
                  ></div>
                </div>
                
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-400 font-medium">Security Grade</span>
                    <span className="text-3xl font-black text-green-400">
                      {trustScore >= 90 ? 'A' : trustScore >= 80 ? 'B' : trustScore >= 70 ? 'C' : trustScore >= 60 ? 'D' : 'F'}
                    </span>
                  </div>

                  {/* Collapsible Breakdown */}
                  {showScoreBreakdown && (
                  <div className="mt-6 pt-6 border-t border-green-500/20 space-y-6 animate-in slide-in-from-top duration-300">
                    {response.score_breakdown?.trust?.positive?.length > 0 && (
                      <div>
                        <div className="flex items-center space-x-2 mb-4">
                          <CheckCircle className="w-5 h-5 text-green-400" />
                          <span className="text-base font-bold text-green-400">Strengths</span>
                        </div>
                        <ul className="space-y-3">
                          {response.score_breakdown.trust.positive.map((item, idx) => (
                            <li key={idx} className="text-sm text-slate-200 flex items-start space-x-3 leading-relaxed">
                              <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                              <span>{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    {response.score_breakdown?.trust?.improvements?.length > 0 && (
                      <div>
                        <div className="flex items-center space-x-2 mb-4">
                          <AlertCircle className="w-5 h-5 text-orange-400" />
                          <span className="text-base font-bold text-orange-400">Room for Improvement</span>
                        </div>
                        <ul className="space-y-3">
                          {response.score_breakdown.trust.improvements.map((item, idx) => (
                            <li key={idx} className="text-sm text-slate-200 flex items-start space-x-3 leading-relaxed">
                              <AlertCircle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                              <span>{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                  )}
                </div>
              </div>
            </div>

            {/* POLICIES SECTION */}
            <div className="space-y-12">
              {/* PERMISSIONS POLICY */}
              <div className="animate-fadeInUp opacity-0 delay-200">
                <button
                  onClick={() => setShowPermissionsPolicy(!showPermissionsPolicy)}
                  className="w-full text-left group mb-6 flex items-center justify-between hover:opacity-80 transition-opacity"
                >
                  <h3 className="text-white text-3xl font-black flex items-center space-x-3">
                    <Shield className="w-8 h-8 text-purple-400" />
                    <span>Permissions Policy</span>
                  </h3>
                  {showPermissionsPolicy ? (
                    <ChevronUp className="w-6 h-6 text-slate-400 group-hover:text-purple-400 transition-colors" />
                  ) : (
                    <ChevronDown className="w-6 h-6 text-slate-400 group-hover:text-purple-400 transition-colors" />
                  )}
                </button>

                {showPermissionsPolicy && (
                <>
                <div className="bg-slate-900/80 backdrop-blur-xl border-2 border-slate-800/50 rounded-2xl overflow-hidden shadow-2xl shadow-purple-500/10 hover-lift animate-fadeInUp">
                  <div className="bg-gradient-to-r from-slate-800/90 to-slate-900/90 px-6 py-4 flex items-center justify-between border-b border-slate-700/50">
                    <div className="flex items-center space-x-3">
                      <div className="flex space-x-2">
                        <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
                        <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
                        <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
                      </div>
                      <span className="text-slate-400 text-sm font-mono">permissions-policy.json</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={handleCopyPolicy}
                        className="group relative px-4 py-2 bg-slate-800/50 hover:bg-slate-700/50 border border-slate-700/50 hover:border-slate-600/50 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105"
                      >
                        <Copy className="w-4 h-4 text-slate-400 group-hover:text-purple-400 transition-colors duration-300" />
                        <span className="text-sm font-medium text-slate-300 group-hover:text-white transition-colors duration-300">
                          {copied ? 'Copied!' : 'Copy'}
                        </span>
                      </button>
                      <button
                        onClick={() => {
                          const blob = new Blob([JSON.stringify(response.policy, null, 2)], { type: 'application/json' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = 'permissions-policy.json';
                          a.click();
                        }}
                        className="group relative px-4 py-2 bg-purple-600/80 hover:bg-purple-500/80 border border-purple-500/50 hover:border-purple-400/50 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 animate-glowPulse"
                      >
                        <Download className="w-4 h-4 text-white transition-transform duration-300 group-hover:translate-y-0.5" />
                        <span className="text-sm font-medium text-white">Download</span>
                      </button>
                    </div>
                  </div>

                  <div className="p-6 overflow-x-auto">
                    <pre className="text-sm font-mono text-slate-300 leading-relaxed">
                      {JSON.stringify(response.policy, null, 2)}
                    </pre>
                  </div>
                </div>

                <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-4 mt-6 backdrop-blur-xl">
                  <div className="flex items-start space-x-3">
                    <Info className="w-5 h-5 text-purple-400 mt-0.5" />
                    <div>
                      <div className="text-sm font-bold text-purple-300 mb-1">About Permissions Policy</div>
                      <p className="text-sm text-slate-300 leading-relaxed">
                        The Permissions Policy defines <strong>WHAT</strong> actions this IAM role can perform on AWS resources. 
                        It specifies the exact services, actions, and resources that are allowed or denied.
                      </p>
                    </div>
                  </div>
                </div>

                {response.explanation && (
                  <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8 mt-6 shadow-2xl">
                    <h4 className="text-white text-xl font-black mb-4 flex items-center space-x-2">
                      <Shield className="w-5 h-5 text-purple-400" />
                      <span>What These Permissions Do</span>
                    </h4>
                    <p className="text-slate-400 mb-6 text-sm">Breakdown of each permission statement</p>
                    
                    <div className="grid grid-cols-1 gap-4">
                      {parseExplanation(response.explanation).map((section: any, index) => (
                        <div key={index} className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 rounded-xl p-5 border border-slate-700/50 transition-all duration-300 hover:border-purple-500/30">
                          <div className="flex items-start space-x-3 mb-3">
                            <div className="text-3xl">{getServiceIcon(section.title)}</div>
                            <div className="flex-1">
                              <div className="text-xs text-slate-500 mb-2 font-bold uppercase tracking-wider">STATEMENT {section.num}</div>
                              <h5 className="text-white font-bold text-base">{stripMarkdown(section.title)}</h5>
                            </div>
                          </div>
                          
                          <div className="space-y-2">
                            {section.details.Permission && (
                              <div className="bg-slate-900/50 rounded-lg p-3">
                                <div className="text-sm text-white font-mono">
                                  {section.details.Permission}
                                </div>
                              </div>
                            )}
                            
                            {section.details.Purpose && (
                              <div className="text-sm text-slate-300 leading-relaxed">
                                <span className="font-bold text-slate-400">Purpose:</span> {stripMarkdown(section.details.Purpose)}
                              </div>
                            )}
                            
                            {section.details.Security && (
                              <div className="flex items-start space-x-2 bg-green-500/5 border border-green-500/20 rounded-lg p-2">
                                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                                <div className="text-xs text-green-300">
                                  {section.details.Security}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                </>
                )}
              </div>

              {/* TRUST POLICY */}
              {response.trust_policy && (
                <div className="animate-fadeInUp opacity-0 delay-300">
                  <button
                    onClick={() => setShowTrustPolicy(!showTrustPolicy)}
                    className="w-full text-left group mb-6 flex items-center justify-between hover:opacity-80 transition-opacity"
                  >
                    <h3 className="text-white text-3xl font-black flex items-center space-x-3">
                      <CheckCircle className="w-8 h-8 text-green-400" />
                      <span>Trust Policy</span>
                    </h3>
                    {showTrustPolicy ? (
                      <ChevronUp className="w-6 h-6 text-slate-400 group-hover:text-green-400 transition-colors" />
                    ) : (
                      <ChevronDown className="w-6 h-6 text-slate-400 group-hover:text-green-400 transition-colors" />
                    )}
                  </button>

                  {showTrustPolicy && (
                  <>
                  <div className="bg-slate-900/80 backdrop-blur-xl border-2 border-slate-800/50 rounded-2xl overflow-hidden shadow-2xl shadow-green-500/10 hover-lift animate-fadeInUp">
                    <div className="bg-gradient-to-r from-slate-800/90 to-slate-900/90 px-6 py-4 flex items-center justify-between border-b border-slate-700/50">
                      <div className="flex items-center space-x-3">
                        <div className="flex space-x-2">
                          <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
                          <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
                          <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
                        </div>
                        <span className="text-slate-400 text-sm font-mono">trust-policy.json</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={handleCopyTrustPolicy}
                          className="group relative px-4 py-2 bg-slate-800/50 hover:bg-slate-700/50 border border-slate-700/50 hover:border-slate-600/50 rounded-lg transition-all duration-300 flex items-center space-x-2"
                        >
                          <Copy className="w-4 h-4 text-slate-400 group-hover:text-green-400 transition-colors duration-300" />
                          <span className="text-sm font-medium text-slate-300 group-hover:text-white transition-colors duration-300">
                            {copiedTrust ? 'Copied!' : 'Copy'}
                          </span>
                        </button>
                        <button
                          onClick={() => {
                            const blob = new Blob([JSON.stringify(response.trust_policy, null, 2)], { type: 'application/json' });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = 'trust-policy.json';
                            a.click();
                          }}
                          className="group relative px-4 py-2 bg-green-600/80 hover:bg-green-500/80 border border-green-500/50 hover:border-green-400/50 rounded-lg transition-all duration-300 flex items-center space-x-2"
                        >
                          <Download className="w-4 h-4 text-white transition-transform duration-300 group-hover:translate-y-0.5" />
                          <span className="text-sm font-medium text-white">Download</span>
                        </button>
                      </div>
                    </div>

                    <div className="p-6 bg-slate-950/50">
                      <pre className="text-sm text-white font-mono leading-relaxed overflow-x-auto">
                        {JSON.stringify(response.trust_policy, null, 2)}
                      </pre>
                    </div>
                  </div>

                  <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4 mt-6 backdrop-blur-xl">
                    <div className="flex items-start space-x-3">
                      <Info className="w-5 h-5 text-green-400 mt-0.5" />
                      <div>
                        <div className="text-sm font-bold text-green-300 mb-1">About Trust Policy</div>
                        <p className="text-sm text-slate-300 leading-relaxed">
                          The Trust Policy defines <strong>WHO</strong> can assume this IAM role. Without it, 
                          nobody (not even AWS services) can use the permissions policy above.
                        </p>
                      </div>
                    </div>
                  </div>

                  {response.trust_explanation && (
                    <div className="bg-slate-900/50 backdrop-blur-xl border border-green-500/20 rounded-2xl p-8 mt-6 shadow-2xl">
                      <h4 className="text-white text-xl font-black mb-4 flex items-center space-x-2">
                        <Shield className="w-5 h-5 text-green-400" />
                        <span>What This Trust Policy Does</span>
                      </h4>
                      <p className="text-slate-400 mb-6 text-sm">Who can assume this role and under what conditions</p>
                      
                      <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 rounded-xl p-5 border border-slate-700/50">
                        <div className="space-y-4">
                          <div>
                            <div className="text-xs text-slate-500 mb-2 uppercase tracking-wide font-bold">Trusted Entity</div>
                            <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-700/30">
                              <div className="text-sm text-white font-mono">
                                {response.trust_policy.Statement?.[0]?.Principal?.Service || 
                                 JSON.stringify(response.trust_policy.Statement?.[0]?.Principal)}
                              </div>
                            </div>
                          </div>
                          
                          <div>
                            <div className="text-xs text-slate-500 mb-2 uppercase tracking-wide font-bold">What It Means</div>
                            <div className="space-y-3">
                              {stripMarkdown(response.trust_explanation).split('\n\n').map((section, idx) => {
                                const lines = section.split('\n');
                                const title = lines[0];
                                const details = lines.slice(1);
                                
                                return (
                                  <div key={idx} className="bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
                                    {title && (
                                      <h5 className="text-white font-bold text-sm mb-2">{stripMarkdown(title)}</h5>
                                    )}
                                    {details.map((detail, dIdx) => (
                                      detail.trim() && (
                                        <p key={dIdx} className="text-sm text-slate-300 leading-relaxed mb-1">
                                          {stripMarkdown(detail.trim())}
                                        </p>
                                      )
                                    ))}
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                          
                          <div className="flex items-start space-x-2 bg-green-500/5 border border-green-500/20 rounded-lg p-3">
                            <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                            <div className="text-xs text-green-300">
                              Follows AWS security best practices by explicitly defining trusted principals
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                  </>
                  )}
                </div>
              )}

              {/* PERMISSIONS POLICY REFINEMENT SUGGESTIONS */}
              {response?.refinement_suggestions?.permissions?.length > 0 && (
                <div className="animate-fadeInUp opacity-0 delay-400">
                  <div className="relative">
                    {/* Decorative gradient glow */}
                    <div className="absolute -inset-1 bg-gradient-to-r from-blue-500/20 via-purple-500/20 to-indigo-500/20 rounded-2xl blur-xl opacity-15"></div>
                    
                    <div className="relative bg-gradient-to-br from-slate-800/60 via-slate-800/50 to-slate-900/60 backdrop-blur-xl border border-blue-500/20 rounded-2xl p-8 shadow-2xl hover:border-blue-400/30 transition-all duration-500">
                      <button
                        onClick={() => setShowPermissionsSuggestions(!showPermissionsSuggestions)}
                        className="w-full text-left group mb-6 flex items-center justify-between hover:opacity-80 transition-opacity"
                      >
                        <div className="flex items-center space-x-3">
                          <div className="p-2 bg-gradient-to-br from-blue-500/30 to-purple-500/30 rounded-xl border border-blue-500/40 group-hover:scale-110 transition-transform duration-300">
                            <Sparkles className="w-6 h-6 text-blue-400" />
                          </div>
                          <div>
                            <h3 className="text-white text-2xl font-black bg-gradient-to-r from-blue-300 via-purple-300 to-indigo-300 bg-clip-text text-transparent">
                              Permissions Policy Refinements
                            </h3>
                            <p className="text-slate-400 text-sm mt-1">🔐 Enhance your permissions policy security</p>
                          </div>
                        </div>
                        {showPermissionsSuggestions ? (
                          <ChevronUp className="w-7 h-7 text-slate-400 group-hover:text-blue-400 transition-colors duration-300" />
                        ) : (
                          <ChevronDown className="w-7 h-7 text-slate-400 group-hover:text-blue-400 transition-colors duration-300" />
                        )}
                      </button>

                      {showPermissionsSuggestions && (
                        <>
                          <div className="bg-gradient-to-r from-blue-500/15 to-purple-500/15 border border-blue-500/30 rounded-xl p-4 mb-6">
                            <p className="text-slate-300 text-sm leading-relaxed">
                              💡 <strong className="text-blue-300">Pro Tip:</strong> Click any suggestion below to automatically implement it via the chatbot
                            </p>
                          </div>
                          
                          <div className="grid grid-cols-1 gap-4">
                            {response.refinement_suggestions.permissions.map((suggestion, idx) => (
                              <button
                                key={idx}
                                onClick={() => {
                                  setFollowUpMessage(suggestion);
                                  setIsChatbotOpen(true);
                                }}
                                className="group relative px-6 py-5 bg-gradient-to-br from-slate-800/80 to-slate-900/80 hover:from-blue-500/20 hover:to-purple-500/20 border-2 border-slate-700/50 hover:border-blue-500/50 rounded-xl text-left transition-all duration-300 shadow-lg hover:shadow-blue-500/20 hover:scale-[1.02] overflow-hidden"
                              >
                                {/* Animated gradient background on hover */}
                                <div className="absolute inset-0 bg-gradient-to-r from-amber-600/0 via-orange-600/0 to-red-600/0 group-hover:from-amber-600/15 group-hover:via-orange-600/15 group-hover:to-red-600/15 transition-all duration-500"></div>
                                
                                <div className="relative flex items-center space-x-4">
                                  <div className="flex-shrink-0 p-2 bg-gradient-to-br from-amber-500/30 to-orange-500/30 rounded-lg border border-amber-500/40 group-hover:scale-110 transition-transform duration-300">
                                    <Sparkles className="w-5 h-5 text-amber-400" />
                                  </div>
                                  <div className="flex-1">
                                    <p className="text-slate-200 group-hover:text-white font-medium transition-colors duration-300">
                                      {suggestion}
                                    </p>
                                  </div>
                                  <ArrowRight className="w-5 h-5 text-slate-600 group-hover:text-blue-400 opacity-0 group-hover:opacity-100 transition-all duration-300 transform group-hover:translate-x-1 flex-shrink-0" />
                                </div>
                              </button>
                            ))}
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* TRUST POLICY REFINEMENT SUGGESTIONS - SEPARATE SECTION */}
              {response?.refinement_suggestions?.trust?.length > 0 && (
                <div className="animate-fadeInUp opacity-0 delay-400 mt-12">
                  <div className="relative">
                    {/* Decorative gradient glow */}
                    <div className="absolute -inset-1 bg-gradient-to-r from-orange-600 via-pink-600 to-purple-600 rounded-2xl blur-xl opacity-20"></div>
                    
                    <div className="relative bg-gradient-to-br from-orange-500/10 via-pink-500/10 to-purple-500/10 backdrop-blur-xl border-2 border-orange-500/30 rounded-2xl p-8 shadow-2xl hover:border-orange-400/50 transition-all duration-500">
                      <button
                        onClick={() => setShowTrustSuggestions(!showTrustSuggestions)}
                        className="w-full text-left group mb-6 flex items-center justify-between hover:opacity-80 transition-opacity"
                      >
                        <div className="flex items-center space-x-3">
                          <div className="p-2 bg-slate-700/50 rounded-xl border border-slate-600/50 group-hover:scale-110 transition-transform duration-300">
                            <Sparkles className="w-6 h-6 text-orange-300" />
                          </div>
                          <div>
                            <h3 className="text-white text-2xl font-black">
                              Trust Policy Refinements
                            </h3>
                            <p className="text-slate-400 text-sm mt-1">🔒 Enhance your trust policy security</p>
                          </div>
                        </div>
                        {showTrustSuggestions ? (
                          <ChevronUp className="w-7 h-7 text-slate-400 group-hover:text-orange-400 transition-colors duration-300" />
                        ) : (
                          <ChevronDown className="w-7 h-7 text-slate-400 group-hover:text-orange-400 transition-colors duration-300" />
                        )}
                      </button>

                      {showTrustSuggestions && (
                        <>
                          <div className="bg-gradient-to-r from-orange-500/10 to-pink-500/10 border border-orange-500/20 rounded-xl p-4 mb-6">
                            <p className="text-slate-300 text-sm leading-relaxed">
                              💡 <strong className="text-orange-300">Pro Tip:</strong> Click any suggestion below to automatically implement it via the chatbot
                            </p>
                          </div>
                          
                          <div className="grid grid-cols-1 gap-4">
                            {response.refinement_suggestions.trust.map((suggestion, idx) => (
                              <button
                                key={idx}
                                onClick={() => {
                                  setFollowUpMessage(suggestion);
                                  setIsChatbotOpen(true);
                                }}
                                className="group relative px-6 py-5 bg-slate-800/50 hover:bg-slate-800/70 border border-slate-700/50 hover:border-slate-600/70 rounded-xl text-left transition-all duration-300 shadow-lg hover:shadow-slate-900/50 hover:scale-[1.01] overflow-hidden"
                              >
                                {/* Animated gradient background on hover */}
                                <div className="absolute inset-0 bg-gradient-to-r from-orange-500/0 via-red-500/0 to-pink-500/0 group-hover:from-orange-500/5 group-hover:via-red-500/5 group-hover:to-pink-500/5 transition-all duration-500"></div>
                                
                                <div className="relative flex items-center space-x-4">
                                  <div className="flex-shrink-0 p-2 bg-slate-700/50 rounded-lg border border-slate-600/50 group-hover:scale-110 transition-transform duration-300">
                                    <Sparkles className="w-5 h-5 text-slate-400 group-hover:text-orange-400" />
                                  </div>
                                  <div className="flex-1">
                                    <p className="text-slate-200 group-hover:text-white font-medium transition-colors duration-300">
                                      {suggestion}
                                    </p>
                                  </div>
                                  <ArrowRight className="w-5 h-5 text-slate-600 group-hover:text-orange-400 opacity-0 group-hover:opacity-100 transition-all duration-300 transform group-hover:translate-x-1 flex-shrink-0" />
                                </div>
                              </button>
                            ))}
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* REFINE POLICY FORM */}
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8 shadow-2xl">
                <h4 className="text-white text-xl font-black mb-4 flex items-center space-x-2">
                  <MessageSquare className="w-6 h-6 text-purple-400" />
                  <span>Refine Your Policy</span>
                </h4>
                <p className="text-slate-300 text-sm mb-6">
                  Ask questions or request changes to improve your policy
                </p>
                
                <form onSubmit={handleFollowUp} className="space-y-4">
                  <textarea
                    value={followUpMessage}
                    onChange={(e) => setFollowUpMessage(e.target.value)}
                    placeholder="Example: Add MFA requirement for sensitive operations..."
                    className="w-full h-24 px-4 py-3 bg-slate-800/50 border border-slate-700/50 rounded-xl text-white placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none resize-none transition-all duration-300"
                    disabled={loading}
                  />
                  
                  <button
                    type="submit"
                    disabled={loading || !followUpMessage.trim()}
                    className="w-full bg-gradient-to-r from-purple-600 via-pink-500 to-orange-600 hover:from-purple-500 hover:via-pink-400 hover:to-orange-500 text-white py-4 px-6 rounded-xl font-bold disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-2xl shadow-purple-500/25 hover:shadow-purple-500/40 hover:scale-[1.02] flex items-center justify-center space-x-2"
                  >
                    {loading ? (
                      <>
                        <RefreshCw className="w-5 h-5 animate-spin" />
                        <span>Processing...</span>
                      </>
                    ) : (
                      <>
                        <Send className="w-5 h-5" />
                        <span>Refine Policy</span>
                      </>
                    )}
                  </button>
                </form>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* FLOATING CHATBOT WIDGET */}
      {!showInitialForm && response && hasPolicy && (
        <div className="fixed bottom-6 right-6 z-50">
          {!isChatbotOpen && (
            <button
              onClick={() => setIsChatbotOpen(true)}
              className="group relative w-16 h-16 bg-gradient-to-br from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 rounded-full shadow-2xl shadow-purple-500/50 hover:shadow-purple-500/70 transition-all duration-300 hover:scale-110 flex items-center justify-center"
            >
              <Bot className="w-8 h-8 text-white" />
              <div className="absolute -top-1 -right-1 w-4 h-4 bg-green-400 rounded-full border-2 border-slate-950 animate-pulse"></div>
            </button>
          )}

          {isChatbotOpen && (
            <div className={`${isChatbotExpanded ? 'w-[90vw] h-[90vh]' : 'w-96 h-[600px]'} bg-slate-900/95 backdrop-blur-xl border border-slate-700/50 rounded-2xl shadow-2xl flex flex-col overflow-hidden transition-all duration-300`}>
              <div className="p-4 bg-gradient-to-r from-purple-600/20 to-pink-600/20 border-b border-slate-700/50 flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full flex items-center justify-center">
                    <Bot className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h3 className="text-white font-bold text-sm">Aegis AI Agent</h3>
                    <p className="text-xs text-slate-400">Ask me anything about your policies</p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setIsChatbotExpanded(!isChatbotExpanded)}
                    className="text-slate-400 hover:text-white transition-colors duration-300 p-1 hover:bg-slate-800/50 rounded"
                  >
                    {isChatbotExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
                  </button>
                  <button
                    onClick={() => setIsChatbotOpen(false)}
                    className="text-slate-400 hover:text-white transition-colors duration-300"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
              </div>

              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {chatHistory.map((msg, idx) => {
                  const isJSONContent = isJSON(msg.content);
                  
                  return (
                    <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                      <div className={`max-w-[85%] ${
                        msg.role === 'user' 
                          ? 'bg-gradient-to-br from-purple-500/20 to-pink-500/20 border border-purple-500/30' 
                          : 'bg-slate-800/50 border border-slate-700/50'
                      } rounded-2xl p-3`}>
                        <div className="flex items-start space-x-2">
                          {msg.role === 'assistant' && (
                            <Bot className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                          )}
                          <div className="flex-1">
                            {isJSONContent ? (
                              <div className="bg-slate-950 rounded-lg p-3 border border-slate-700/50">
                                <div className="flex items-center justify-between mb-2">
                                  <span className="text-xs text-slate-500 font-mono">JSON Response</span>
                                  <button
                                    onClick={() => handleCopyJSON(msg.content)}
                                    className="text-xs text-purple-400 hover:text-purple-300 transition-colors duration-300 flex items-center space-x-1"
                                  >
                                    <Copy className="w-3 h-3" />
                                    <span>Copy</span>
                                  </button>
                                </div>
                                <pre className="text-xs text-green-400 font-mono overflow-x-auto leading-relaxed">
                                  {JSON.stringify(JSON.parse(msg.content), null, 2)}
                                </pre>
                              </div>
                            ) : (
                              <div>
                                <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-wrap">{msg.content}</p>
                                
                                {/* Quick Action Buttons for Initial Greeting */}
                                {idx === 0 && msg.role === 'assistant' && msg.content.includes('Aegis AI Agent') && (
                                  <div className="mt-4 flex flex-wrap gap-2">
                                    <button
                                      onClick={() => {
                                        setFollowUpMessage('Show me both policies in JSON format');
                                        // Auto-submit
                                        setTimeout(() => {
                                          const form = document.querySelector('form');
                                          if (form) {
                                            const event = new Event('submit', { bubbles: true, cancelable: true });
                                            form.dispatchEvent(event);
                                          }
                                        }, 100);
                                      }}
                                      className="group px-3 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 hover:border-purple-500/60 rounded-lg text-xs text-purple-300 hover:text-white transition-all duration-300 flex items-center space-x-2"
                                    >
                                      <Copy className="w-3 h-3" />
                                      <span>Get Both Policies (JSON)</span>
                                    </button>
                                    <button
                                      onClick={() => {
                                        setFollowUpMessage('Add MFA requirement for sensitive operations');
                                      }}
                                      className="group px-3 py-2 bg-orange-500/20 hover:bg-orange-500/30 border border-orange-500/40 hover:border-orange-500/60 rounded-lg text-xs text-orange-300 hover:text-white transition-all duration-300 flex items-center space-x-2"
                                    >
                                      <Lock className="w-3 h-3" />
                                      <span>Add MFA</span>
                                    </button>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
                
                {/* Loading indicator inside chatbot */}
                {loading && (
                  <div className="flex justify-start">
                    <div className="max-w-[85%] bg-slate-800/50 border border-slate-700/50 rounded-2xl p-3">
                      <div className="flex items-start space-x-2">
                        <Bot className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" />
                        <div className="flex items-center space-x-2">
                          <div className="flex space-x-1">
                            <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
                            <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
                            <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
                          </div>
                          <span className="text-xs text-slate-400">Aegis AI is thinking...</span>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
                
                <div ref={chatEndRef} />
              </div>

              <div className="p-4 border-t border-slate-700/50 bg-slate-900/50">
                <form onSubmit={handleFollowUp} className="space-y-2">
                  <textarea
                    value={followUpMessage}
                    onChange={(e) => setFollowUpMessage(e.target.value)}
                    placeholder="Ask me to refine the policy, explain something, or answer questions..."
                    className="w-full h-20 px-3 py-2 bg-slate-800/50 border border-slate-700/50 rounded-xl text-white text-sm placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none resize-none transition-all duration-300"
                    disabled={loading}
                  />
                  
                  <button
                    type="submit"
                    disabled={loading || !followUpMessage.trim()}
                    className="w-full bg-gradient-to-r from-purple-600 via-pink-500 to-orange-600 hover:from-purple-500 hover:via-pink-400 hover:to-orange-500 text-white py-2.5 px-4 rounded-xl font-bold text-sm disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-lg flex items-center justify-center space-x-2 hover:scale-[1.02]"
                  >
                    {loading ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Processing...</span>
                      </>
                    ) : (
                      <>
                        <Send className="w-4 h-4" />
                        <span>Send Message</span>
                      </>
                    )}
                  </button>
                </form>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default GeneratePolicy;