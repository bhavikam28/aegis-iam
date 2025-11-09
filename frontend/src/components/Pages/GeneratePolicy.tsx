import React, { useState, useEffect, useRef } from 'react';
import { Shield, Send, RefreshCw, User, Bot, MessageSquare, Lock, ArrowRight, CheckCircle, AlertCircle, Download, Copy, Sparkles, Info, X, Minimize2, ChevronUp, ChevronDown, Maximize2, XCircle, Lightbulb, FileCheck, Target } from 'lucide-react';
import { generatePolicy, sendFollowUp } from '../../services/api';
import { GeneratePolicyResponse, ChatMessage } from '../../types';

const GeneratePolicy: React.FC = () => {
  const [description, setDescription] = useState('');
  const [restrictive, setRestrictive] = useState(true);
  const [compliance, setCompliance] = useState('general');
  const [awsAccountId, setAwsAccountId] = useState('');
  const [awsRegion, setAwsRegion] = useState('');
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
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  
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
      // Build description with optional AWS values if provided
      let enhancedDescription = description;
      if (awsAccountId.trim()) {
        enhancedDescription += `\n\nAWS Account ID: ${awsAccountId.trim()}`;
      }
      if (awsRegion.trim()) {
        enhancedDescription += `\n\nAWS Region: ${awsRegion.trim()}`;
      }
      
      const result = await generatePolicy({
        description: enhancedDescription,
        restrictive,
        compliance
      });
      
      // Validate result before setting state
      if (!result) {
        throw new Error('No response received from server');
      }
      
      setResponse(result);
      setConversationId(result?.conversation_id || null);
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
      
      // Check if result is null/undefined
      if (!result) {
        throw new Error('No response received from server');
      }
      
      // Use the result's final_answer directly - it should already contain both policies in JSON format
      // The backend agent is now instructed to ALWAYS return both policies in JSON format
      let responseContent = result?.final_answer || 'Policy updated successfully.';
      
      // Extract and update policies from result if available
      // The backend should always return both policies, so we update our state
      if (result?.policy || result?.trust_policy) {
        // Update response state with new policies
        setResponse(prev => ({
          ...prev,
          ...result,
          policy: result?.policy || prev?.policy,
          trust_policy: result?.trust_policy || prev?.trust_policy,
          permissions_score: result?.permissions_score ?? prev?.permissions_score ?? 0,
          trust_score: result?.trust_score ?? prev?.trust_score ?? 0,
          overall_score: result?.overall_score ?? prev?.overall_score ?? 0,
          final_answer: result?.final_answer || prev?.final_answer || '',
          explanation: result?.explanation || prev?.explanation || '',
        }));
      } else {
        // Even if no policy, update the response with final_answer for chat display
        setResponse(prev => ({
          ...prev,
          ...result,
          final_answer: result?.final_answer || prev?.final_answer || '',
          explanation: result?.explanation || prev?.explanation || result?.final_answer || '',
        }));
      }
      
      // Add assistant response to chat
      const assistantMessage: ChatMessage = {
        role: 'assistant',
        content: responseContent,
        timestamp: new Date().toISOString()
      };
      setChatHistory(prev => [...prev, assistantMessage]);
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
    setAwsAccountId('');
    setAwsRegion('');
    
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
  
  // Check if there's an explanation or final_answer to display (even without a new policy)
  const hasContent = hasPolicy || 
                     (response?.final_answer && response.final_answer.trim() !== '') ||
                     (response?.explanation && response.explanation.trim() !== '');

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
    <div className="min-h-screen relative overflow-hidden">
      {/* Premium Animated Background - Light Theme */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 right-0 w-[800px] h-[800px] bg-gradient-to-br from-blue-400/8 via-purple-400/6 to-pink-400/4 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 left-0 w-[700px] h-[700px] bg-gradient-to-tr from-amber-400/6 via-orange-400/4 to-red-400/3 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '2s' }}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-br from-emerald-400/5 via-cyan-400/4 to-blue-400/3 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '4s' }}></div>
      </div>

      {/* INITIAL FORM */}
      {showInitialForm && !response && (
        <div className="relative">
          <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-12 sm:pt-20 pb-16 sm:pb-32">
            <div className="mb-12 sm:mb-16 animate-fadeIn text-center">
              <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-200 rounded-full px-4 sm:px-6 py-2 mb-4 sm:mb-6 backdrop-blur-sm">
                <Shield className="w-4 h-4 text-blue-600" />
                <span className="text-blue-700 text-xs sm:text-sm font-semibold">AI-Powered Security</span>
              </div>
              
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent mb-4 sm:mb-6 leading-tight tracking-tight px-4">
                Generate Secure<br />
                <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
                  IAM Policies
                </span>
              </h1>
              
              <p className="text-base sm:text-lg lg:text-xl text-slate-600 max-w-3xl mx-auto leading-relaxed font-medium px-4">
                Describe your permission needs in plain English. Our AI automatically generates 
                secure, least-privilege IAM policies following AWS best practices.
              </p>
            </div>

            <div className="max-w-4xl mx-auto">
              <form onSubmit={handleSubmit}>
                <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-xl">
                  <div className="mb-8">
                    <label className="block text-slate-900 text-lg font-bold mb-4">
                      What permissions do you need?
                    </label>
                    <textarea
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="Example: Lambda function to read from S3 bucket customer-uploads-prod and write to DynamoDB table transaction-logs..."
                      className="w-full h-40 px-6 py-5 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-2xl text-slate-900 text-base placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none resize-none transition-all duration-300 ease-out font-medium"
                      required
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-6">
                    <div className="flex items-center space-x-4 bg-gradient-to-br from-white to-slate-50 rounded-2xl p-6 border-2 border-slate-200 transition-all duration-300 hover:border-blue-300 hover:shadow-lg">
                      <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-500 rounded-xl flex items-center justify-center flex-shrink-0 shadow-lg">
                        <Lock className="w-6 h-6 text-white" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-1">
                          <input
                            id="restrictive"
                            type="checkbox"
                            checked={restrictive}
                            onChange={(e) => setRestrictive(e.target.checked)}
                            className="w-5 h-5 rounded-md border-2 border-slate-300 bg-white text-blue-600 focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 cursor-pointer transition-all hover:border-blue-400 checked:bg-blue-600 checked:border-blue-600"
                          />
                          <label htmlFor="restrictive" className="text-slate-900 text-base font-bold cursor-pointer">
                            Maximum Security
                          </label>
                        </div>
                        <p className="text-slate-600 text-sm font-medium">Least-privilege mode</p>
                      </div>
                    </div>

                    <div className="bg-gradient-to-br from-white to-slate-50 rounded-2xl p-6 border-2 border-slate-200 transition-all duration-300 hover:border-blue-300 hover:shadow-lg">
                      <label className="block text-slate-900 text-base font-bold mb-3">Compliance Framework</label>
                      <select
                        value={compliance}
                        onChange={(e) => setCompliance(e.target.value)}
                        className="w-full px-4 py-3 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl text-slate-900 text-base focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none cursor-pointer transition-all duration-300 font-medium shadow-sm"
                      >
                        {complianceFrameworks.map(framework => (
                          <option key={framework.value} value={framework.value}>
                            {framework.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {/* Optional AWS Details Section - Collapsible */}
                  <div className="mb-8">
                    <button
                      type="button"
                      onClick={() => setShowAdvancedOptions(!showAdvancedOptions)}
                      className="w-full flex items-center justify-between p-4 bg-gradient-to-br from-white/50 to-slate-50/30 rounded-xl border-2 border-slate-200 hover:border-blue-300 transition-all duration-300 group"
                    >
                      <div className="flex items-center space-x-3">
                        <ChevronDown className={`w-5 h-5 text-slate-600 transition-transform duration-300 ${showAdvancedOptions ? 'rotate-180' : ''}`} />
                        <span className="text-slate-700 text-sm font-semibold">Advanced Options</span>
                        <span className="text-slate-400 text-xs font-normal">(optional)</span>
                      </div>
                      <Info className="w-4 h-4 text-slate-400 group-hover:text-blue-600 transition-colors" />
                    </button>
                    
                    {showAdvancedOptions && (
                      <div className="mt-4 bg-gradient-to-br from-white/80 to-slate-50/50 rounded-xl p-6 border-2 border-slate-200/50">
                        <p className="text-slate-600 text-sm font-medium mb-4">
                          Provide these for more complete policies. Leave empty to use placeholders (you can refine later via chatbot).
                        </p>
                        
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                          <div>
                            <label htmlFor="awsAccountId" className="block text-slate-700 text-sm font-semibold mb-2">
                              AWS Account ID
                            </label>
                            <input
                              id="awsAccountId"
                              type="text"
                              value={awsAccountId}
                              onChange={(e) => setAwsAccountId(e.target.value)}
                              placeholder="123456789012"
                              maxLength={12}
                              pattern="[0-9]{12}"
                              className="w-full px-4 py-3 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl text-slate-900 text-base placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none transition-all duration-300 font-medium"
                            />
                            <p className="text-xs text-slate-500 mt-1 font-medium">12-digit numeric account ID</p>
                          </div>
                          
                          <div>
                            <label htmlFor="awsRegion" className="block text-slate-700 text-sm font-semibold mb-2">
                              AWS Region
                            </label>
                            <input
                              id="awsRegion"
                              type="text"
                              value={awsRegion}
                              onChange={(e) => setAwsRegion(e.target.value)}
                              placeholder="us-east-1"
                              className="w-full px-4 py-3 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl text-slate-900 text-base placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none transition-all duration-300 font-medium"
                            />
                            <p className="text-xs text-slate-500 mt-1 font-medium">e.g., us-east-1, eu-west-1</p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  <button
                    type="submit"
                    disabled={loading || !description.trim()}
                    className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white py-4 sm:py-5 px-6 sm:px-8 rounded-2xl font-bold text-base sm:text-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 ease-out shadow-lg hover:shadow-xl hover:scale-[1.02] flex items-center justify-center space-x-3 group transform touch-manipulation"
                    style={{ minHeight: '44px' }}
                  >
                    <Shield className="w-6 h-6" />
                    <span>Generate Secure Policy</span>
                    <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform duration-300" />
                  </button>
                </div>
              </form>

              {error && (
                <div className="mt-6 bg-gradient-to-r from-red-50 to-rose-50 border-2 border-red-400 rounded-2xl p-6 shadow-lg">
                  <p className="text-red-700 text-base font-semibold">{error}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* LOADING STATE - Premium Light */}
      {!showInitialForm && loading && !response && (
        <div className="relative min-h-screen flex items-center justify-center">
          <div className="text-center px-8 max-w-3xl">
            <div className="inline-flex items-center justify-center w-32 h-32 mb-10 relative">
              <div className="absolute inset-0 border-4 border-transparent border-t-blue-500 border-r-purple-500 rounded-full animate-spin"></div>
              <div className="absolute inset-2 border-4 border-transparent border-t-purple-500 border-r-pink-500 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '2s' }}></div>
              <div className="absolute inset-0 bg-gradient-to-br from-blue-500/20 via-purple-500/20 to-pink-500/20 rounded-full animate-ping"></div>
              <Shield className="w-16 h-16 text-blue-600 relative z-10 animate-pulse" />
            </div>
            
            <h2 className="text-6xl font-extrabold bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent mb-4 animate-pulse leading-tight pb-2">
              Aegis AI Analyzing
            </h2>
            
            <p className="text-2xl text-slate-700 mb-8 leading-relaxed font-semibold max-w-2xl mx-auto">
              Crafting your secure IAM policy with least-privilege principles...
            </p>
            
            <div className="flex flex-col items-center space-y-4 mb-10">
              <div className="flex items-center space-x-3 px-6 py-3 bg-white/80 backdrop-blur-xl border-2 border-blue-200 rounded-full shadow-lg">
                <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
                <span className="text-sm font-semibold text-slate-700">Analyzing AWS services...</span>
              </div>
              <div className="flex items-center space-x-3 px-6 py-3 bg-white/80 backdrop-blur-xl border-2 border-purple-200 rounded-full shadow-lg">
                <div className="w-2 h-2 bg-purple-500 rounded-full animate-pulse" style={{ animationDelay: '0.5s' }}></div>
                <span className="text-sm font-semibold text-slate-700">Calculating security scores...</span>
              </div>
              <div className="flex items-center space-x-3 px-6 py-3 bg-white/80 backdrop-blur-xl border-2 border-pink-200 rounded-full shadow-lg">
                <div className="w-2 h-2 bg-pink-500 rounded-full animate-pulse" style={{ animationDelay: '1s' }}></div>
                <span className="text-sm font-semibold text-slate-700">Generating policies...</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* LOADING STATE AFTER MORE INFO PAGE - Premium Light Theme */}
      {!showInitialForm && loading && response && response.is_question && !isRefining && (
        <div className="relative min-h-screen flex items-center justify-center">
          <div className="text-center px-8 max-w-3xl">
            <div className="inline-flex items-center justify-center w-32 h-32 mb-10 relative">
              <div className="absolute inset-0 border-4 border-transparent border-t-purple-500 border-r-pink-500 rounded-full animate-spin"></div>
              <div className="absolute inset-2 border-4 border-transparent border-t-pink-500 border-r-orange-500 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '2s' }}></div>
              <div className="absolute inset-0 bg-gradient-to-br from-purple-500/20 via-pink-500/20 to-orange-500/20 rounded-full animate-ping"></div>
              <Shield className="w-16 h-16 text-purple-600 relative z-10 animate-pulse" />
            </div>
            
            <h2 className="text-6xl font-extrabold bg-gradient-to-r from-purple-600 via-pink-600 to-orange-600 bg-clip-text text-transparent mb-4 animate-pulse leading-tight pb-2">
              Aegis AI Analyzing
            </h2>
            
            <p className="text-2xl text-slate-700 mb-8 leading-relaxed font-semibold max-w-2xl mx-auto">
              Crafting your secure IAM policy with least-privilege principles...
            </p>
            
            <div className="flex flex-col items-center space-y-4 mb-10">
              <div className="flex items-center space-x-3 px-6 py-3 bg-white/80 backdrop-blur-xl border-2 border-purple-200 rounded-full shadow-lg">
                <div className="w-2 h-2 bg-purple-500 rounded-full animate-pulse"></div>
                <span className="text-sm font-semibold text-slate-700">Analyzing AWS services...</span>
              </div>
              <div className="flex items-center space-x-3 px-6 py-3 bg-white/80 backdrop-blur-xl border-2 border-pink-200 rounded-full shadow-lg">
                <div className="w-2 h-2 bg-pink-500 rounded-full animate-pulse" style={{ animationDelay: '0.5s' }}></div>
                <span className="text-sm font-semibold text-slate-700">Calculating security scores...</span>
              </div>
              <div className="flex items-center space-x-3 px-6 py-3 bg-white/80 backdrop-blur-xl border-2 border-orange-200 rounded-full shadow-lg">
                <div className="w-2 h-2 bg-orange-500 rounded-full animate-pulse" style={{ animationDelay: '1s' }}></div>
                <span className="text-sm font-semibold text-slate-700">Generating policies...</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MORE INFORMATION NEEDED PAGE - Premium Light Theme */}
      {!showInitialForm && !loading && response && response.is_question && (
        <div className="relative min-h-screen">
          <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
            <div className="text-center mb-12">
              <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-orange-500/20 to-pink-500/20 rounded-2xl mb-6 border-2 border-orange-300/50 backdrop-blur-xl shadow-lg">
                <AlertCircle className="w-10 h-10 text-orange-600" />
              </div>
              
              <h2 className="text-4xl sm:text-5xl font-black bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent mb-4">
                Just a Few More Details
              </h2>
              
              <p className="text-lg text-slate-600 font-medium">
                To generate the most secure policy, I need some additional information
              </p>
            </div>

            <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 mb-6 shadow-xl">
              <div className="text-slate-700 leading-relaxed whitespace-pre-wrap text-base font-medium">
                {cleanMarkdown(response?.explanation || response?.final_answer || 'No additional information needed.')}
              </div>
            </div>

            <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 mb-6 shadow-xl">
              <form onSubmit={handleFollowUp}>
                <label className="block text-slate-900 font-bold text-lg mb-4">
                  Your Response
                </label>
                <textarea
                  value={followUpMessage}
                  onChange={(e) => setFollowUpMessage(e.target.value)}
                  placeholder="Provide the requested information..."
                  className="w-full h-32 px-6 py-4 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl text-slate-900 placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none resize-none mb-4 transition-all duration-300 font-medium"
                  disabled={loading}
                />
                <button
                  type="submit"
                  disabled={loading || !followUpMessage.trim()}
                  className="w-full bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white py-4 px-6 rounded-xl font-bold disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-xl hover:shadow-2xl flex items-center justify-center space-x-2 hover:scale-[1.02]"
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
              className="w-full px-6 py-4 bg-white/80 backdrop-blur-xl hover:bg-white/90 border-2 border-slate-200 hover:border-slate-300 text-slate-700 hover:text-slate-900 rounded-2xl transition-all duration-300 flex items-center justify-center space-x-2 shadow-lg hover:shadow-xl font-semibold"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Start Over</span>
            </button>
          </div>
        </div>
      )}

      {/* RESULTS DISPLAY */}
      {!showInitialForm && response && hasContent && (
        <div className="relative min-h-screen">
          <div className="relative max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
            {/* HEADER - Matching Audit Account Design Exactly */}
            <div className="mb-16 animate-fadeIn">
              {/* Security Assessment Complete Badge - No Icon */}
              <div className="text-center mb-6">
                <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-200 rounded-full px-4 py-1.5 backdrop-blur-sm">
                  <span className="text-blue-700 text-sm font-semibold">Security Assessment Complete</span>
                </div>
              </div>

              {/* Main Heading - Fixed Text Cutoff with Proper Line Height */}
              <div className="text-center mb-8">
                <h2 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent mb-4 tracking-tight text-center" style={{ lineHeight: '1.15', letterSpacing: '-0.02em' }}>
                  {hasPolicy ? 'Policies Generated Successfully' : 'Policy Explanation'}
                </h2>
                
                {/* Gradient underline */}
                <div className="w-32 h-1.5 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 mx-auto rounded-full mb-12 shadow-lg"></div>
                
                <p className="text-slate-600 text-base sm:text-lg max-w-2xl mx-auto leading-relaxed mb-6 font-medium">
                  {hasPolicy 
                    ? <>Review your IAM policies below. Use the <span className="text-blue-600 font-semibold">Aegis AI chatbot</span> to refine them before deployment.</>
                    : <>Explanation of your IAM policies. Use the <span className="text-blue-600 font-semibold">Aegis AI chatbot</span> to ask questions or make refinements.</>
                  }
                </p>
                
                {hasPolicy && (
                  <div className="flex items-center justify-center gap-3 mb-8">
                    <div className="flex items-center space-x-2 px-4 py-2 bg-blue-500/10 border-2 border-blue-200/50 rounded-full backdrop-blur-xl">
                      <CheckCircle className="w-4 h-4 text-blue-600" />
                      <span className="text-xs sm:text-sm text-blue-700 font-semibold">Permissions Policy</span>
                    </div>
                    <div className="flex items-center space-x-2 px-4 py-2 bg-purple-500/10 border-2 border-purple-200/50 rounded-full backdrop-blur-xl">
                      <CheckCircle className="w-4 h-4 text-purple-600" />
                      <span className="text-xs sm:text-sm text-purple-700 font-semibold">Trust Policy</span>
                    </div>
                  </div>
                )}
              </div>
              
              <div className="flex justify-center">
                <button
                  onClick={handleNewConversation}
                  className="group relative px-6 py-3 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white font-bold rounded-xl transition-all duration-300 shadow-xl hover:shadow-2xl hover:scale-105 flex items-center space-x-2"
                >
                  <RefreshCw className="w-4 h-4 group-hover:rotate-180 transition-transform duration-500" />
                  <span>Generate New Policy</span>
                </button>
              </div>
            </div>

            {/* EXPLANATION SECTION - Show when there's an explanation but no policy */}
            {!hasPolicy && (response?.final_answer || response?.explanation) && (
              <div className="mb-16 animate-fadeIn">
                <div className="mb-6">
                  <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                    <Info className="w-7 h-7 text-blue-600" />
                    <span>Explanation</span>
                  </h3>
                  <p className="text-slate-600 text-sm font-medium">AI-generated explanation of your policies</p>
                </div>
                
                <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 shadow-xl">
                  <div className="text-slate-700 leading-relaxed whitespace-pre-wrap text-base font-medium">
                    {cleanMarkdown(response?.final_answer || response?.explanation || '')}
                  </div>
                </div>
              </div>
            )}

            {/* SECURITY SCORES SECTION - Premium Light Theme with Subsection Header */}
            <div className="mb-16 animate-fadeIn" style={{ animationDelay: '0.1s' }}>
              {/* Premium Section Header - Matching Audit Account */}
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                    <Shield className="w-7 h-7 text-blue-600" />
                    <span>Security Scores</span>
                  </h3>
                  <p className="text-slate-600 text-sm font-medium">Policy security assessment</p>
                </div>
                <button
                  onClick={() => setShowScoreBreakdown(!showScoreBreakdown)}
                  className="group flex items-center space-x-2 px-4 py-2 bg-white/80 backdrop-blur-xl hover:bg-white/90 border-2 border-slate-200 hover:border-blue-300 rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl"
                >
                  <span className="text-sm font-semibold text-slate-700 group-hover:text-blue-600 transition-colors duration-300">
                    {showScoreBreakdown ? 'Hide Details' : 'Show Details'}
                  </span>
                  {showScoreBreakdown ? (
                    <ChevronUp className="w-4 h-4 text-slate-500 group-hover:text-blue-600 transition-colors duration-300" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-slate-500 group-hover:text-blue-600 transition-colors duration-300" />
                  )}
                </button>
              </div>

              {/* Quick Stats Dashboard Widget */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                <div className="bg-gradient-to-br from-blue-50 to-purple-50 border-2 border-blue-200/50 rounded-xl p-5 shadow-lg">
                  <div className="flex items-center justify-between mb-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-lg flex items-center justify-center shadow-md">
                      <Shield className="w-5 h-5 text-white" />
                    </div>
                    <span className="text-xs font-semibold text-slate-600 uppercase tracking-wider">Overall</span>
                  </div>
                  <div className="text-3xl font-black bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent mb-1">
                    {Math.round((permissionsScore + trustScore) / 2)}
                  </div>
                  <div className="text-xs text-slate-600 font-medium">Average Security Score</div>
                </div>
                
                <div className="bg-gradient-to-br from-emerald-50 to-green-50 border-2 border-emerald-200/50 rounded-xl p-5 shadow-lg">
                  <div className="flex items-center justify-between mb-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-emerald-500 to-green-500 rounded-lg flex items-center justify-center shadow-md">
                      <CheckCircle className="w-5 h-5 text-white" />
                    </div>
                    <span className="text-xs font-semibold text-slate-600 uppercase tracking-wider">Strengths</span>
                  </div>
                  <div className="text-3xl font-black bg-gradient-to-r from-emerald-600 to-green-600 bg-clip-text text-transparent mb-1">
                    {(response.score_breakdown?.permissions?.positive?.length || 0) + (response.score_breakdown?.trust?.positive?.length || 0)}
                  </div>
                  <div className="text-xs text-slate-600 font-medium">Security Features</div>
                </div>
                
                <div className="bg-gradient-to-br from-amber-50 to-orange-50 border-2 border-amber-200/50 rounded-xl p-5 shadow-lg">
                  <div className="flex items-center justify-between mb-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-amber-500 to-orange-500 rounded-lg flex items-center justify-center shadow-md">
                      <Target className="w-5 h-5 text-white" />
                    </div>
                    <span className="text-xs font-semibold text-slate-600 uppercase tracking-wider">Actions</span>
                  </div>
                  <div className="text-3xl font-black bg-gradient-to-r from-amber-600 to-orange-600 bg-clip-text text-transparent mb-1">
                    {(response.score_breakdown?.permissions?.improvements?.length || 0) + (response.score_breakdown?.trust?.improvements?.length || 0)}
                  </div>
                  <div className="text-xs text-slate-600 font-medium">Recommendations</div>
                </div>
              </div>

              {/* Score Cards Grid - Premium Light Theme */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Permissions Policy Score Card */}
                <div className="relative bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1 overflow-hidden">
                  {/* Gradient accent bar at top */}
                  <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 shadow-lg"></div>
                  <h3 className="text-blue-600 text-sm font-bold uppercase tracking-wider mb-6">Permissions Policy</h3>
                
                <div className="flex items-end justify-between mb-6">
                  <div 
                    className="text-6xl font-black"
                    style={{
                      background: permissionsScore >= 80 
                        ? 'linear-gradient(135deg, #10b981, #3b82f6)' 
                        : permissionsScore >= 60
                        ? 'linear-gradient(135deg, #3b82f6, #8b5cf6)'
                        : permissionsScore >= 40
                        ? 'linear-gradient(135deg, #f59e0b, #f97316)'
                        : 'linear-gradient(135deg, #ef4444, #ec4899)',
                      WebkitBackgroundClip: 'text',
                      WebkitTextFillColor: 'transparent',
                      backgroundClip: 'text'
                    }}
                  >
                    {permissionsScore}
                  </div>
                  <div className="text-slate-400 text-xl font-medium">/100</div>
                </div>
                
                <div className="w-full bg-white/60 backdrop-blur-sm rounded-full h-3 mb-6 overflow-hidden border border-slate-200 shadow-inner">
                  <div
                    className={`h-3 rounded-full transition-all duration-1000 ease-out shadow-md ${
                      permissionsScore >= 80 
                        ? 'bg-gradient-to-r from-green-500 to-blue-500'
                        : permissionsScore >= 60
                        ? 'bg-gradient-to-r from-blue-500 to-purple-500'
                        : permissionsScore >= 40
                        ? 'bg-gradient-to-r from-orange-500 to-pink-500'
                        : 'bg-gradient-to-r from-red-500 to-pink-500'
                    }`}
                    style={{ width: `${permissionsScore}%` }}
                  ></div>
                </div>
                
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-600 font-medium">Security Grade</span>
                    <span 
                      className="text-3xl font-black"
                      style={{
                        background: permissionsScore >= 80 
                          ? 'linear-gradient(135deg, #10b981, #3b82f6)' 
                          : permissionsScore >= 60
                          ? 'linear-gradient(135deg, #3b82f6, #8b5cf6)'
                          : permissionsScore >= 40
                          ? 'linear-gradient(135deg, #f59e0b, #f97316)'
                          : 'linear-gradient(135deg, #ef4444, #ec4899)',
                        WebkitBackgroundClip: 'text',
                        WebkitTextFillColor: 'transparent',
                        backgroundClip: 'text'
                      }}
                    >
                      {permissionsScore >= 90 ? 'A' : permissionsScore >= 80 ? 'B' : permissionsScore >= 70 ? 'C' : permissionsScore >= 60 ? 'D' : 'F'}
                    </span>
                  </div>

                  {/* Collapsible Breakdown - Premium Enhanced */}
                  {showScoreBreakdown && (
                  <div className="mt-6 pt-6 border-t border-slate-200/50 space-y-6 animate-in slide-in-from-top duration-300">
                    {response.score_breakdown?.permissions?.positive?.length > 0 && (
                      <div className="bg-gradient-to-br from-emerald-50 via-green-50 to-teal-50 border-2 border-emerald-200/50 rounded-xl p-6 shadow-lg">
                        <div className="flex items-center space-x-3 mb-5">
                          <div className="w-10 h-10 bg-gradient-to-br from-emerald-500 to-green-500 rounded-lg flex items-center justify-center shadow-md">
                            <CheckCircle className="w-6 h-6 text-white" />
                          </div>
                          <div>
                            <h4 className="text-lg font-bold bg-gradient-to-r from-emerald-600 to-green-600 bg-clip-text text-transparent">
                              Strengths
                            </h4>
                            <p className="text-xs text-slate-600 font-medium">{response.score_breakdown.permissions.positive.length} security features</p>
                          </div>
                        </div>
                        <ul className="space-y-3">
                          {response.score_breakdown.permissions.positive.map((item, idx) => (
                            <li key={idx} className="bg-white/80 backdrop-blur-sm border border-emerald-200/50 rounded-lg p-3 flex items-start space-x-3 shadow-sm hover:shadow-md transition-all">
                              <div className="flex-shrink-0 w-6 h-6 bg-gradient-to-br from-emerald-400 to-green-400 rounded-full flex items-center justify-center mt-0.5">
                                <CheckCircle className="w-4 h-4 text-white" />
                              </div>
                              <span className="text-sm text-slate-700 leading-relaxed font-medium flex-1">{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    {response.score_breakdown?.permissions?.improvements?.length > 0 && (
                      <div className="bg-gradient-to-br from-amber-50 via-orange-50 to-yellow-50 border-2 border-amber-200/50 rounded-xl p-6 shadow-lg">
                        <div className="flex items-center space-x-3 mb-5">
                          <div className="w-10 h-10 bg-gradient-to-br from-amber-500 to-orange-500 rounded-lg flex items-center justify-center shadow-md">
                            <Target className="w-6 h-6 text-white" />
                          </div>
                          <div>
                            <h4 className="text-lg font-bold bg-gradient-to-r from-amber-600 to-orange-600 bg-clip-text text-transparent">
                              Room for Improvement
                            </h4>
                            <p className="text-xs text-slate-600 font-medium">{response.score_breakdown.permissions.improvements.length} recommendations</p>
                          </div>
                        </div>
                        <ul className="space-y-3">
                          {response.score_breakdown.permissions.improvements.map((item, idx) => (
                            <li key={idx} className="bg-white/80 backdrop-blur-sm border border-amber-200/50 rounded-lg p-3 flex items-start space-x-3 shadow-sm hover:shadow-md transition-all">
                              <div className="flex-shrink-0 w-6 h-6 bg-gradient-to-br from-amber-400 to-orange-400 rounded-full flex items-center justify-center mt-0.5">
                                <Target className="w-4 h-4 text-white" />
                              </div>
                              <span className="text-sm text-slate-700 leading-relaxed font-medium flex-1">{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                  )}
                </div>

                {/* Trust Policy Score Card */}
                <div className="relative bg-white/80 backdrop-blur-xl border-2 border-purple-200/50 rounded-2xl p-8 shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1 overflow-hidden">
                  {/* Gradient accent bar at top */}
                  <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 shadow-lg"></div>
                  <h3 className="text-purple-600 text-sm font-bold uppercase tracking-wider mb-6">Trust Policy</h3>
                
                <div className="flex items-end justify-between mb-6">
                  <div 
                    className="text-6xl font-black"
                    style={{
                      background: trustScore >= 80 
                        ? 'linear-gradient(135deg, #10b981, #3b82f6)' 
                        : trustScore >= 60
                        ? 'linear-gradient(135deg, #3b82f6, #8b5cf6)'
                        : trustScore >= 40
                        ? 'linear-gradient(135deg, #f59e0b, #f97316)'
                        : 'linear-gradient(135deg, #ef4444, #ec4899)',
                      WebkitBackgroundClip: 'text',
                      WebkitTextFillColor: 'transparent',
                      backgroundClip: 'text'
                    }}
                  >
                    {trustScore}
                  </div>
                  <div className="text-slate-400 text-xl font-medium">/100</div>
                </div>
                
                <div className="w-full bg-white/60 backdrop-blur-sm rounded-full h-3 mb-6 overflow-hidden border border-slate-200 shadow-inner">
                  <div
                    className={`h-3 rounded-full transition-all duration-1000 ease-out shadow-md ${
                      trustScore >= 80 
                        ? 'bg-gradient-to-r from-green-500 to-blue-500'
                        : trustScore >= 60
                        ? 'bg-gradient-to-r from-blue-500 to-purple-500'
                        : trustScore >= 40
                        ? 'bg-gradient-to-r from-orange-500 to-pink-500'
                        : 'bg-gradient-to-r from-red-500 to-pink-500'
                    }`}
                    style={{ width: `${trustScore}%` }}
                  ></div>
                </div>
                
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-600 font-medium">Security Grade</span>
                    <span 
                      className="text-3xl font-black"
                      style={{
                        background: trustScore >= 80 
                          ? 'linear-gradient(135deg, #10b981, #3b82f6)' 
                          : trustScore >= 60
                          ? 'linear-gradient(135deg, #3b82f6, #8b5cf6)'
                          : trustScore >= 40
                          ? 'linear-gradient(135deg, #f59e0b, #f97316)'
                          : 'linear-gradient(135deg, #ef4444, #ec4899)',
                        WebkitBackgroundClip: 'text',
                        WebkitTextFillColor: 'transparent',
                        backgroundClip: 'text'
                      }}
                    >
                      {trustScore >= 90 ? 'A' : trustScore >= 80 ? 'B' : trustScore >= 70 ? 'C' : trustScore >= 60 ? 'D' : 'F'}
                    </span>
                  </div>

                  {/* Collapsible Breakdown - Premium Enhanced */}
                  {showScoreBreakdown && (
                  <div className="mt-6 pt-6 border-t border-slate-200/50 space-y-6 animate-in slide-in-from-top duration-300">
                    {response.score_breakdown?.trust?.positive?.length > 0 && (
                      <div className="bg-gradient-to-br from-emerald-50 via-green-50 to-teal-50 border-2 border-emerald-200/50 rounded-xl p-6 shadow-lg">
                        <div className="flex items-center space-x-3 mb-5">
                          <div className="w-10 h-10 bg-gradient-to-br from-emerald-500 to-green-500 rounded-lg flex items-center justify-center shadow-md">
                            <CheckCircle className="w-6 h-6 text-white" />
                          </div>
                          <div>
                            <h4 className="text-lg font-bold bg-gradient-to-r from-emerald-600 to-green-600 bg-clip-text text-transparent">
                              Strengths
                            </h4>
                            <p className="text-xs text-slate-600 font-medium">{response.score_breakdown.trust.positive.length} security features</p>
                          </div>
                        </div>
                        <ul className="space-y-3">
                          {response.score_breakdown.trust.positive.map((item, idx) => (
                            <li key={idx} className="bg-white/80 backdrop-blur-sm border border-emerald-200/50 rounded-lg p-3 flex items-start space-x-3 shadow-sm hover:shadow-md transition-all">
                              <div className="flex-shrink-0 w-6 h-6 bg-gradient-to-br from-emerald-400 to-green-400 rounded-full flex items-center justify-center mt-0.5">
                                <CheckCircle className="w-4 h-4 text-white" />
                              </div>
                              <span className="text-sm text-slate-700 leading-relaxed font-medium flex-1">{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    {response.score_breakdown?.trust?.improvements?.length > 0 && (
                      <div className="bg-gradient-to-br from-amber-50 via-orange-50 to-yellow-50 border-2 border-amber-200/50 rounded-xl p-6 shadow-lg">
                        <div className="flex items-center space-x-3 mb-5">
                          <div className="w-10 h-10 bg-gradient-to-br from-amber-500 to-orange-500 rounded-lg flex items-center justify-center shadow-md">
                            <Target className="w-6 h-6 text-white" />
                          </div>
                          <div>
                            <h4 className="text-lg font-bold bg-gradient-to-r from-amber-600 to-orange-600 bg-clip-text text-transparent">
                              Room for Improvement
                            </h4>
                            <p className="text-xs text-slate-600 font-medium">{response.score_breakdown.trust.improvements.length} recommendations</p>
                          </div>
                        </div>
                        <ul className="space-y-3">
                          {response.score_breakdown.trust.improvements.map((item, idx) => (
                            <li key={idx} className="bg-white/80 backdrop-blur-sm border border-amber-200/50 rounded-lg p-3 flex items-start space-x-3 shadow-sm hover:shadow-md transition-all">
                              <div className="flex-shrink-0 w-6 h-6 bg-gradient-to-br from-amber-400 to-orange-400 rounded-full flex items-center justify-center mt-0.5">
                                <Target className="w-4 h-4 text-white" />
                              </div>
                              <span className="text-sm text-slate-700 leading-relaxed font-medium flex-1">{item}</span>
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

            {/* POLICIES SECTION - Premium Subsection Design */}
            <div className="space-y-16 animate-fadeIn" style={{ animationDelay: '0.2s' }}>
              {/* PERMISSIONS POLICY */}
              <div>
                {/* Premium Subsection Header */}
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                      <Shield className="w-8 h-8 text-blue-600" />
                      <span>Permissions Policy</span>
                    </h3>
                    <p className="text-slate-600 text-sm font-medium">IAM permissions configuration</p>
                  </div>
                  <button
                    onClick={() => setShowPermissionsPolicy(!showPermissionsPolicy)}
                    className="group flex items-center space-x-2 px-4 py-2 bg-white/80 backdrop-blur-xl hover:bg-white/90 border-2 border-slate-200 hover:border-blue-300 rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl"
                  >
                    <span className="text-sm font-semibold text-slate-700 group-hover:text-blue-600 transition-colors duration-300">
                      {showPermissionsPolicy ? 'Hide' : 'Show'}
                    </span>
                    {showPermissionsPolicy ? (
                      <ChevronUp className="w-4 h-4 text-slate-500 group-hover:text-blue-600 transition-colors duration-300" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-500 group-hover:text-blue-600 transition-colors duration-300" />
                    )}
                  </button>
                </div>

                {showPermissionsPolicy && (
                <>
                <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl transition-all duration-300">
                  <div className="bg-gradient-to-r from-slate-50 to-white px-6 py-4 flex items-center justify-between border-b-2 border-slate-200/50">
                    <div className="flex items-center space-x-3">
                      <div className="flex space-x-2">
                        <div className="w-3 h-3 rounded-full bg-red-500"></div>
                        <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                        <div className="w-3 h-3 rounded-full bg-green-500"></div>
                      </div>
                      <span className="text-slate-600 text-sm font-mono font-semibold">permissions-policy.json</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={handleCopyPolicy}
                        className="group relative px-4 py-2 bg-white/80 hover:bg-white border-2 border-slate-200 hover:border-blue-300 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 shadow-sm hover:shadow-md"
                      >
                        <Copy className="w-4 h-4 text-slate-600 group-hover:text-blue-600 transition-colors duration-300" />
                        <span className="text-sm font-medium text-slate-700 group-hover:text-blue-600 transition-colors duration-300">
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
                        className="group relative px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 border border-blue-500/50 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 shadow-lg hover:shadow-xl"
                      >
                        <Download className="w-4 h-4 text-white transition-transform duration-300 group-hover:translate-y-0.5" />
                        <span className="text-sm font-medium text-white">Download</span>
                      </button>
                    </div>
                  </div>

                  <div className="p-6 overflow-x-auto bg-slate-50/50">
                    <pre className="text-sm font-mono text-slate-800 leading-relaxed">
                      {JSON.stringify(response.policy, null, 2)}
                    </pre>
                  </div>
                </div>

                  {/* About Permissions Policy - Enhanced Premium Subsection */}
                  <div className="mt-6">
                    <div className="bg-gradient-to-r from-blue-50 via-purple-50 to-pink-50 border-2 border-blue-200/50 rounded-xl p-5 shadow-lg">
                      <div className="flex items-start space-x-3">
                        <div className="flex-shrink-0 w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-lg flex items-center justify-center shadow-md">
                          <Info className="w-5 h-5 text-white" />
                        </div>
                        <div className="flex-1">
                          <div className="text-base font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent mb-2">
                            About Permissions Policy
                          </div>
                          <p className="text-sm text-slate-700 leading-relaxed font-medium">
                            The Permissions Policy defines <strong className="text-blue-600">WHAT</strong> actions this IAM role can perform on AWS resources. 
                            It specifies the exact services, actions, and resources that are allowed or denied.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>

                {response.explanation && (
                  <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 mt-6 shadow-xl">
                    {/* Premium Subsection Header */}
                    <div className="mb-6">
                      <h4 className="text-2xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                        <Shield className="w-6 h-6 text-blue-600" />
                        <span>What These Permissions Do</span>
                      </h4>
                      <p className="text-slate-600 text-sm font-medium">Breakdown of each permission statement</p>
                    </div>
                    
                    <div className="grid grid-cols-1 gap-4">
                      {parseExplanation(response.explanation).map((section: any, index) => (
                        <div key={index} className="bg-gradient-to-br from-white to-slate-50 rounded-xl p-5 border-2 border-slate-200/50 transition-all duration-300 hover:border-blue-300 hover:shadow-lg">
                          <div>
                            <div className="flex items-start space-x-3 mb-3">
                              <div className="text-3xl">{getServiceIcon(section.title)}</div>
                              <div className="flex-1">
                                <div className="text-xs text-slate-500 mb-2 font-bold uppercase tracking-wider">STATEMENT {section.num}</div>
                                <h5 className="text-slate-900 font-bold text-base">{stripMarkdown(section.title)}</h5>
                              </div>
                            </div>
                          
                          <div className="space-y-2">
                            {section.details.Permission && (
                              <div className="bg-slate-100 rounded-lg p-3 border border-slate-200">
                                <div className="text-sm text-slate-800 font-mono">
                                  {section.details.Permission}
                                </div>
                              </div>
                            )}
                            
                            {section.details.Purpose && (
                              <div className="text-sm text-slate-700 leading-relaxed font-medium">
                                <span className="font-bold text-slate-600">Purpose:</span> {stripMarkdown(section.details.Purpose)}
                              </div>
                            )}
                            
                            {section.details.Security && (
                              <div className="flex items-start space-x-2 bg-green-50 border-2 border-green-200 rounded-lg p-2">
                                <CheckCircle className="w-4 h-4 text-green-600 mt-0.5 flex-shrink-0" />
                                <div className="text-xs text-green-700 font-medium">
                                  {section.details.Security}
                                </div>
                              </div>
                            )}
                          </div>
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
                <div>
                  {/* Premium Subsection Header */}
                  <div className="flex items-center justify-between mb-6">
                    <div>
                      <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                        <CheckCircle className="w-8 h-8 text-purple-600" />
                        <span>Trust Policy</span>
                      </h3>
                      <p className="text-slate-600 text-sm font-medium">IAM role trust relationship</p>
                    </div>
                    <button
                      onClick={() => setShowTrustPolicy(!showTrustPolicy)}
                      className="group flex items-center space-x-2 px-4 py-2 bg-white/80 backdrop-blur-xl hover:bg-white/90 border-2 border-slate-200 hover:border-purple-300 rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl"
                    >
                      <span className="text-sm font-semibold text-slate-700 group-hover:text-purple-600 transition-colors duration-300">
                        {showTrustPolicy ? 'Hide' : 'Show'}
                      </span>
                      {showTrustPolicy ? (
                        <ChevronUp className="w-4 h-4 text-slate-500 group-hover:text-purple-600 transition-colors duration-300" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500 group-hover:text-purple-600 transition-colors duration-300" />
                      )}
                    </button>
                  </div>

                  {showTrustPolicy && (
                  <>
                  <div className="bg-white/80 backdrop-blur-xl border-2 border-purple-200/50 rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl transition-all duration-300">
                    <div className="bg-gradient-to-r from-slate-50 to-white px-6 py-4 flex items-center justify-between border-b-2 border-slate-200/50">
                      <div className="flex items-center space-x-3">
                        <div className="flex space-x-2">
                          <div className="w-3 h-3 rounded-full bg-red-500"></div>
                          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                          <div className="w-3 h-3 rounded-full bg-green-500"></div>
                        </div>
                        <span className="text-slate-600 text-sm font-mono font-semibold">trust-policy.json</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={handleCopyTrustPolicy}
                          className="group relative px-4 py-2 bg-white/80 hover:bg-white border-2 border-slate-200 hover:border-purple-300 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 shadow-sm hover:shadow-md"
                        >
                          <Copy className="w-4 h-4 text-slate-600 group-hover:text-purple-600 transition-colors duration-300" />
                          <span className="text-sm font-medium text-slate-700 group-hover:text-purple-600 transition-colors duration-300">
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
                          className="group relative px-4 py-2 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 border border-purple-500/50 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 shadow-lg hover:shadow-xl"
                        >
                          <Download className="w-4 h-4 text-white transition-transform duration-300 group-hover:translate-y-0.5" />
                          <span className="text-sm font-medium text-white">Download</span>
                        </button>
                      </div>
                    </div>

                    <div className="p-6 overflow-x-auto bg-slate-50/50">
                      <pre className="text-sm font-mono text-slate-800 leading-relaxed">
                        {JSON.stringify(response.trust_policy, null, 2)}
                      </pre>
                    </div>
                  </div>

                  {/* About Trust Policy - Enhanced Premium Subsection */}
                  <div className="mt-6">
                    <div className="bg-gradient-to-r from-purple-50 via-pink-50 to-orange-50 border-2 border-purple-200/50 rounded-xl p-5 shadow-lg">
                      <div className="flex items-start space-x-3">
                        <div className="flex-shrink-0 w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center shadow-md">
                          <Info className="w-5 h-5 text-white" />
                        </div>
                        <div className="flex-1">
                          <div className="text-base font-bold bg-gradient-to-r from-purple-600 to-pink-600 bg-clip-text text-transparent mb-2">
                            About Trust Policy
                          </div>
                          <p className="text-sm text-slate-700 leading-relaxed font-medium">
                            The Trust Policy defines <strong className="text-purple-600">WHO</strong> can assume this IAM role. Without it, 
                            nobody (not even AWS services) can use the permissions policy above.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {response.trust_explanation && (
                    <div className="bg-white/80 backdrop-blur-xl border-2 border-purple-200/50 rounded-2xl p-8 mt-6 shadow-xl">
                      {/* Premium Subsection Header */}
                      <div className="mb-6">
                        <h4 className="text-2xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                          <Shield className="w-6 h-6 text-purple-600" />
                          <span>What This Trust Policy Does</span>
                        </h4>
                        <p className="text-slate-600 text-sm font-medium">Who can assume this role and under what conditions</p>
                      </div>
                      
                      <div className="bg-gradient-to-br from-white to-slate-50 rounded-xl p-5 border-2 border-slate-200/50">
                        <div className="space-y-4">
                          <div>
                            <div className="text-xs text-slate-500 mb-2 uppercase tracking-wide font-bold">Trusted Entity</div>
                            <div className="bg-slate-100 rounded-lg p-3 border border-slate-200">
                              <div className="text-sm text-slate-800 font-mono">
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
                                
                                // Skip redundant "Trusted Entity" repetition
                                if (title && title.toLowerCase().includes('trusted entity')) {
                                  return null;
                                }
                                
                                return (
                                  <div key={idx} className="bg-slate-100 rounded-lg p-4 border border-slate-200">
                                    <div>
                                      {title && (
                                        <h5 className="text-slate-900 font-bold text-sm mb-2">{stripMarkdown(title)}</h5>
                                      )}
                                      {details.map((detail, dIdx) => (
                                        detail.trim() && (
                                          <p key={dIdx} className="text-sm text-slate-700 leading-relaxed mb-1 font-medium">
                                            {stripMarkdown(detail.trim())}
                                          </p>
                                        )
                                      ))}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                          
                          <div className="flex items-start space-x-2 bg-green-50 border-2 border-green-200 rounded-lg p-3">
                            <CheckCircle className="w-4 h-4 text-green-600 mt-0.5 flex-shrink-0" />
                            <div className="text-xs text-green-700 font-medium">
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

              {/* PERMISSIONS POLICY REFINEMENT SUGGESTIONS - Premium Subsection */}
              {response?.refinement_suggestions?.permissions?.length > 0 && (
                <div className="animate-fadeIn" style={{ animationDelay: '0.3s' }}>
                  {/* Premium Subsection Header */}
                  <div className="flex items-center justify-between mb-6">
                    <div>
                      <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                        <Sparkles className="w-7 h-7 text-blue-600" />
                        <span>Permissions Policy Refinements</span>
                      </h3>
                      <p className="text-slate-600 text-sm font-medium">AI-powered improvement suggestions</p>
                    </div>
                    <button
                      onClick={() => setShowPermissionsSuggestions(!showPermissionsSuggestions)}
                      className="group flex items-center space-x-2 px-4 py-2 bg-white/80 backdrop-blur-xl hover:bg-white/90 border-2 border-slate-200 hover:border-blue-300 rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl"
                    >
                      <span className="text-sm font-semibold text-slate-700 group-hover:text-blue-600 transition-colors duration-300">
                        {showPermissionsSuggestions ? 'Hide' : 'Show'}
                      </span>
                      {showPermissionsSuggestions ? (
                        <ChevronUp className="w-4 h-4 text-slate-500 group-hover:text-blue-600 transition-colors duration-300" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500 group-hover:text-blue-600 transition-colors duration-300" />
                      )}
                    </button>
                  </div>

                  {/* Content Card */}
                  {showPermissionsSuggestions && (
                  <div className="relative bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 shadow-xl hover:shadow-2xl transition-all duration-500">
                      {/* Pro Tip - Enhanced Premium */}
                      <div className="bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-pink-500/10 border-2 border-blue-200/50 rounded-xl p-5 mb-6 shadow-lg">
                        <div className="flex items-center space-x-3">
                          <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-lg flex items-center justify-center shadow-md flex-shrink-0">
                            <Lightbulb className="w-5 h-5 text-white" />
                          </div>
                          <div className="flex-1">
                            <p className="text-slate-700 text-sm leading-relaxed font-medium">
                              <strong className="bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">Pro Tip:</strong> Click any suggestion below to automatically implement it via the chatbot
                            </p>
                          </div>
                        </div>
                      </div>
                      
                      <div className="grid grid-cols-1 gap-4">
                        {response.refinement_suggestions.permissions.map((suggestion, idx) => (
                          <button
                            key={idx}
                            onClick={() => {
                              setFollowUpMessage(suggestion);
                              setIsChatbotOpen(true);
                            }}
                            className="group relative px-6 py-5 bg-gradient-to-br from-white to-slate-50/50 hover:from-white hover:to-blue-50/30 border-2 border-slate-200 hover:border-blue-300 rounded-xl text-left transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-[1.02] overflow-hidden"
                          >
                            <div className="relative flex items-center space-x-4">
                              <div className="flex-shrink-0 w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-500 rounded-lg flex items-center justify-center shadow-md group-hover:scale-110 group-hover:rotate-3 transition-all duration-300">
                                <FileCheck className="w-6 h-6 text-white" />
                              </div>
                              <div className="flex-1">
                                <p className="text-slate-700 group-hover:text-slate-900 font-medium transition-colors duration-300 leading-relaxed">
                                  {suggestion}
                                </p>
                              </div>
                              <ArrowRight className="w-5 h-5 text-slate-400 group-hover:text-blue-600 opacity-0 group-hover:opacity-100 transition-all duration-300 transform group-hover:translate-x-1 flex-shrink-0" />
                            </div>
                          </button>
                        ))}
                      </div>
                  </div>
                  )}
                </div>
              )}

              {/* TRUST POLICY REFINEMENT SUGGESTIONS - Premium Subsection */}
              {response?.refinement_suggestions?.trust?.length > 0 && (
                <div className="animate-fadeIn" style={{ animationDelay: '0.4s' }}>
                  {/* Premium Subsection Header */}
                  <div className="flex items-center justify-between mb-6">
                    <div>
                      <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                        <Sparkles className="w-7 h-7 text-purple-600" />
                        <span>Trust Policy Refinements</span>
                      </h3>
                      <p className="text-slate-600 text-sm font-medium">AI-powered improvement suggestions</p>
                    </div>
                    <button
                      onClick={() => setShowTrustSuggestions(!showTrustSuggestions)}
                      className="group flex items-center space-x-2 px-4 py-2 bg-white/80 backdrop-blur-xl hover:bg-white/90 border-2 border-slate-200 hover:border-purple-300 rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl"
                    >
                      <span className="text-sm font-semibold text-slate-700 group-hover:text-purple-600 transition-colors duration-300">
                        {showTrustSuggestions ? 'Hide' : 'Show'}
                      </span>
                      {showTrustSuggestions ? (
                        <ChevronUp className="w-4 h-4 text-slate-500 group-hover:text-purple-600 transition-colors duration-300" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500 group-hover:text-purple-600 transition-colors duration-300" />
                      )}
                    </button>
                  </div>

                  {/* Content Card */}
                  {showTrustSuggestions && (
                  <div className="relative bg-white/80 backdrop-blur-xl border-2 border-purple-200/50 rounded-2xl p-8 shadow-xl hover:shadow-2xl transition-all duration-500">
                      {/* Pro Tip - Enhanced Premium */}
                      <div className="bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-orange-500/10 border-2 border-purple-200/50 rounded-xl p-5 mb-6 shadow-lg">
                        <div className="flex items-center space-x-3">
                          <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center shadow-md flex-shrink-0">
                            <Lightbulb className="w-5 h-5 text-white" />
                          </div>
                          <div className="flex-1">
                            <p className="text-slate-700 text-sm leading-relaxed font-medium">
                              <strong className="bg-gradient-to-r from-purple-600 to-pink-600 bg-clip-text text-transparent">Pro Tip:</strong> Click any suggestion below to automatically implement it via the chatbot
                            </p>
                          </div>
                        </div>
                      </div>
                      
                      <div className="grid grid-cols-1 gap-4">
                        {response.refinement_suggestions.trust.map((suggestion, idx) => (
                          <button
                            key={idx}
                            onClick={() => {
                              setFollowUpMessage(suggestion);
                              setIsChatbotOpen(true);
                            }}
                            className="group relative px-6 py-5 bg-gradient-to-br from-white to-slate-50/50 hover:from-white hover:to-purple-50/30 border-2 border-slate-200 hover:border-purple-300 rounded-xl text-left transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-[1.02] overflow-hidden"
                          >
                            <div className="relative flex items-center space-x-4">
                              <div className="flex-shrink-0 w-12 h-12 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center shadow-md group-hover:scale-110 group-hover:rotate-3 transition-all duration-300">
                                <FileCheck className="w-6 h-6 text-white" />
                              </div>
                              <div className="flex-1">
                                <p className="text-slate-700 group-hover:text-slate-900 font-medium transition-colors duration-300 leading-relaxed">
                                  {suggestion}
                                </p>
                              </div>
                              <ArrowRight className="w-5 h-5 text-slate-400 group-hover:text-purple-600 opacity-0 group-hover:opacity-100 transition-all duration-300 transform group-hover:translate-x-1 flex-shrink-0" />
                            </div>
                          </button>
                        ))}
                      </div>
                  </div>
                  )}
                </div>
              )}

              {/* COMPLIANCE STATUS - Premium Subsection */}
              {response.compliance_status && Object.keys(response.compliance_status).length > 0 && (
                <div className="mb-16 animate-fadeIn" style={{ animationDelay: '0.4s' }}>
                  {/* Premium Subsection Header */}
                  <div className="mb-8">
                    <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                      <CheckCircle className="w-7 h-7 text-blue-600" />
                      <span>Compliance Status</span>
                    </h3>
                    <p className="text-slate-600 text-sm font-medium">Compliance validation against selected framework</p>
                  </div>

                  {/* Overall Compliance Summary Banner */}
                  {(() => {
                    const frameworks = Object.values(response.compliance_status || {});
                    const compliantCount = frameworks.filter((f: any) => f.status === 'Compliant').length;
                    const nonCompliantCount = frameworks.length - compliantCount;
                    const totalViolations = frameworks.reduce((sum: number, f: any) => {
                      return sum + (f.violations?.length || f.gaps?.length || 0);
                    }, 0);
                    
                    return (
                      <div className={`mb-8 border-2 rounded-2xl p-6 shadow-xl ${
                        nonCompliantCount > 0 
                          ? 'bg-gradient-to-r from-red-50 via-orange-50 to-yellow-50 border-red-200/50'
                          : 'bg-gradient-to-r from-green-50 via-emerald-50 to-teal-50 border-green-200/50'
                      }`}>
                        <div className="flex items-center justify-between flex-wrap gap-4">
                          <div className="flex items-center space-x-4">
                            <div className={`w-16 h-16 rounded-full flex items-center justify-center border-2 ${
                              nonCompliantCount > 0
                                ? 'bg-red-500/10 border-red-200/50'
                                : 'bg-green-500/10 border-green-200/50'
                            }`}>
                              {nonCompliantCount > 0 ? (
                                <XCircle className="w-8 h-8 text-red-600" />
                              ) : (
                                <CheckCircle className="w-8 h-8 text-green-600" />
                              )}
                            </div>
                            <div>
                              <div className={`font-black text-2xl mb-1 ${
                                nonCompliantCount > 0 ? 'text-red-900' : 'text-green-900'
                              }`}>
                                {nonCompliantCount > 0 ? 'Non-Compliance Detected' : 'Fully Compliant'}
                              </div>
                              <div className="text-slate-700 text-sm font-medium">
                                {nonCompliantCount > 0 
                                  ? `${nonCompliantCount} of ${frameworks.length} frameworks failed • ${totalViolations} total violations`
                                  : `All ${frameworks.length} framework requirements met`
                                }
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            <div className="text-right">
                              <div className="text-slate-600 text-xs font-semibold uppercase tracking-wide mb-1">Compliance Rate</div>
                              <div className={`font-black text-3xl ${
                                nonCompliantCount > 0 ? 'text-red-600' : 'text-green-600'
                              }`}>
                                {Math.round((compliantCount / frameworks.length) * 100)}%
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })()}

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {Object.entries(response.compliance_status).map(([key, framework]: [string, any]) => {
                      const violations = framework.violations || [];
                      const gaps = framework.gaps || [];
                      const totalIssues = violations.length + gaps.length;
                      
                      return (
                        <div key={key} className={`bg-white/80 backdrop-blur-xl border-2 rounded-2xl p-6 shadow-xl hover:shadow-2xl transition-all duration-300 ${
                          framework.status === 'Compliant' 
                            ? 'border-green-200/50' 
                            : 'border-red-200/50'
                        }`}>
                          <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center space-x-3">
                              <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                                framework.status === 'Compliant'
                                  ? 'bg-green-500/10 border-2 border-green-200/50'
                                  : 'bg-red-500/10 border-2 border-red-200/50'
                              }`}>
                                {framework.status === 'Compliant' ? (
                                  <CheckCircle className="w-6 h-6 text-green-600" />
                                ) : (
                                  <XCircle className="w-6 h-6 text-red-600" />
                                )}
                              </div>
                              <div>
                                <h4 className="text-slate-900 font-bold text-lg">{framework.name}</h4>
                                <div className="text-xs text-slate-500 font-medium">{totalIssues} {totalIssues === 1 ? 'issue' : 'issues'} found</div>
                              </div>
                            </div>
                            <span className={`px-3 py-1.5 rounded-full text-xs font-bold ${
                              framework.status === 'Compliant'
                                ? 'bg-green-500/10 text-green-700 border border-green-200/50'
                                : 'bg-red-500/10 text-red-700 border border-red-200/50'
                            }`}>
                              {framework.status}
                            </span>
                          </div>
                          
                          {/* Progress Indicator */}
                          {framework.status !== 'Compliant' && (
                            <div className="mb-4">
                              <div className="flex items-center justify-between text-xs text-slate-600 mb-2">
                                <span className="font-semibold">Remediation Progress</span>
                                <span className="font-bold">0%</span>
                              </div>
                              <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                                <div className="h-full bg-gradient-to-r from-red-500 to-orange-500 rounded-full transition-all duration-500" style={{ width: '0%' }}></div>
                              </div>
                              <div className="text-xs text-slate-500 mt-1 font-medium">Use AI Assistant below to fix compliance issues</div>
                            </div>
                          )}
                          
                          {/* Full violations handling */}
                          {violations.length > 0 && (
                            <div className="space-y-3">
                              <div className="text-xs text-slate-600 font-bold uppercase tracking-wide mb-2">Violations:</div>
                              {violations.map((violation: any, idx: number) => (
                                <div key={idx} className="bg-slate-50 rounded-xl p-4 border-2 border-slate-200/50 hover:border-red-200/50 transition-all duration-300">
                                  <div className="flex items-start justify-between mb-2">
                                    <div className="flex items-center space-x-2">
                                      <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                                      <div className="text-red-700 font-bold text-sm">{violation.requirement}</div>
                                    </div>
                                    <span className="px-2 py-0.5 bg-red-500/10 text-red-700 text-xs font-semibold rounded border border-red-200/50">
                                      High Priority
                                    </span>
                                  </div>
                                  <p className="text-slate-700 text-sm mb-3 leading-relaxed font-medium">{violation.description}</p>
                                  <div className="bg-blue-500/10 border-l-4 border-blue-500/50 rounded-r-lg p-3">
                                    <div className="text-blue-700 text-xs font-bold mb-1 flex items-center space-x-1">
                                      <Sparkles className="w-3 h-3" />
                                      <span>How to Fix:</span>
                                    </div>
                                    <p className="text-slate-700 text-sm font-medium">{violation.fix}</p>
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                          
                          {/* Fallback to gaps if no violations */}
                          {violations.length === 0 && gaps.length > 0 && (
                            <div className="space-y-2">
                              <div className="text-xs text-slate-600 font-bold uppercase tracking-wide mb-2">Compliance Gaps:</div>
                              {gaps.map((gap: string, idx: number) => (
                                <div key={idx} className="flex items-start space-x-2 bg-slate-50 rounded-lg p-3 border border-slate-200/50">
                                  <XCircle className="w-4 h-4 text-red-600 mt-0.5 flex-shrink-0" />
                                  <p className="text-slate-700 text-sm font-medium">{gap}</p>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Compliant State */}
                          {framework.status === 'Compliant' && (
                            <div className="bg-green-50 rounded-xl p-4 border-2 border-green-200/50 text-center">
                              <CheckCircle className="w-8 h-8 text-green-600 mx-auto mb-2" />
                              <p className="text-green-700 font-semibold text-sm">All requirements met</p>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* REFINE POLICY FORM - Premium Subsection */}
              <div className="animate-fadeIn" style={{ animationDelay: '0.5s' }}>
                {/* Premium Subsection Header */}
                <div className="mb-6">
                  <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                    <MessageSquare className="w-7 h-7 text-blue-600" />
                    <span>Refine Your Policy</span>
                  </h3>
                  <p className="text-slate-600 text-sm font-medium">Use AI to improve your policies</p>
                </div>

                {/* Content Card */}
                <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 shadow-xl">
                  <p className="text-slate-600 text-sm mb-6 font-medium">
                    Ask questions or request changes to improve your policy
                  </p>
                
                <form onSubmit={handleFollowUp} className="space-y-4">
                  <textarea
                    value={followUpMessage}
                    onChange={(e) => setFollowUpMessage(e.target.value)}
                    placeholder="Example: Add MFA requirement for sensitive operations..."
                    className="w-full h-24 px-4 py-3 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl text-slate-900 placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none resize-none transition-all duration-300 font-medium"
                    disabled={loading}
                  />
                  
                  <button
                    type="submit"
                    disabled={loading || !followUpMessage.trim()}
                    className="w-full bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white py-4 px-6 rounded-xl font-bold disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-xl hover:shadow-2xl hover:scale-[1.02] flex items-center justify-center space-x-2"
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
        </div>
      )}

      {/* FLOATING CHATBOT WIDGET */}
      {!showInitialForm && response && hasContent && (
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
            <div className={`${isChatbotExpanded ? 'w-[90vw] h-[90vh]' : 'w-96 h-[600px]'} bg-white/95 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl shadow-2xl flex flex-col overflow-hidden transition-all duration-300`}>
              <div className="p-4 bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-pink-500/10 border-b-2 border-slate-200/50 flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full flex items-center justify-center shadow-lg">
                    <Bot className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h3 className="text-slate-900 font-bold text-sm">Aegis AI Agent</h3>
                    <p className="text-xs text-slate-600 font-medium">Ask me anything about your policies</p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setIsChatbotExpanded(!isChatbotExpanded)}
                    className="text-slate-500 hover:text-slate-900 transition-colors duration-300 p-1 hover:bg-slate-100 rounded"
                  >
                    {isChatbotExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
                  </button>
                  <button
                    onClick={() => setIsChatbotOpen(false)}
                    className="text-slate-500 hover:text-slate-900 transition-colors duration-300"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
              </div>

              <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-slate-50/30">
                {chatHistory.map((msg, idx) => {
                  // Extract JSON blocks from markdown-style responses (```json ... ```)
                  const jsonBlockRegex = /```json\s*([\s\S]*?)```/g;
                  const jsonBlocks: string[] = [];
                  let match;
                  while ((match = jsonBlockRegex.exec(msg.content)) !== null) {
                    try {
                      JSON.parse(match[1].trim()); // Validate it's valid JSON
                      jsonBlocks.push(match[1].trim());
                    } catch (e) {
                      // Not valid JSON, skip
                    }
                  }
                  
                  // Get text content without JSON blocks
                  const textContent = msg.content.replace(/```json[\s\S]*?```/g, '').trim();
                  const hasText = textContent.length > 0;
                  const hasJSON = jsonBlocks.length > 0;
                  
                  return (
                    <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                      <div className={`max-w-[85%] ${
                        msg.role === 'user' 
                          ? 'bg-gradient-to-br from-blue-500/20 to-purple-500/20 border-2 border-blue-200/50' 
                          : 'bg-white/80 border-2 border-slate-200/50'
                      } rounded-2xl p-3 shadow-sm`}>
                        <div className="flex items-start space-x-2">
                          {msg.role === 'assistant' && (
                            <Bot className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
                          )}
                          <div className="flex-1 space-y-3">
                            {/* Text explanation (if any) */}
                            {hasText && (
                              <p className="text-sm text-slate-700 leading-relaxed whitespace-pre-wrap font-medium">{textContent}</p>
                            )}
                            
                            {/* JSON blocks (both policies) */}
                            {hasJSON && jsonBlocks.map((jsonBlock, jsonIdx) => {
                              try {
                                const parsed = JSON.parse(jsonBlock);
                                const isTrustPolicy = JSON.stringify(parsed).includes('"Principal"');
                                return (
                                  <div key={jsonIdx} className="bg-slate-100 rounded-lg p-3 border border-slate-200">
                                    <div className="flex items-center justify-between mb-2">
                                      <span className="text-xs text-slate-500 font-mono font-semibold">
                                        {isTrustPolicy ? 'Trust Policy' : 'Permissions Policy'}
                                      </span>
                                      <button
                                        onClick={() => handleCopyJSON(jsonBlock)}
                                        className="text-xs text-blue-600 hover:text-blue-700 transition-colors duration-300 flex items-center space-x-1 font-medium"
                                      >
                                        <Copy className="w-3 h-3" />
                                        <span>Copy</span>
                                      </button>
                                    </div>
                                    <pre className="text-xs text-slate-800 font-mono overflow-x-auto leading-relaxed">
                                      {JSON.stringify(parsed, null, 2)}
                                    </pre>
                                  </div>
                                );
                              } catch (e) {
                                return null;
                              }
                            })}
                            
                            {/* Fallback: if no JSON blocks but content looks like JSON */}
                            {!hasJSON && !hasText && isJSON(msg.content) && (
                              <div className="bg-slate-100 rounded-lg p-3 border border-slate-200">
                                <div className="flex items-center justify-between mb-2">
                                  <span className="text-xs text-slate-500 font-mono font-semibold">JSON Response</span>
                                  <button
                                    onClick={() => handleCopyJSON(msg.content)}
                                    className="text-xs text-blue-600 hover:text-blue-700 transition-colors duration-300 flex items-center space-x-1 font-medium"
                                  >
                                    <Copy className="w-3 h-3" />
                                    <span>Copy</span>
                                  </button>
                                </div>
                                <pre className="text-xs text-slate-800 font-mono overflow-x-auto leading-relaxed">
                                  {JSON.stringify(JSON.parse(msg.content), null, 2)}
                                </pre>
                              </div>
                            )}
                            
                            {/* Fallback: plain text if no JSON */}
                            {!hasJSON && !hasText && !isJSON(msg.content) && (
                              <div>
                                <p className="text-sm text-slate-700 leading-relaxed whitespace-pre-wrap font-medium">{msg.content}</p>
                                
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
                                      className="group px-3 py-2 bg-blue-500/10 hover:bg-blue-500/20 border-2 border-blue-200/50 hover:border-blue-300 rounded-lg text-xs text-blue-700 hover:text-blue-800 transition-all duration-300 flex items-center space-x-2 font-semibold"
                                    >
                                      <Copy className="w-3 h-3" />
                                      <span>Get Both Policies (JSON)</span>
                                    </button>
                                    <button
                                      onClick={() => {
                                        setFollowUpMessage('Add MFA requirement for sensitive operations');
                                      }}
                                      className="group px-3 py-2 bg-purple-500/10 hover:bg-purple-500/20 border-2 border-purple-200/50 hover:border-purple-300 rounded-lg text-xs text-purple-700 hover:text-purple-800 transition-all duration-300 flex items-center space-x-2 font-semibold"
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
                    <div className="max-w-[85%] bg-white/80 border-2 border-slate-200/50 rounded-2xl p-3 shadow-sm">
                      <div className="flex items-start space-x-2">
                        <Bot className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
                        <div className="flex items-center space-x-2">
                          <div className="flex space-x-1">
                            <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
                            <div className="w-2 h-2 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
                            <div className="w-2 h-2 bg-pink-500 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
                          </div>
                          <span className="text-xs text-slate-600 font-medium">Aegis AI is thinking...</span>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
                
                <div ref={chatEndRef} />
              </div>

              <div className="p-4 border-t-2 border-slate-200/50 bg-white/80">
                <form onSubmit={handleFollowUp} className="space-y-2">
                  <textarea
                    value={followUpMessage}
                    onChange={(e) => setFollowUpMessage(e.target.value)}
                    placeholder="Ask me to refine the policy, explain something, or answer questions..."
                    className="w-full h-20 px-3 py-2 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl text-slate-900 text-sm placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none resize-none transition-all duration-300 font-medium"
                    disabled={loading}
                  />
                  
                  <button
                    type="submit"
                    disabled={loading || !followUpMessage.trim()}
                    className="w-full bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white py-2.5 px-4 rounded-xl font-bold text-sm disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-lg hover:shadow-xl flex items-center justify-center space-x-2 hover:scale-[1.02]"
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