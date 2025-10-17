import React, { useState, useEffect, useRef } from 'react';
import { Shield, Send, RefreshCw, User, Bot, MessageSquare, Lock, ArrowRight, CheckCircle, AlertCircle, Download, Copy, Sparkles, Info, X, Minimize2, ChevronUp, ChevronDown } from 'lucide-react';
import { generatePolicy, sendFollowUp } from '../../services/api';
import { GeneratePolicyResponse, ChatMessage } from '../../types';

// ScoreCard Component - Elite security-focused design
const ScoreCard = ({ title, score, color }: { title: string; score: number; color: string }) => {
  const getGrade = (score: number) => {
    if (score >= 90) return { 
      letter: 'A', 
      color: 'text-emerald-400', 
      bg: 'from-emerald-950/40 via-emerald-900/30 to-emerald-950/40', 
      border: 'border-emerald-500/40',
      glow: 'shadow-emerald-500/20',
      label: 'Excellent',
      labelColor: 'text-emerald-300'
    };
    if (score >= 80) return { 
      letter: 'B', 
      color: 'text-green-400', 
      bg: 'from-green-950/40 via-green-900/30 to-green-950/40', 
      border: 'border-green-500/40',
      glow: 'shadow-green-500/20',
      label: 'Good',
      labelColor: 'text-green-300'
    };
    if (score >= 70) return { 
      letter: 'C', 
      color: 'text-yellow-400', 
      bg: 'from-yellow-950/40 via-yellow-900/30 to-yellow-950/40', 
      border: 'border-yellow-500/40',
      glow: 'shadow-yellow-500/20',
      label: 'Fair',
      labelColor: 'text-yellow-300'
    };
    if (score >= 60) return { 
      letter: 'D', 
      color: 'text-orange-400', 
      bg: 'from-orange-950/40 via-orange-900/30 to-orange-950/40', 
      border: 'border-orange-500/40',
      glow: 'shadow-orange-500/20',
      label: 'Needs Work',
      labelColor: 'text-orange-300'
    };
    return { 
      letter: 'F', 
      color: 'text-red-400', 
      bg: 'from-red-950/40 via-red-900/30 to-red-950/40', 
      border: 'border-red-500/40',
      glow: 'shadow-red-500/20',
      label: 'Critical',
      labelColor: 'text-red-300'
    };
  };

  const grade = getGrade(score);
  
  return (
    <div className={`relative bg-gradient-to-br ${grade.bg} backdrop-blur-xl border-2 ${grade.border} rounded-3xl p-8 ${grade.glow} shadow-2xl transition-all duration-500 hover:scale-105 hover:shadow-xl group`}>
      {/* Animated background glow */}
      <div className={`absolute inset-0 bg-gradient-to-br ${grade.bg} rounded-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 blur-xl`}></div>
      
      <div className="relative">
        {/* Title */}
        <div className="flex items-center justify-between mb-6">
          <h3 className={`${color} text-base font-bold uppercase tracking-wider`}>{title}</h3>
          <Shield className={`w-5 h-5 ${color} opacity-60`} />
        </div>
        
        {/* Score Display */}
        <div className="flex items-end justify-between mb-6">
          <div className="flex items-baseline space-x-3">
            <div className={`text-7xl font-black ${grade.color} tracking-tight`}>
              {score}
            </div>
            <div className="text-slate-400 text-2xl font-medium pb-2">/100</div>
          </div>
          
          {/* Grade Badge */}
          <div className="text-center">
            <div className={`text-5xl font-black ${grade.color} leading-none mb-1`}>{grade.letter}</div>
            <div className={`text-xs font-semibold ${grade.labelColor} uppercase tracking-wide`}>{grade.label}</div>
          </div>
        </div>
        
        {/* Progress Bar */}
        <div className="relative w-full h-4 bg-slate-900/60 rounded-full overflow-hidden border border-slate-800/50">
          <div
            className={`h-full rounded-full transition-all duration-1000 ease-out ${
              score >= 90 ? 'bg-gradient-to-r from-emerald-500 via-emerald-400 to-green-400' :
              score >= 80 ? 'bg-gradient-to-r from-green-500 via-green-400 to-lime-400' :
              score >= 70 ? 'bg-gradient-to-r from-yellow-500 via-yellow-400 to-amber-400' :
              score >= 60 ? 'bg-gradient-to-r from-orange-500 via-orange-400 to-red-400' :
              'bg-gradient-to-r from-red-500 via-red-400 to-rose-400'
            } shadow-lg`}
            style={{ width: `${score}%` }}
          >
            {/* Animated shine effect */}
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-shimmer"></div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ScoreBreakdown Component - Better breakdown display with strengths and improvements
const ScoreBreakdown = ({ 
  title, 
  positive, 
  improvements,
  colorClass 
}: { 
  title: string; 
  positive: string[]; 
  improvements: string[];
  colorClass: string;
}) => {
  return (
    <div className={`bg-${colorClass}-500/5 backdrop-blur-xl border border-${colorClass}-500/30 rounded-2xl p-6`}>
      <h4 className={`text-${colorClass}-300 font-semibold mb-4 flex items-center space-x-2`}>
        <Shield className="w-5 h-5" />
        <span>{title}</span>
      </h4>
      
      {positive && positive.length > 0 && (
        <div className="mb-4">
          <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4">
            <h5 className="text-green-400 font-semibold mb-3 flex items-center space-x-2">
              <CheckCircle className="w-4 h-4" />
              <span>Strengths</span>
            </h5>
            <ul className="space-y-2">
              {positive.map((item, idx) => (
                <li key={idx} className="text-sm text-slate-300 flex items-start space-x-2">
                  <span className="text-green-400 mt-0.5">✓</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
      
      {improvements && improvements.length > 0 && (
        <div>
          <div className="bg-orange-500/10 border border-orange-500/30 rounded-xl p-4">
            <h5 className="text-orange-400 font-semibold mb-3 flex items-center space-x-2">
              <AlertCircle className="w-4 h-4" />
              <span>Room for Improvement</span>
            </h5>
            <ul className="space-y-2">
              {improvements.map((item, idx) => (
                <li key={idx} className="text-sm text-slate-300 flex items-start space-x-2">
                  <span className="text-orange-400 mt-0.5">!</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};

// RefinementButton Component - Clickable refinement suggestion
const RefinementButton = ({ 
  suggestion, 
  onClick,
  icon,
  colorClass 
}: { 
  suggestion: string; 
  onClick: () => void;
  icon: React.ReactNode;
  colorClass: string;
}) => {
  return (
    <button
      onClick={onClick}
      className={`group px-4 py-3 bg-slate-800/50 hover:bg-${colorClass}-500/20 border border-${colorClass}-500/30 hover:border-${colorClass}-500/50 rounded-xl text-sm text-slate-300 hover:text-white transition-all flex items-center justify-between text-left w-full`}
    >
      <div className="flex items-center space-x-3">
        <div className={`w-8 h-8 bg-${colorClass}-500/20 rounded-lg flex items-center justify-center flex-shrink-0`}>
          {icon}
        </div>
        <span className="flex-1">{suggestion}</span>
      </div>
      <ArrowRight className={`w-4 h-4 text-${colorClass}-400 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0`} />
    </button>
  );
};

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
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [isChatMinimized, setIsChatMinimized] = useState(false);
  const [showPermissionsBreakdown, setShowPermissionsBreakdown] = useState(false);
  const [showTrustBreakdown, setShowTrustBreakdown] = useState(false);
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

  const handleDownloadPolicy = () => {
    if (response?.policy) {
      const blob = new Blob([JSON.stringify(response.policy, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'permissions-policy.json';
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
      setIsChatOpen(true);
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
    setResponse(null); // Clear response to show loading screen
    
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
    setIsChatOpen(false);
  };

  const hasPolicy = response?.policy !== null && 
                    response?.policy !== undefined && 
                    typeof response?.policy === 'object' &&
                    Object.keys(response?.policy || {}).length > 0 &&
                    response?.is_question !== true;

  const permissionsScore = response?.permissions_score || 0;
  const trustScore = response?.trust_score || 0;
  const overallScore = response?.overall_score || 0;

  console.log('🔍 DEBUG SCORES:', {
    permissionsScore,
    trustScore,
    overallScore,
    response_permissions_score: response?.permissions_score,
    response_trust_score: response?.trust_score,
    response_overall_score: response?.overall_score,
    fullResponse: response
  });

  const getServiceIcon = (title: string) => {
    const lower = title.toLowerCase();
    if (lower.includes('s3') || lower.includes('bucket')) return '🪣';
    if (lower.includes('dynamo')) return '🗄️';
    if (lower.includes('cloudwatch') || lower.includes('log')) return '📊';
    if (lower.includes('lambda')) return '⚡';
    if (lower.includes('ec2')) return '💻';
    if (lower.includes('rds')) return '🗃️';
    return '🔒';
  };

  const parseExplanation = (explanation: string) => {
    if (!explanation || explanation.trim() === '') return [];
    
    const sections = explanation
      .split(/(?=^\d+\.\s+)/m)
      .filter(section => section.trim());
    
    return sections.map(section => {
      const match = section.match(/^(\d+)\.\s+(.+?)(?:\n|$)([\s\S]*)/);
      if (!match) return null;
      
      const [, num, title, content] = match;
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
      
      return { num, title: title.trim(), details };
    }).filter((item): item is { num: string; title: string; details: { [key: string]: string } } => item !== null);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* INITIAL FORM */}
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
                    className="w-full bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 hover:from-orange-700 hover:via-pink-600 hover:to-purple-700 text-white py-4 sm:py-5 px-6 sm:px-8 rounded-xl sm:rounded-2xl font-semibold text-base sm:text-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-purple-500/25 hover:shadow-xl hover:shadow-purple-500/40 flex items-center justify-center space-x-2 group"
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

      {/* LOADING STATE */}
      {!showInitialForm && loading && !response && (
        <div className="relative overflow-hidden min-h-screen flex items-center justify-center bg-slate-950">
          {/* Animated background orbs */}
          <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-purple-500/10 rounded-full blur-3xl animate-pulse"></div>
          <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-pink-500/10 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
          <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] bg-orange-500/5 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '2s' }}></div>
          
          <div className="relative text-center px-8 max-w-3xl">
            {/* Main Icon */}
            <div className="inline-flex items-center justify-center w-32 h-32 mb-10 relative">
              {/* Rotating ring */}
              <div className="absolute inset-0 border-4 border-transparent border-t-purple-500 border-r-pink-500 rounded-full animate-spin"></div>
              <div className="absolute inset-2 border-4 border-transparent border-t-pink-500 border-r-orange-500 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '2s' }}></div>
              
              {/* Pulsing background */}
              <div className="absolute inset-0 bg-gradient-to-br from-purple-500/20 via-pink-500/20 to-orange-500/20 rounded-full animate-ping"></div>
              <div className="absolute inset-0 bg-gradient-to-br from-purple-500/30 via-pink-500/30 to-orange-500/30 rounded-full animate-pulse"></div>
              
              {/* Shield icon */}
              <Shield className="w-16 h-16 text-purple-400 relative z-10 animate-pulse" />
            </div>
            
            {/* Main heading */}
            <h2 className="text-5xl sm:text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-orange-400 mb-4 animate-pulse leading-tight pb-2">
              Aegis AI Analyzing
            </h2>
            
            {/* Subheading */}
            <p className="text-xl sm:text-2xl text-slate-300 mb-8 leading-relaxed font-medium max-w-2xl mx-auto">
              Crafting your secure IAM policy with least-privilege principles...
            </p>
            
            {/* Status indicators */}
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
            
            {/* Animated dots */}
            <div className="flex items-center justify-center space-x-3 mb-8">
              <div className="w-3 h-3 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0ms', animationDuration: '1s' }}></div>
              <div className="w-3 h-3 bg-pink-400 rounded-full animate-bounce" style={{ animationDelay: '200ms', animationDuration: '1s' }}></div>
              <div className="w-3 h-3 bg-orange-400 rounded-full animate-bounce" style={{ animationDelay: '400ms', animationDuration: '1s' }}></div>
            </div>

            {/* Security features being analyzed */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 max-w-2xl mx-auto">
              {['Least Privilege', 'Resource Scoping', 'Action Specificity', 'Trust Boundaries'].map((feature, idx) => (
                <div 
                  key={feature}
                  className="px-4 py-3 bg-slate-800/30 backdrop-blur-xl border border-slate-700/30 rounded-xl"
                  style={{ 
                    animation: 'fadeIn 0.5s ease-out',
                    animationDelay: `${idx * 0.2}s`,
                    animationFillMode: 'backwards'
                  }}
                >
                  <div className="flex items-center justify-center space-x-2">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    <span className="text-xs font-medium text-slate-300">{feature}</span>
                  </div>
                </div>
              ))}
            </div>

            <div className="text-sm text-slate-500 mt-8">
              This may take a few moments...
            </div>
          </div>
        </div>
      )}

      {/* MORE INFORMATION NEEDED PAGE */}
      {!showInitialForm && !loading && response && response.is_question && (
        <div className="relative overflow-hidden min-h-screen">
          <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-orange-500/10 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-yellow-500/8 rounded-full blur-3xl"></div>
          
          <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
            <div className="text-center mb-12">
              <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-orange-500/20 to-yellow-500/20 rounded-2xl mb-6 border border-orange-500/30">
                <AlertCircle className="w-10 h-10 text-orange-400" />
              </div>
              
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
                Just a Few More Details
              </h2>
              
              <p className="text-lg text-slate-400">
                To generate the most secure policy, I need some additional information
              </p>
            </div>

            <div className="bg-slate-900/50 backdrop-blur-xl border border-orange-500/20 rounded-2xl p-8 mb-6">
              <div className="text-slate-300 leading-relaxed whitespace-pre-wrap">
                {cleanMarkdown(response.explanation || response.final_answer)}
              </div>
            </div>

            <div className="bg-slate-900/50 backdrop-blur-xl border border-orange-500/20 rounded-2xl p-8 mb-6">
              <form onSubmit={handleFollowUp}>
                <label className="block text-white font-medium mb-4">
                  Your Response
                </label>
                <textarea
                  value={followUpMessage}
                  onChange={(e) => setFollowUpMessage(e.target.value)}
                  placeholder="Provide the requested information..."
                  className="w-full h-32 px-6 py-4 bg-slate-800/50 border border-slate-700/50 rounded-xl text-white placeholder-slate-500 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none resize-none mb-4"
                  disabled={loading}
                />
                <button
                  type="submit"
                  disabled={loading || !followUpMessage.trim()}
                  className="w-full bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 hover:from-orange-700 hover:via-pink-600 hover:to-purple-700 text-white py-4 px-6 rounded-xl font-semibold disabled:opacity-50 transition-all shadow-lg flex items-center justify-center space-x-2"
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

            <div className="bg-orange-500/10 border border-orange-500/30 rounded-2xl p-6 mb-6">
              <div className="flex items-start space-x-3">
                <Sparkles className="w-5 h-5 text-orange-400 mt-0.5" />
                <div>
                  <h4 className="text-orange-300 font-semibold mb-2">Quick Tips</h4>
                  <ul className="mt-2 space-y-1 text-xs text-slate-300">
                    <li>• Be as specific as possible with AWS Account IDs and regions</li>
                    <li>• If you don't have the information right now, I can use placeholders</li>
                    <li>• You can always refine the policy after it's generated</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="bg-slate-900/50 border border-slate-700/50 rounded-2xl overflow-hidden">
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

      {/* RESULTS DISPLAY */}
      {!showInitialForm && response && hasPolicy && (
        <div className="relative overflow-hidden min-h-screen bg-slate-950">
          {/* Animated background orbs */}
          <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-purple-500/5 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-pink-500/5 rounded-full blur-3xl"></div>
          
          <div className="relative max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            {/* HEADER */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-12 pb-8 border-b border-slate-800/50">
              <div className="mb-6 sm:mb-0">
                <div className="flex items-center space-x-4 mb-3">
                  <div className="relative">
                    <div className="absolute inset-0 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-2xl blur-xl"></div>
                    <div className="relative bg-gradient-to-br from-purple-500/10 to-pink-500/10 backdrop-blur-xl border border-purple-500/30 rounded-2xl p-3">
                      <Shield className="w-8 h-8 text-purple-400" />
                    </div>
                  </div>
                  <div>
                    <h2 className="text-3xl sm:text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-purple-400">
                      Policies Generated Successfully
                    </h2>
                    <div className="flex items-center space-x-2 mt-2">
                      <div className="flex items-center space-x-1.5 px-3 py-1 bg-emerald-500/10 border border-emerald-500/30 rounded-full">
                        <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></div>
                        <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wide">Secure</span>
                      </div>
                      <div className="flex items-center space-x-1.5 px-3 py-1 bg-blue-500/10 border border-blue-500/30 rounded-full">
                        <CheckCircle className="w-3 h-3 text-blue-400" />
                        <span className="text-xs font-semibold text-blue-400 uppercase tracking-wide">Production Ready</span>
                      </div>
                    </div>
                  </div>
                </div>
                <p className="text-slate-400 text-base ml-20">
                  Review your secure IAM policies below. Both permissions and trust policies are ready for deployment.
                </p>
              </div>
              <button
                onClick={handleNewConversation}
                className="group relative px-8 py-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white font-semibold rounded-xl transition-all duration-300 shadow-lg shadow-purple-500/25 hover:shadow-purple-500/40 hover:scale-105 flex items-center space-x-3"
              >
                <div className="absolute inset-0 bg-gradient-to-r from-purple-400 to-pink-400 rounded-xl opacity-0 group-hover:opacity-20 blur-xl transition-opacity duration-300"></div>
                <RefreshCw className="w-5 h-5 group-hover:rotate-180 transition-transform duration-500" />
                <span>New Policy</span>
              </button>
            </div>

            {/* SECURITY SCORES - Only Permissions and Trust */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-12">
              {/* Permissions Policy Score */}
              <div className="bg-gradient-to-br from-orange-500/10 to-red-500/10 backdrop-blur-xl border-2 border-orange-500/30 rounded-2xl p-6 shadow-2xl">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-orange-400 text-sm font-semibold uppercase tracking-wide">Permissions Policy</h3>
                  <button
                    onClick={() => setShowPermissionsBreakdown(!showPermissionsBreakdown)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    {showPermissionsBreakdown ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                  </button>
                </div>
                
                <div className="flex items-end justify-between mb-4">
                  <div className="text-6xl font-bold text-white">{permissionsScore}</div>
                  <div className="text-slate-400 text-lg">/100</div>
                </div>
                
                <div className="w-full bg-slate-800/50 rounded-full h-3 mb-4">
                  <div
                    className="bg-gradient-to-r from-orange-500 to-red-500 h-3 rounded-full transition-all duration-500"
                    style={{ width: `${permissionsScore}%` }}
                  ></div>
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-400">Security Grade</span>
                  <span className="text-2xl font-bold text-orange-400">
                    {permissionsScore >= 90 ? 'A' : permissionsScore >= 80 ? 'B' : permissionsScore >= 70 ? 'C' : permissionsScore >= 60 ? 'D' : 'F'}
                  </span>
                </div>

                {/* Expandable Breakdown */}
                {showPermissionsBreakdown && (
                  <div className="mt-6 pt-6 border-t border-orange-500/20 space-y-4 animate-in slide-in-from-top">
                    {response.score_breakdown?.permissions?.positive?.length > 0 && (
                      <div>
                        <div className="flex items-center space-x-2 mb-2">
                          <CheckCircle className="w-4 h-4 text-green-400" />
                          <span className="text-sm font-semibold text-green-400">Strengths</span>
                        </div>
                        <ul className="space-y-1">
                          {response.score_breakdown.permissions.positive.map((item, idx) => (
                            <li key={idx} className="text-xs text-slate-300 flex items-start space-x-2">
                              <span className="text-green-400 mt-0.5">✓</span>
                              <span>{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    {response.score_breakdown?.permissions?.improvements?.length > 0 && (
                      <div>
                        <div className="flex items-center space-x-2 mb-2">
                          <AlertCircle className="w-4 h-4 text-orange-400" />
                          <span className="text-sm font-semibold text-orange-400">Room for Improvement</span>
                        </div>
                        <ul className="space-y-1">
                          {response.score_breakdown.permissions.improvements.map((item, idx) => (
                            <li key={idx} className="text-xs text-slate-300 flex items-start space-x-2">
                              <span className="text-orange-400 mt-0.5">!</span>
                              <span>{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Trust Policy Score */}
              <div className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 backdrop-blur-xl border-2 border-green-500/30 rounded-2xl p-6 shadow-2xl">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-green-400 text-sm font-semibold uppercase tracking-wide">Trust Policy</h3>
                  <button
                    onClick={() => setShowTrustBreakdown(!showTrustBreakdown)}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    {showTrustBreakdown ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                  </button>
                </div>
                
                <div className="flex items-end justify-between mb-4">
                  <div className="text-6xl font-bold text-white">{trustScore}</div>
                  <div className="text-slate-400 text-lg">/100</div>
                </div>
                
                <div className="w-full bg-slate-800/50 rounded-full h-3 mb-4">
                  <div
                    className="bg-gradient-to-r from-green-500 to-emerald-500 h-3 rounded-full transition-all duration-500"
                    style={{ width: `${trustScore}%` }}
                  ></div>
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-400">Security Grade</span>
                  <span className="text-2xl font-bold text-green-400">
                    {trustScore >= 90 ? 'A' : trustScore >= 80 ? 'B' : trustScore >= 70 ? 'C' : trustScore >= 60 ? 'D' : 'F'}
                  </span>
                </div>

                {/* Expandable Breakdown */}
                {showTrustBreakdown && (
                  <div className="mt-6 pt-6 border-t border-green-500/20 space-y-4 animate-in slide-in-from-top">
                    {response.score_breakdown?.trust?.positive?.length > 0 && (
                      <div>
                        <div className="flex items-center space-x-2 mb-2">
                          <CheckCircle className="w-4 h-4 text-green-400" />
                          <span className="text-sm font-semibold text-green-400">Strengths</span>
                        </div>
                        <ul className="space-y-1">
                          {response.score_breakdown.trust.positive.map((item, idx) => (
                            <li key={idx} className="text-xs text-slate-300 flex items-start space-x-2">
                              <span className="text-green-400 mt-0.5">✓</span>
                              <span>{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    {response.score_breakdown?.trust?.improvements?.length > 0 && (
                      <div>
                        <div className="flex items-center space-x-2 mb-2">
                          <AlertCircle className="w-4 h-4 text-orange-400" />
                          <span className="text-sm font-semibold text-orange-400">Room for Improvement</span>
                        </div>
                        <ul className="space-y-1">
                          {response.score_breakdown.trust.improvements.map((item, idx) => (
                            <li key={idx} className="text-xs text-slate-300 flex items-start space-x-2">
                              <span className="text-orange-400 mt-0.5">!</span>
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

            {/* SCORE BREAKDOWN - Two Columns */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
              {/* Permissions Policy Analysis */}
              <div>
                <h3 className="text-white text-xl font-semibold mb-4 flex items-center space-x-2">
                  <Shield className="w-5 h-5 text-purple-400" />
                  <span>Permissions Policy Analysis</span>
                </h3>
                <ScoreBreakdown
                  title="Strengths"
                  positive={response.score_breakdown?.permissions?.positive || []}
                  improvements={[]}
                  colorClass="green"
                />
                <div className="mt-4">
                  <ScoreBreakdown
                    title="Room for Improvement"
                    positive={[]}
                    improvements={response.score_breakdown?.permissions?.improvements || []}
                    colorClass="orange"
                  />
                </div>
              </div>

              {/* Trust Policy Analysis */}
              <div>
                <h3 className="text-white text-xl font-semibold mb-4 flex items-center space-x-2">
                  <Lock className="w-5 h-5 text-green-400" />
                  <span>Trust Policy Analysis</span>
                </h3>
                <ScoreBreakdown
                  title="Strengths"
                  positive={response.score_breakdown?.trust?.positive || []}
                  improvements={[]}
                  colorClass="green"
                />
                <div className="mt-4">
                  <ScoreBreakdown
                    title="Room for Improvement"
                    positive={[]}
                    improvements={response.score_breakdown?.trust?.improvements || []}
                    colorClass="orange"
                  />
                </div>
              </div>
            </div>

            {/* POLICIES SECTION */}
            <div className="space-y-8">
              {/* PERMISSIONS POLICY */}
              <div>
                <h3 className="text-white text-2xl font-semibold mb-4 flex items-center space-x-2">
                  <Shield className="w-6 h-6 text-purple-400" />
                  <span>Permissions Policy</span>
                </h3>

                <div className="bg-slate-900/80 backdrop-blur-xl border-2 border-slate-800/50 rounded-2xl overflow-hidden shadow-2xl">
                  {/* Terminal Header */}
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
                        className="group relative px-4 py-2 bg-slate-800/50 hover:bg-slate-700/50 border border-slate-700/50 hover:border-slate-600/50 rounded-lg transition-all duration-200 flex items-center space-x-2"
                      >
                        <Copy className="w-4 h-4 text-slate-400 group-hover:text-purple-400 transition-colors" />
                        <span className="text-sm font-medium text-slate-300 group-hover:text-white transition-colors">
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
                        className="group relative px-4 py-2 bg-purple-600/80 hover:bg-purple-500/80 border border-purple-500/50 hover:border-purple-400/50 rounded-lg transition-all duration-200 flex items-center space-x-2"
                      >
                        <Download className="w-4 h-4 text-white transition-transform group-hover:translate-y-0.5" />
                        <span className="text-sm font-medium text-white">Download</span>
                      </button>
                    </div>
                  </div>

                  {/* JSON Content */}
                  <div className="p-6 overflow-x-auto">
                    <pre className="text-sm font-mono text-slate-300 leading-relaxed">
                      {JSON.stringify(response.policy, null, 2)}
                    </pre>
                  </div>
                </div>

                <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-4 mb-6">
                  <div className="flex items-start space-x-3">
                    <Info className="w-5 h-5 text-purple-400 mt-0.5" />
                    <div>
                      <div className="text-sm font-semibold text-purple-300 mb-1">About Permissions Policy</div>
                      <p className="text-sm text-slate-300">
                        The Permissions Policy defines <strong>WHAT</strong> actions this IAM role can perform on AWS resources. 
                        It specifies the exact services, actions, and resources that are allowed or denied.
                      </p>
                    </div>
                  </div>
                </div>

                {response.explanation && (
                  <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-6">
                    <h4 className="text-white text-xl font-bold mb-4 flex items-center space-x-2">
                      <Shield className="w-5 h-5 text-purple-400" />
                      <span>What These Permissions Do</span>
                    </h4>
                    <p className="text-slate-400 mb-6 text-sm">Breakdown of each permission statement</p>
                    
                    <div className="grid grid-cols-1 gap-4">
                      {parseExplanation(response.explanation).map((section: any, index) => (
                        <div key={index} className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 rounded-xl p-5 border border-slate-700/50">
                          <div className="flex items-start space-x-3 mb-3">
                            <div className="text-3xl">{getServiceIcon(section.title)}</div>
                            <div className="flex-1">
                              <div className="text-xs text-slate-500 mb-2">STATEMENT {section.num}</div>
                              <h5 className="text-white font-bold text-base">{section.title}</h5>
                            </div>
                          </div>
                          
                          <div className="space-y-2">
                            {section.details.Permission && (
                              <div className="bg-slate-900/50 rounded-lg p-3">
                                <div className="text-sm text-slate-200 font-mono">
                                  {section.details.Permission}
                                </div>
                              </div>
                            )}
                            
                            {section.details.Purpose && (
                              <div className="text-sm text-slate-300">
                                <span className="font-semibold text-slate-400">Purpose:</span> {section.details.Purpose}
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
              </div>

              {/* TRUST POLICY */}
              {response.trust_policy && (
                <div>
                  <h3 className="text-white text-2xl font-semibold mb-4 flex items-center space-x-2">
                    <CheckCircle className="w-6 h-6 text-green-400" />
                    <span>Trust Policy</span>
                  </h3>

                  <div className="bg-slate-900/80 backdrop-blur-xl border-2 border-slate-800/50 rounded-2xl overflow-hidden shadow-2xl">
                    {/* Terminal Header */}
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
                          className="group relative px-4 py-2 bg-slate-800/50 hover:bg-slate-700/50 border border-slate-700/50 hover:border-slate-600/50 rounded-lg transition-all duration-200 flex items-center space-x-2"
                        >
                          <Copy className="w-4 h-4 text-slate-400 group-hover:text-green-400 transition-colors" />
                          <span className="text-sm font-medium text-slate-300 group-hover:text-white transition-colors">
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
                          className="group relative px-4 py-2 bg-green-600/80 hover:bg-green-500/80 border border-green-500/50 hover:border-green-400/50 rounded-lg transition-all duration-200 flex items-center space-x-2"
                        >
                          <Download className="w-4 h-4 text-white transition-transform group-hover:translate-y-0.5" />
                          <span className="text-sm font-medium text-white">Download</span>
                        </button>
                      </div>
                    </div>

                    {/* JSON Content */}
                    <div className="p-6 bg-slate-950/50">
                      <pre className="text-sm text-white font-mono leading-relaxed overflow-x-auto">
                        {JSON.stringify(response.trust_policy, null, 2)}
                      </pre>
                    </div>
                  </div>

                  <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4 mt-6 mb-6">
                    <div className="flex items-start space-x-3">
                      <Info className="w-5 h-5 text-green-400 mt-0.5" />
                      <div>
                        <div className="text-sm font-semibold text-green-300 mb-1">About Trust Policy</div>
                        <p className="text-sm text-slate-300">
                          The Trust Policy defines <strong>WHO</strong> can assume this IAM role. Without it, 
                          nobody (not even AWS services) can use the permissions policy above.
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Trust Policy Explanation */}
                  {response.trust_explanation && (
                    <div className="bg-slate-900/50 backdrop-blur-xl border border-green-500/20 rounded-2xl p-6">
                      <h4 className="text-white text-xl font-bold mb-4 flex items-center space-x-2">
                        <Shield className="w-5 h-5 text-green-400" />
                        <span>What This Trust Policy Does</span>
                      </h4>
                      <p className="text-slate-400 mb-6 text-sm">Who can assume this role and under what conditions</p>
                      
                      <div className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 rounded-xl p-5 border border-slate-700/50">
                        <div className="space-y-4">
                          {/* Trusted Entity */}
                          <div>
                            <div className="text-xs text-slate-500 mb-2 uppercase tracking-wide font-semibold">Trusted Entity</div>
                            <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-700/30">
                              <div className="text-sm text-white font-mono">
                                {response.trust_policy.Statement?.[0]?.Principal?.Service || 
                                 JSON.stringify(response.trust_policy.Statement?.[0]?.Principal)}
                              </div>
                            </div>
                          </div>
                          
                          {/* Explanation */}
                          <div>
                            <div className="text-xs text-slate-500 mb-2 uppercase tracking-wide font-semibold">What It Means</div>
                            <div className="space-y-3">
                              {response.trust_explanation.split('\n\n').map((section, idx) => {
                                const lines = section.split('\n');
                                const title = lines[0];
                                const details = lines.slice(1);
                                
                                return (
                                  <div key={idx} className="bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
                                    {title && (
                                      <h5 className="text-white font-semibold text-sm mb-2">{title}</h5>
                                    )}
                                    {details.map((detail, dIdx) => (
                                      detail.trim() && (
                                        <p key={dIdx} className="text-sm text-slate-300 leading-relaxed mb-1">
                                          {detail.trim()}
                                        </p>
                                      )
                                    ))}
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                          
                          {/* Security Note */}
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
                </div>
              )}
            </div>

            {/* REFINEMENT SUGGESTIONS */}
            {(response?.refinement_suggestions?.permissions?.length > 0 || 
              response?.refinement_suggestions?.trust?.length > 0) && (
              <div className="bg-purple-500/10 backdrop-blur-xl border border-purple-500/30 rounded-2xl p-6 mb-8">
                <h4 className="text-purple-400 text-lg font-semibold mb-4 flex items-center space-x-2">
                  <Sparkles className="w-5 h-5" />
                  <span>Suggested Refinements</span>
                </h4>
                <p className="text-slate-400 text-sm mb-4">
                  Click any suggestion to refine your policy
                </p>
                
                <div className="space-y-4">
                  {response.refinement_suggestions.permissions && response.refinement_suggestions.permissions.length > 0 && (
                    <div>
                      <div className="text-xs text-slate-500 mb-2 uppercase tracking-wide font-semibold">Permissions Policy</div>
                      <div className="flex flex-wrap gap-2">
                        {response.refinement_suggestions.permissions.map((suggestion, idx) => (
                          <button
                            key={idx}
                            onClick={() => {
                              setFollowUpMessage(suggestion);
                              // Scroll to the follow-up input
                              window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
                            }}
                            className="group px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 hover:border-purple-500/60 rounded-lg text-sm text-purple-300 hover:text-white transition-all flex items-center space-x-2"
                          >
                            <Sparkles className="w-3 h-3" />
                            <span>{suggestion}</span>
                            <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {response.refinement_suggestions.trust && response.refinement_suggestions.trust.length > 0 && (
                    <div>
                      <div className="text-xs text-slate-500 mb-2 uppercase tracking-wide font-semibold">Trust Policy</div>
                      <div className="flex flex-wrap gap-2">
                        {response.refinement_suggestions.trust.map((suggestion, idx) => (
                          <button
                            key={idx}
                            onClick={() => {
                              setFollowUpMessage(suggestion);
                              window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
                            }}
                            className="group px-4 py-2 bg-green-500/20 hover:bg-green-500/30 border border-green-500/40 hover:border-green-500/60 rounded-lg text-sm text-green-300 hover:text-white transition-all flex items-center space-x-2"
                          >
                            <Sparkles className="w-3 h-3" />
                            <span>{suggestion}</span>
                            <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* REFINE POLICY FORM */}
            <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-6">
              <h4 className="text-white text-xl font-bold mb-4 flex items-center space-x-2">
                <MessageSquare className="w-5 h-5 text-purple-400" />
                <span>Refine Your Policy</span>
              </h4>
              <p className="text-slate-400 text-sm mb-4">
                Ask questions or request changes to improve your policy
              </p>
              
              <form onSubmit={handleFollowUp} className="space-y-4">
                <textarea
                  value={followUpMessage}
                  onChange={(e) => setFollowUpMessage(e.target.value)}
                  placeholder="Example: Add MFA requirement for sensitive operations..."
                  className="w-full h-24 px-4 py-3 bg-slate-800/50 border border-slate-700/50 rounded-xl text-white placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none resize-none transition-all"
                  disabled={loading}
                />
                
                <button
                  type="submit"
                  disabled={loading || !followUpMessage.trim()}
                  className="w-full bg-gradient-to-r from-purple-600 via-pink-500 to-orange-600 hover:from-purple-500 hover:via-pink-400 hover:to-orange-500 text-white py-3 px-6 rounded-xl font-semibold disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-purple-500/25 hover:shadow-xl hover:shadow-purple-500/40 flex items-center justify-center space-x-2"
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
      )}
    </div>
  );
};

export default GeneratePolicy;
