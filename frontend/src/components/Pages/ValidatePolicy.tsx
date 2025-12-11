import React, { useState, useRef, useEffect } from 'react';
import { Search, AlertTriangle, XCircle, CheckCircle, Info, AlertCircle, Shield, Sparkles, Copy, Download, RefreshCw, Zap, Bot, ChevronDown, ChevronUp, Send, TrendingUp, Target, Clock, Share2, Activity, Scan, FileSearch, Users, Database, Lock, Eye, Settings, X, Minimize2, Maximize2, ArrowRight, ExternalLink, Key } from 'lucide-react';
import { saveToStorage, loadFromStorage, STORAGE_KEYS } from '@/utils/persistence';
import { getComplianceLink } from '@/utils/complianceLinks';
import CollapsibleTile from '@/components/Common/CollapsibleTile';
import SecurityTips from '@/components/Common/SecurityTips';
import AWSConfigModal from '@/components/Modals/AWSConfigModal';
import { AWSCredentials, validateCredentials, maskAccessKeyId, getRegionDisplayName } from '@/utils/awsCredentials';

// ============================================
// TYPE DEFINITIONS
// ============================================

interface SecurityFinding {
  id: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  type: string;
  title: string;
  description: string;
  recommendation: string;
  affectedStatement?: number;
  code_snippet?: string;
  detailed_explanation?: string;
}

interface ComplianceFramework {
  name: string;
  status: 'Compliant' | 'NonCompliant' | 'Partial';
  gaps?: string[];
  violations?: Array<{
    requirement: string;
    description: string;
    fix: string;
  }>;
}

interface ValidatePolicyResponse {
  findings: SecurityFinding[];
  risk_score: number;
  security_issues: string[];
  recommendations: string[];
  compliance_status: Record<string, ComplianceFramework>;
  quick_wins?: string[];
  audit_summary?: any;
  top_risks?: string[];
  agent_reasoning?: string;
  role_details?: {
    role_arn?: string;
    role_name?: string;
    attached_policies?: Array<{ name: string; arn: string; document?: any }>;
    inline_policies?: Array<{ name: string }>;
    trust_policy?: any;
    permissions_boundary_arn?: string;
  };
}

interface EnhancementMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

// Available compliance frameworks
const AVAILABLE_FRAMEWORKS = [
  { id: 'pci_dss', name: 'PCI DSS', description: 'Payment Card Industry Data Security Standard' },
  { id: 'hipaa', name: 'HIPAA', description: 'Health Insurance Portability and Accountability Act' },
  { id: 'sox', name: 'SOX', description: 'Sarbanes-Oxley Act' },
  { id: 'gdpr', name: 'GDPR', description: 'General Data Protection Regulation' },
  { id: 'cis', name: 'CIS', description: 'Center for Internet Security Benchmarks' },
  { id: 'hitrust', name: 'HITRUST', description: 'Health Information Trust Alliance' },
  { id: 'nist', name: 'NIST 800-53', description: 'National Institute of Standards and Technology' },
  { id: 'iso27001', name: 'ISO 27001', description: 'Information Security Management' }
];

interface ValidatePolicyProps {
  awsCredentials: AWSCredentials | null;
  onOpenCredentialsModal: () => void;
}

const ValidatePolicy: React.FC<ValidatePolicyProps> = ({ awsCredentials: propCredentials, onOpenCredentialsModal }) => {
  // State management
  const [inputType, setInputType] = useState<'policy' | 'arn'>('policy');
  const [inputValue, setInputValue] = useState('');
  const [response, setResponse] = useState<ValidatePolicyResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [validationStep, setValidationStep] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [showInitialForm, setShowInitialForm] = useState(true);
  
  // Selected compliance frameworks (default ones checked)
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>(['pci_dss', 'hipaa', 'sox', 'gdpr']);
  const [showFrameworkSelector, setShowFrameworkSelector] = useState(false);
  
  // Enhancement chat state
  const [enhancementChat, setEnhancementChat] = useState<EnhancementMessage[]>([]);
  const [enhancementInput, setEnhancementInput] = useState('');
  const [enhancementLoading, setEnhancementLoading] = useState(false);
  const [isChatbotOpen, setIsChatbotOpen] = useState(false);
  const [isChatbotExpanded, setIsChatbotExpanded] = useState(false);
  
  // Expandable sections
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const [showScoreBreakdown, setShowScoreBreakdown] = useState(true); // Expanded by default
  const [expandedPolicies, setExpandedPolicies] = useState<Set<string>>(new Set()); // For attached policies
  const [showTrustPolicy, setShowTrustPolicy] = useState(false); // Collapsed by default
  const [showSecurityFindings, setShowSecurityFindings] = useState(true); // Expanded by default
  
  // Use app-level credentials (passed as props)
  const awsCredentials = propCredentials;
  
  const chatEndRef = useRef<HTMLDivElement>(null);
  
  // ============================================
  // PERSISTENCE: Load saved state on mount
  // ============================================
  useEffect(() => {
    const saved = loadFromStorage<{
      inputType: 'policy' | 'arn';
      inputValue: string;
      response: ValidatePolicyResponse | null;
      selectedFrameworks: string[];
      enhancementChat: EnhancementMessage[];
      showInitialForm: boolean;
      isChatbotOpen: boolean;
    }>(STORAGE_KEYS.VALIDATE_POLICY);

    if (saved) {
      console.log('🔄 Restoring saved Validate Policy state');
      setInputType(saved.inputType || 'policy');
      setInputValue(saved.inputValue || '');
      setResponse(saved.response);
      setSelectedFrameworks(saved.selectedFrameworks || ['pci_dss', 'hipaa', 'sox', 'gdpr']);
      setEnhancementChat(saved.enhancementChat || []);
      setShowInitialForm(saved.showInitialForm ?? true);
      setIsChatbotOpen(saved.isChatbotOpen ?? false);
    }
  }, []); // Only run on mount

  // ============================================
  // PERSISTENCE: Save state whenever it changes
  // ============================================
  useEffect(() => {
    // Only save if we have meaningful data (response or chat)
    if (response || enhancementChat.length > 0) {
      const stateToSave = {
        inputType,
        inputValue,
        response,
        selectedFrameworks,
        enhancementChat,
        showInitialForm,
        isChatbotOpen
      };
      saveToStorage(STORAGE_KEYS.VALIDATE_POLICY, stateToSave, 24); // 24 hours expiry
    }
  }, [inputType, inputValue, response, selectedFrameworks, enhancementChat, showInitialForm, isChatbotOpen]);
  
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [enhancementChat]);

  // Animated step indicator for loading state
  useEffect(() => {
    if (loading) {
      setValidationStep(0);
      const id = window.setInterval(() => {
        setValidationStep(prev => (prev + 1) % 3);
      }, 1700);
      return () => window.clearInterval(id);
    } else {
      setValidationStep(0);
    }
  }, [loading]);

  // Helper function for security score grade - converts risk score (0-100, higher=worse) to security score (0-100, higher=better)
  const getSecurityScore = (riskScore: number) => {
    return 100 - riskScore; // Invert: 0 risk = 100 security, 100 risk = 0 security
  };

  // Helper function for security grade - MUST BE BEFORE handleValidation
  const getSecurityGrade = (securityScore: number) => {
    if (securityScore >= 70) return { 
      grade: 'A', 
      label: 'Excellent', 
      color: 'emerald', 
      bgClass: 'from-emerald-500/20 to-green-500/20', 
      borderClass: 'border-emerald-500/30' 
    };
    if (securityScore >= 40) return { 
      grade: 'B', 
      label: 'Good', 
      color: 'blue', 
      bgClass: 'from-blue-500/20 to-cyan-500/20', 
      borderClass: 'border-blue-500/30' 
    };
    if (securityScore >= 20) return { 
      grade: 'C', 
      label: 'Moderate', 
      color: 'orange', 
      bgClass: 'from-orange-500/20 to-red-500/20', 
      borderClass: 'border-orange-500/30' 
    };
    return { 
      grade: 'F', 
      label: 'Needs Improvement', 
      color: 'red', 
      bgClass: 'from-red-500/20 to-rose-500/20', 
      borderClass: 'border-red-500/30' 
    };
  };

  const toggleFramework = (frameworkId: string) => {
    setSelectedFrameworks(prev => 
      prev.includes(frameworkId)
        ? prev.filter(id => id !== frameworkId)
        : [...prev, frameworkId]
    );
  };

  const handleValidation = async () => {
    console.log('🔍 handleValidation called');
    console.log('📝 inputType:', inputType);
    console.log('📝 inputValue length:', inputValue.length);
    console.log('📝 inputValue preview:', inputValue.substring(0, 100));
    
    // CRITICAL: Check for AWS credentials first
    if (!awsCredentials) {
      setError('Please configure your AWS credentials first');
      onOpenCredentialsModal();
      return;
    }
    
    // Clean the input - remove markdown code fences if present
    let cleanedInput = inputValue.trim();
    if (cleanedInput.startsWith('```json') || cleanedInput.startsWith('```')) {
      cleanedInput = cleanedInput.replace(/^```(json)?\n?/, '').replace(/```\s*$/, '').trim();
      console.log('✨ Removed markdown code fences');
    }
    
    // Validate JSON if it's a policy
    if (inputType === 'policy') {
      try {
        JSON.parse(cleanedInput);
      } catch (e) {
        setError('Invalid JSON format. Please paste valid IAM policy JSON (without markdown code fences).');
        return;
      }
    }
    
    setLoading(true);
    setError(null);
    setShowInitialForm(false);
    
    try {
      const response = await fetch('http://localhost:8000/api/validate/quick', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input_type: inputType,
          input_value: cleanedInput,
          compliance_frameworks: selectedFrameworks,
          aws_credentials: awsCredentials || undefined
        })
      });
      
      const data = await response.json();
      
      // Check for errors in response
      if (data.error || data.success === false || !data.risk_score) {
        setError(data.error || 'Validation failed. Please check your input and try again.');
        setShowInitialForm(true);
        return;
      }
      
      // Ensure role_details is included in response if validating via ARN
      if (inputType === 'arn' && inputValue) {
        if (!data.role_details) {
          // Extract role name from ARN as fallback
          const rolePath = inputValue.split(':role/')[1] || '';
          const roleName = rolePath.split('/').pop() || rolePath;
          data.role_details = {
            role_arn: inputValue,
            role_name: roleName
          };
        }
        // Log for debugging
        console.log('📋 Role details in response:', data.role_details);
        console.log('   Attached policies:', data.role_details?.attached_policies?.length || 0);
        console.log('   Inline policies:', data.role_details?.inline_policies?.length || 0);
        if (data.role_details?.attached_policies) {
          console.log('   Attached policy names:', data.role_details.attached_policies.map((p: any) => p.name));
        }
      }
      
      // Ensure compliance_status is an object (not null/undefined)
      if (!data.compliance_status || typeof data.compliance_status !== 'object' || Object.keys(data.compliance_status).length === 0) {
        // Check if it's in a nested location
        if (data.validation && data.validation.compliance_status) {
          data.compliance_status = data.validation.compliance_status;
          console.log('📋 Found compliance_status in validation object:', Object.keys(data.compliance_status));
        } else {
          data.compliance_status = {};
          console.log('⚠️ compliance_status was empty, initialized as empty object');
        }
      } else {
        console.log('📋 Compliance frameworks in response:', Object.keys(data.compliance_status));
      }
      
      // Ensure recommendations and quick_wins are arrays
      if (!Array.isArray(data.recommendations)) {
        if (data.validation && Array.isArray(data.validation.recommendations)) {
          data.recommendations = data.validation.recommendations;
        } else {
          data.recommendations = [];
        }
      }
      if (!Array.isArray(data.quick_wins)) {
        if (data.validation && Array.isArray(data.validation.quick_wins)) {
          data.quick_wins = data.validation.quick_wins;
        } else {
          data.quick_wins = [];
        }
      }
      
      console.log('📋 Recommendations count:', data.recommendations?.length || 0);
      console.log('📋 Quick wins count:', data.quick_wins?.length || 0);
      
      setResponse(data);
      
      // Auto-open chatbot with dynamic greeting based on actual findings
      setTimeout(() => {
        // Generate dynamic greeting based on actual findings
        const criticalCount = data.findings.filter((f: SecurityFinding) => f.severity === 'Critical').length;
        const highCount = data.findings.filter((f: SecurityFinding) => f.severity === 'High').length;
        const mediumCount = data.findings.filter((f: SecurityFinding) => f.severity === 'Medium').length;
        const lowCount = data.findings.filter((f: SecurityFinding) => f.severity === 'Low').length;
        const securityScore = getSecurityScore(data.risk_score);
        const securityGrade = getSecurityGrade(securityScore);
        const hasCriticalIssues = criticalCount > 0 || highCount > 0;
        const hasQuickWins = data.quick_wins && data.quick_wins.length > 0;
        const hasRecommendations = data.recommendations && data.recommendations.length > 0;
        
        const suggestions: string[] = [];
        if (hasCriticalIssues) {
          suggestions.push(`**"Fix all ${criticalCount > 0 ? 'critical' : 'high'} issues"** - Automatically remediate ${criticalCount > 0 ? 'critical' : 'high'}-risk vulnerabilities`);
        }
        const hasWildcards = data.findings.some((f: SecurityFinding) => 
          f.type?.toLowerCase().includes('wildcard') || 
          f.description?.toLowerCase().includes('wildcard') ||
          f.code_snippet?.includes('*')
        );
        if (hasWildcards) {
          suggestions.push(`**"Remove wildcards"** - Replace * with specific permissions`);
        }
        const hasTrustPolicyIssues = data.findings.some((f: SecurityFinding) => 
          f.type?.toLowerCase().includes('trust') || 
          f.title?.toLowerCase().includes('trust')
        );
        if (hasTrustPolicyIssues) {
          suggestions.push(`**"Fix trust policy"** - Improve assume role policy security`);
        }
        const hasS3Issues = data.findings.some((f: SecurityFinding) => 
          f.type?.toLowerCase().includes('s3') || 
          f.description?.toLowerCase().includes('s3')
        );
        if (hasS3Issues) {
          suggestions.push(`**"Improve S3 permissions"** - Enhance S3 access controls`);
        }
        if (hasQuickWins) {
          suggestions.push(`**"Implement quick wins"** - Apply ${data.quick_wins.length} immediate security improvements`);
        }
        if (hasRecommendations) {
          suggestions.push(`**"Apply recommendations"** - Implement ${data.recommendations.length} long-term security improvements`);
        }
        if (data.findings.length > 0) {
          suggestions.push(`**"Explain finding ${data.findings[0]?.id || 'IAM-001'}"** - Get detailed explanation of this finding`);
        }
        suggestions.push(`**"Rewrite this policy"** - Generate a secure version from scratch`);
        
        let greetingContent = `🔒 **Analysis Complete!** I'm Aegis AI, your intelligent security assistant.\n\n`;
        greetingContent += `**Your Policy Assessment:**\n`;
        greetingContent += `• Security Score: **${securityScore}/100** (${securityGrade.label})\n`;
        greetingContent += `• Total Findings: **${data.findings.length}** security ${data.findings.length === 1 ? 'issue' : 'issues'}\n`;
        greetingContent += `• Critical: **${criticalCount}** | High: **${highCount}** | Medium: **${mediumCount}** | Low: **${lowCount}**\n\n`;
        if (hasCriticalIssues) {
          greetingContent += `⚠️ **Action Required:** Your role has ${criticalCount > 0 ? 'critical' : 'high'}-severity security issues that need immediate attention.\n\n`;
        } else if (securityScore >= 80) {
          greetingContent += `✅ **Excellent Security Posture:** Your role follows AWS security best practices with minimal issues.\n\n`;
        } else {
          greetingContent += `📊 **Security Review:** Your role has some areas for improvement.\n\n`;
        }
        greetingContent += `**I can help you:**\n\n`;
        suggestions.forEach(suggestion => {
          greetingContent += `• ${suggestion}\n`;
        });
        greetingContent += `\n**Try one of the quick actions below or ask me anything!**`;
        
        const greeting: EnhancementMessage = {
          role: 'assistant',
          content: greetingContent,
          timestamp: new Date().toISOString()
        };
        setEnhancementChat([greeting]);
      }, 500);
    } catch (err) {
      setError('Failed to validate policy. Please try again.');
      setShowInitialForm(true);
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleEnhancementSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!enhancementInput.trim()) return;
    
    const userMessage: EnhancementMessage = {
      role: 'user',
      content: enhancementInput,
      timestamp: new Date().toISOString()
    };
    
    setEnhancementChat([...enhancementChat, userMessage]);
    setEnhancementInput('');
    setEnhancementLoading(true);
    
    // Check if user is asking for additional frameworks
    const askingForFrameworks = enhancementInput.toLowerCase().includes('framework') || 
                                  enhancementInput.toLowerCase().includes('hitrust') ||
                                  enhancementInput.toLowerCase().includes('nist') ||
                                  enhancementInput.toLowerCase().includes('iso');
    
    // Simulate AI response
    setTimeout(() => {
      let aiResponse = '';
      
      if (askingForFrameworks) {
        aiResponse = `I can validate your policy against additional compliance frameworks!\n\nAvailable frameworks:\n• HITRUST - Healthcare security framework\n• NIST 800-53 - Government security controls\n• ISO 27001 - International security standard\n\nWould you like me to run validation against any of these? Just let me know which ones!`;
      } else {
        aiResponse = `I've updated your policy based on your request: "${enhancementInput}"\n\nKey improvements:\n• Replaced wildcard permissions with specific actions\n• Added resource-level ARN restrictions\n• Included security conditions\n\nThe new risk score is estimated at 20/100 (improved from ${response?.risk_score}/100).\n\nWould you like me to show you the updated policy?`;
      }
      
      const aiMessage: EnhancementMessage = {
        role: 'assistant',
        content: aiResponse,
        timestamp: new Date().toISOString()
      };
      setEnhancementChat(prev => [...prev, aiMessage]);
      setEnhancementLoading(false);
    }, 1500);
  };

  const toggleFindingExpansion = (findingId: string) => {
    setExpandedFindings(prev => {
      const newSet = new Set(prev);
      if (newSet.has(findingId)) {
        newSet.delete(findingId);
      } else {
        newSet.add(findingId);
      }
      return newSet;
    });
  };

  // Premium Light Theme - getSeverityColor
  const getSeverityColor = (severity: SecurityFinding['severity']) => {
    switch (severity) {
      case 'Critical': return { 
        bg: 'bg-white/80', 
        border: 'border-red-200/50', 
        icon: 'bg-red-500/10 border-red-200/50', 
        text: 'text-red-600',
        badge: 'bg-red-500/10 text-red-700 border-red-200/50'
      };
      case 'High': return { 
        bg: 'bg-white/80', 
        border: 'border-orange-200/50', 
        icon: 'bg-orange-500/10 border-orange-200/50', 
        text: 'text-orange-600',
        badge: 'bg-orange-500/10 text-orange-700 border-orange-200/50'
      };
      case 'Medium': return { 
        bg: 'bg-white/80', 
        border: 'border-yellow-200/50', 
        icon: 'bg-yellow-500/10 border-yellow-200/50', 
        text: 'text-yellow-600',
        badge: 'bg-yellow-500/10 text-yellow-700 border-yellow-200/50'
      };
      case 'Low': return { 
        bg: 'bg-white/80', 
        border: 'border-slate-200/50', 
        icon: 'bg-slate-500/10 border-slate-200/50', 
        text: 'text-slate-600',
        badge: 'bg-slate-500/10 text-slate-700 border-slate-200/50'
      };
    }
  };

  // Get dynamic impact description - Only use backend-provided detailed_explanation
  // No hardcoded scenarios or fear-mongering - let backend AI generate context-appropriate explanations
  const getSpecificImpact = (finding: SecurityFinding) => {
    // Only show detailed explanation if backend provides it
    // This ensures explanations are dynamic, specific to the finding, and context-appropriate
    if (finding.detailed_explanation && finding.detailed_explanation.trim().length > 0) {
      return {
        impact: finding.detailed_explanation,
        hasExplanation: true
      };
    }
    
    // If no detailed explanation from backend, don't show impact sections
    // The finding description is already shown above and is specific enough
    return null;
  };

  return (
    <div className="min-h-screen relative overflow-hidden">
      {/* Premium Animated Background - Light Theme */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 right-0 w-[800px] h-[800px] bg-gradient-to-br from-blue-400/8 via-purple-400/6 to-pink-400/4 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 left-0 w-[700px] h-[700px] bg-gradient-to-tr from-amber-400/6 via-orange-400/4 to-red-400/3 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '2s' }}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-br from-emerald-400/5 via-cyan-400/4 to-blue-400/3 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '4s' }}></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-8 py-12 sm:py-20">
        {/* ============================================ */}
        {/* INITIAL FORM */}
        {/* ============================================ */}
        {showInitialForm && !response && (
          <div className="relative">
            {/* Hero Section */}
            <div className="mb-16 animate-fadeIn text-center">
              <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-200 rounded-full px-6 py-2 mb-6 backdrop-blur-sm">
                <Shield className="w-4 h-4 text-blue-600" />
                <span className="text-blue-700 text-sm font-semibold">AI-Powered Security Analysis</span>
              </div>
              
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent mb-4 sm:mb-6 leading-tight tracking-tight px-4">
                Validate IAM<br />
                <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
                  Security Policies
                </span>
              </h1>
              
              <p className="text-base sm:text-lg lg:text-xl text-slate-600 max-w-3xl mx-auto leading-relaxed font-medium px-4">
                Deep security analysis powered by AI agents. Get instant risk assessment, 
                compliance validation, and actionable recommendations.
              </p>
              
              {/* AWS Credentials Status */}
              <div className="mt-6 flex justify-center">
                {awsCredentials ? (
                  <div className="inline-flex items-center gap-3 bg-gradient-to-r from-green-50 to-emerald-50 border-2 border-green-200 rounded-xl px-5 py-3 shadow-sm">
                    <CheckCircle className="w-5 h-5 text-green-600" />
                    <div className="flex flex-col sm:flex-row sm:items-center sm:gap-3">
                      <span className="text-sm font-semibold text-green-900">
                        AWS Configured: {getRegionDisplayName(awsCredentials.region)}
                      </span>
                      <span className="text-xs text-green-700 font-mono">
                        {maskAccessKeyId(awsCredentials.access_key_id)}
                      </span>
                    </div>
                    <button
                      onClick={() => onOpenCredentialsModal()}
                      className="ml-2 text-green-700 hover:text-green-900 transition-colors"
                      title="Reconfigure credentials"
                    >
                      <Settings className="w-4 h-4" />
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => onOpenCredentialsModal()}
                    className="inline-flex items-center gap-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-semibold px-6 py-3 rounded-xl shadow-lg transition-all duration-300 transform hover:scale-105"
                  >
                    <Key className="w-5 h-5" />
                    Configure AWS Credentials
                  </button>
                )}
              </div>
            </div>

            {/* Main Input Form */}
            <div className="max-w-4xl mx-auto">
              <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-6 sm:p-8 lg:p-10 shadow-xl">
                {/* Input Type Selection */}
                <div className="mb-8">
                  <label className="block text-slate-900 text-lg font-bold mb-4">What would you like to validate?</label>
                  <div className="grid grid-cols-2 gap-4">
                    <button
                      onClick={() => setInputType('policy')}
                      className={`group px-6 py-6 rounded-2xl font-bold transition-all duration-300 ${
                        inputType === 'policy'
                          ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg hover:shadow-xl'
                          : 'bg-gradient-to-br from-white to-slate-50 text-slate-600 hover:text-slate-900 border-2 border-slate-200 hover:border-blue-300 hover:shadow-md'
                      }`}
                    >
                      <Shield className="w-8 h-8 mx-auto mb-2 group-hover:scale-110 transition-transform duration-300" />
                      <span className="block text-base">Policy JSON</span>
                      <span className="block text-xs opacity-75 mt-1">Paste your IAM policy</span>
                    </button>
                    <button
                      onClick={() => setInputType('arn')}
                      className={`group px-6 py-6 rounded-2xl font-bold transition-all duration-300 ${
                        inputType === 'arn'
                          ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg hover:shadow-xl'
                          : 'bg-gradient-to-br from-white to-slate-50 text-slate-600 hover:text-slate-900 border-2 border-slate-200 hover:border-blue-300 hover:shadow-md'
                      }`}
                    >
                      <Zap className="w-8 h-8 mx-auto mb-2 group-hover:scale-110 transition-transform duration-300" />
                      <span className="block text-base">Role ARN</span>
                      <span className="block text-xs opacity-75 mt-1">Fetch from AWS</span>
                    </button>
                  </div>
                </div>

                {/* Input Field */}
                {inputType === 'policy' ? (
                  <div className="mb-8">
                    <label className="block text-slate-900 text-lg font-bold mb-4">IAM Policy JSON</label>
                    <textarea
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      placeholder='{\n  "Version": "2012-10-17",\n  "Statement": [{\n    "Effect": "Allow",\n    "Action": "s3:GetObject",\n    "Resource": "arn:aws:s3:::my-bucket/*"\n  }]\n}'
                      className="w-full h-64 px-6 py-5 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-2xl text-slate-900 placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none resize-none font-mono text-sm leading-relaxed transition-all duration-300"
                    />
                  </div>
                ) : (
                  <div className="mb-8">
                    <label className="block text-slate-900 text-lg font-bold mb-4">IAM Role ARN</label>
                    <input
                      type="text"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      placeholder="arn:aws:iam::123456789012:role/MyRole"
                      className="w-full px-6 py-5 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-2xl text-slate-900 placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none font-mono text-base transition-all duration-300 shadow-sm"
                    />
                  </div>
                )}

                {/* Compliance Framework Selector */}
                <div className="mb-8">
                  <div className="flex items-center justify-between mb-4">
                    <label className="text-slate-900 text-lg font-bold">Compliance Frameworks</label>
                    <button
                      onClick={() => setShowFrameworkSelector(!showFrameworkSelector)}
                      className="text-blue-600 hover:text-blue-700 text-sm font-semibold flex items-center space-x-1 transition-colors"
                    >
                      <Settings className="w-4 h-4" />
                      <span>{showFrameworkSelector ? 'Hide' : 'Customize'}</span>
                    </button>
                  </div>
                  
                  {!showFrameworkSelector ? (
                    <div className="flex flex-wrap gap-2">
                      {AVAILABLE_FRAMEWORKS.filter(f => selectedFrameworks.includes(f.id)).map(framework => (
                        <div key={framework.id} className="px-4 py-2 bg-gradient-to-r from-blue-100 to-purple-100 border-2 border-blue-300 rounded-full text-blue-700 text-sm font-semibold">
                          {framework.name}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {AVAILABLE_FRAMEWORKS.map(framework => (
                        <label
                          key={framework.id}
                          className={`flex items-start space-x-3 p-4 rounded-xl cursor-pointer transition-all duration-300 ${
                            selectedFrameworks.includes(framework.id)
                              ? 'bg-gradient-to-r from-blue-50 to-purple-50 border-2 border-blue-400'
                              : 'bg-gradient-to-br from-white to-slate-50 border-2 border-slate-200 hover:border-blue-300'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={selectedFrameworks.includes(framework.id)}
                            onChange={() => toggleFramework(framework.id)}
                            className="w-5 h-5 mt-0.5 rounded-md border-2 border-slate-300 bg-white text-blue-600 focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 cursor-pointer transition-all hover:border-blue-400 checked:bg-blue-600 checked:border-blue-600"
                          />
                          <div className="flex-1">
                            <div className="text-slate-900 font-bold text-sm">{framework.name}</div>
                            <div className="text-slate-600 text-xs mt-0.5 font-medium">{framework.description}</div>
                          </div>
                        </label>
                      ))}
                    </div>
                  )}
                </div>

                {/* Submit Button */}
                <button
                  onClick={handleValidation}
                  disabled={loading || !inputValue.trim()}
                  className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white py-4 sm:py-5 px-6 sm:px-8 rounded-2xl font-bold text-base sm:text-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-[1.02] flex items-center justify-center space-x-3 group transform touch-manipulation"
                  style={{ minHeight: '44px' }}
                >
                  <Search className="w-6 h-6" />
                  <span>Analyze Security</span>
                  <Shield className="w-5 h-5 group-hover:rotate-12 transition-transform duration-300" />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ============================================ */}
        {/* LOADING STATE */}
        {/* ============================================ */}
        {loading && (
          <div className="relative min-h-screen flex items-center justify-center">
            <div className="text-center px-8 max-w-3xl">
              <div className="inline-flex items-center justify-center w-32 h-32 mb-10 relative">
                <div className="absolute inset-0 border-4 border-transparent border-t-blue-500 border-r-purple-500 rounded-full animate-spin"></div>
                <div className="absolute inset-2 border-4 border-transparent border-t-purple-500 border-r-pink-500 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '2s' }}></div>
                <div className="absolute inset-0 bg-gradient-to-br from-blue-500/20 via-purple-500/20 to-pink-500/20 rounded-full animate-ping"></div>
                <Shield className="w-16 h-16 text-blue-600 relative z-10 animate-pulse" />
              </div>
              
              <h2 className="text-4xl sm:text-5xl font-extrabold bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent mb-4 animate-pulse leading-tight pb-2">
                Deep Security Scan
              </h2>
              
              <p className="text-xl text-slate-600 mb-8 leading-relaxed font-medium max-w-2xl mx-auto">
                Analyzing your IAM policy for vulnerabilities and compliance issues...
              </p>
              
              {/* Step indicators */}
              <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-8">
                {['Checking security controls', 'Validating compliance', 'Calculating risk score'].map((label, idx) => {
                  const isCurrent = validationStep === idx;
                  const isDone = validationStep > idx;
                  return (
                    <div key={label} className="flex items-center w-full sm:w-auto">
                      <div
                        className={`flex items-center space-x-3 px-4 py-3 rounded-xl border-2 shadow-lg transition-all w-full sm:w-64 ${
                          isCurrent
                            ? 'bg-white/90 backdrop-blur-xl border-blue-300 shadow-blue-100'
                            : 'bg-white/70 border-slate-200'
                        }`}
                      >
                        <div
                          className={`w-3 h-3 rounded-full ${
                            isCurrent
                              ? 'bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 animate-pulse'
                              : isDone
                              ? 'bg-blue-400'
                              : 'bg-slate-300'
                          }`}
                        ></div>
                        <div className="text-left">
                          <div className="text-xs font-semibold text-slate-500">Step {idx + 1} of 3</div>
                          <div className={`text-sm font-bold ${isCurrent ? 'text-slate-900' : 'text-slate-600'}`}>
                            {label}...
                          </div>
                        </div>
                      </div>
                      {idx < 2 && (
                        <div className="hidden sm:block w-10 h-0.5 bg-gradient-to-r from-blue-200 via-purple-200 to-pink-200 mx-2"></div>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Security Tips while loading */}
              <div className="mt-8">
                <SecurityTips rotationInterval={4000} />
              </div>
            </div>
          </div>
        )}

        {/* ============================================ */}
        {/* RESULTS */}
        {/* ============================================ */}
        {!loading && response && (
          <div className="relative">
            {/* Premium Header - Matching Audit Account */}
            <div className="flex flex-col items-center justify-center mb-16 animate-fadeIn">
              <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-200 rounded-full px-4 py-1.5 mb-6 backdrop-blur-sm">
                <Shield className="w-4 h-4 text-blue-600" />
                <span className="text-blue-700 text-sm font-semibold">Security Analysis Complete</span>
              </div>
              <h1 className="text-6xl font-extrabold bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent mb-4 tracking-tight leading-tight text-center">
                Policy Validation Results
              </h1>
              <div className="w-32 h-1.5 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 mx-auto rounded-full mb-8 shadow-lg"></div>
              <div className="flex items-center justify-center gap-4">
                <button
                  onClick={() => {
                    setResponse(null);
                    setInputValue('');
                    setShowInitialForm(true);
                    setEnhancementChat([]);
                    setExpandedFindings(new Set());
                  }}
                  className="group relative px-6 py-3 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white rounded-xl transition-all duration-300 shadow-xl hover:shadow-2xl hover:scale-105 flex items-center space-x-2"
                >
                  <RefreshCw className="w-4 h-4 group-hover:rotate-180 transition-transform duration-500" />
                  <span className="font-bold">New Analysis</span>
                </button>
              </div>
            </div>

            {/* PREMIUM SECURITY RISK SCORE - Matching Audit Account Design */}
            {(() => {
              const riskScore = response.risk_score || 0;
              const grade = getSecurityGrade(riskScore);
              
              // Color scheme based on score
              const getScoreColors = (score: number) => {
                if (score <= 30) {
                  return {
                    bg: 'from-emerald-50 to-green-50',
                    border: 'border-emerald-300',
                    scoreGradient: 'from-emerald-500 to-green-500',
                    scoreText: 'text-emerald-600',
                    badge: 'from-emerald-500/20 to-green-500/20 text-emerald-600 border-emerald-500/40',
                    status: 'bg-emerald-100 text-emerald-800'
                  };
                } else if (score <= 60) {
                  return {
                    bg: 'from-blue-50 to-cyan-50',
                    border: 'border-blue-300',
                    scoreGradient: 'from-blue-500 to-cyan-500',
                    scoreText: 'text-blue-600',
                    badge: 'from-blue-500/20 to-cyan-500/20 text-blue-600 border-blue-500/40',
                    status: 'bg-blue-100 text-blue-800'
                  };
                } else if (score <= 80) {
                  return {
                    bg: 'from-amber-50 to-orange-50',
                    border: 'border-amber-300',
                    scoreGradient: 'from-amber-500 to-orange-500',
                    scoreText: 'text-amber-600',
                    badge: 'from-amber-500/20 to-orange-500/20 text-amber-600 border-amber-500/40',
                    status: 'bg-amber-100 text-amber-800'
                  };
                } else {
                  return {
                    bg: 'from-red-50 to-rose-50',
                    border: 'border-red-300',
                    scoreGradient: 'from-red-500 to-rose-500',
                    scoreText: 'text-red-600',
                    badge: 'from-red-500/20 to-rose-500/20 text-red-600 border-red-500/40',
                    status: 'bg-red-100 text-red-800'
                  };
                }
              };
              
              const colors = getScoreColors(riskScore);
              
              return (
                <div className="relative max-w-full mx-auto mb-16">
                  {/* Enhanced gradient background with multiple layers */}
                  <div className="absolute inset-0 bg-gradient-to-br from-blue-500/8 via-purple-500/8 to-pink-500/8 rounded-3xl blur-3xl -z-10"></div>
                  <div className="absolute inset-0 bg-gradient-to-tr from-transparent via-white/20 to-transparent rounded-3xl -z-10"></div>
                  
                  {/* Main card - Ultra-premium with refined spacing */}
                  <div className="relative bg-white/90 backdrop-blur-2xl border-2 border-blue-200/60 rounded-3xl p-8 shadow-2xl hover:shadow-3xl transition-all duration-500 overflow-hidden">
                    {/* Enhanced top accent bar with glow */}
                    <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 shadow-lg"></div>
                    
                    {/* Row 1: Clean & Balanced Top Section */}
                    <div className="flex items-center justify-between gap-8 mb-6">
                      {/* Left: Label Only */}
                      <div className="flex items-center gap-4 flex-shrink-0">
                        <div className="flex flex-col gap-1">
                          <div className="text-slate-700 text-sm font-black uppercase tracking-widest">Security Score</div>
                          <div className="text-xs text-slate-500 font-medium">Higher = Better Security</div>
                        </div>
                      </div>
                      
                      {/* Center: Massive Score */}
                      <div className="flex items-baseline gap-4 flex-1 justify-center">
                        <span 
                          className={`text-8xl font-bold leading-none drop-shadow-lg`}
                          style={{
                            background: riskScore <= 30 
                              ? 'linear-gradient(135deg, #10b981, #3b82f6)' 
                              : riskScore <= 60
                              ? 'linear-gradient(135deg, #3b82f6, #8b5cf6)'
                              : riskScore <= 80
                              ? 'linear-gradient(135deg, #f59e0b, #f97316)'
                              : 'linear-gradient(135deg, #ef4444, #ec4899)',
                            WebkitBackgroundClip: 'text',
                            WebkitTextFillColor: 'transparent',
                            backgroundClip: 'text',
                            filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.1))'
                          }}
                        >
                          {riskScore}
                        </span>
                        <span className="text-3xl text-slate-400 font-semibold pb-2">/100</span>
                      </div>
                      
                      {/* Right: Single Grade Badge */}
                      <div className={`inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-bold ${colors.status} shadow-md flex-shrink-0 ring-2 ring-opacity-20 ${colors.status.includes('red') ? 'ring-red-200' : colors.status.includes('orange') ? 'ring-orange-200' : colors.status.includes('blue') ? 'ring-blue-200' : 'ring-green-200'}`}>
                        <span className="text-base">Grade {grade.grade}</span>
                        <span className="opacity-50">•</span>
                        <span className="text-xs">{grade.label}</span>
                      </div>
                    </div>
                    
                    {/* Row 2: Refined Bottom Section */}
                    <div className="flex items-center justify-between gap-8 pt-6 border-t-2 border-slate-200/60">
                      {/* Left: Risk Level */}
                      <div className="flex flex-col gap-1.5 flex-shrink-0 min-w-[140px]">
                        <div className="text-slate-600 text-xs font-semibold uppercase tracking-wide">Risk Level</div>
                        <div className="text-slate-800 text-lg font-bold">{riskScore}% <span className="text-sm font-normal text-slate-500">risk</span></div>
                      </div>
                      
                      {/* Center: Enhanced Progress Bar */}
                      <div className="flex-1 max-w-2xl flex flex-col gap-2">
                        <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                          <span className="font-medium">Progress</span>
                          <span className="font-bold text-slate-700">{riskScore}%</span>
                        </div>
                        <div className="relative w-full bg-gradient-to-r from-slate-100 via-slate-50 to-slate-100 rounded-full h-3 overflow-hidden border border-slate-200 shadow-inner">
                          <div
                            className={`h-full bg-gradient-to-r ${colors.scoreGradient} rounded-full transition-all duration-1000 ease-out shadow-lg relative overflow-hidden`}
                            style={{ width: `${riskScore}%` }}
                          >
                            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer"></div>
                          </div>
                        </div>
                      </div>
                      
                      {/* Right: Findings Count */}
                      <div className="flex items-center gap-6 text-sm flex-shrink-0">
                        <div className="flex flex-col items-end gap-1">
                          <div className="text-slate-500 text-xs font-medium uppercase tracking-wide">Total Findings</div>
                          <div className="flex items-center gap-2">
                            <span className="text-slate-800 font-black text-xl">{response.findings.length}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* ROLE DETAILS SECTION - Show when validating via ARN */}
            {inputType === 'arn' && inputValue && (
              <div className="mb-16">
                <div className="flex items-center space-x-3 mb-8">
                  <div className="flex-1">
                    <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                      <Database className="w-7 h-7 text-blue-600" />
                      <span>IAM Role Details</span>
                    </h3>
                    <p className="text-slate-600 text-sm mt-2 font-medium">Role configuration and attached policies</p>
                  </div>
                </div>
                
                <div className="bg-gradient-to-br from-white via-blue-50/40 to-purple-50/40 backdrop-blur-xl border-2 border-blue-200/50 rounded-3xl p-8 shadow-2xl hover:shadow-3xl transition-all duration-500 relative overflow-hidden">
                  {/* Decorative gradient overlay */}
                  <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-blue-400/10 to-purple-400/10 rounded-full blur-3xl -z-0"></div>
                  <div className="absolute bottom-0 left-0 w-64 h-64 bg-gradient-to-tr from-purple-400/10 to-pink-400/10 rounded-full blur-3xl -z-0"></div>
                  
                  <div className="relative z-10 space-y-8">
                    {/* Role ARN & Name - Side by Side with Enhanced Design */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      {/* Role ARN */}
                      <div className="bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 rounded-2xl p-6 border-2 border-blue-200/50 shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-[1.02] hover:border-blue-300/50 relative overflow-hidden group">
                        <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-blue-400/20 to-indigo-400/20 rounded-full blur-2xl -z-0"></div>
                        <div className="relative z-10">
                          <div className="flex items-center space-x-3 mb-4">
                            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                              <Users className="w-6 h-6 text-white" />
                            </div>
                            <span className="text-slate-700 font-black text-sm uppercase tracking-wider">Role ARN</span>
                          </div>
                          <p className="text-slate-800 font-medium text-sm break-all bg-white/90 backdrop-blur-sm p-4 rounded-xl border-2 border-slate-200/50 shadow-inner group-hover:border-blue-300/50 transition-colors duration-300">{inputValue}</p>
                        </div>
                      </div>
                      
                      {/* Role Name */}
                      {response.role_details?.role_name && (
                        <div className="bg-gradient-to-br from-indigo-50 via-purple-50 to-blue-50 rounded-2xl p-6 border-2 border-indigo-200/50 shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-[1.02] hover:border-indigo-300/50 relative overflow-hidden group">
                          <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-indigo-400/20 to-purple-400/20 rounded-full blur-2xl -z-0"></div>
                          <div className="relative z-10">
                            <div className="flex items-center space-x-3 mb-4">
                              <div className="w-12 h-12 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                                <Users className="w-6 h-6 text-white" />
                              </div>
                              <span className="text-slate-700 font-black text-sm uppercase tracking-wider">Role Name</span>
                            </div>
                            <p className="text-slate-800 font-medium text-sm break-all bg-white/90 backdrop-blur-sm p-4 rounded-xl border-2 border-slate-200/50 shadow-inner group-hover:border-indigo-300/50 transition-colors duration-300">{response.role_details.role_name}</p>
                          </div>
                        </div>
                      )}
                    </div>
                    
                    {/* Trust Policy - Collapsible */}
                    {response.role_details?.trust_policy && (
                      <div>
                        <div className="flex items-center space-x-2 mb-4">
                          <Lock className="w-5 h-5 text-indigo-600" />
                          <span className="text-slate-700 font-black text-sm uppercase tracking-wider">
                            Trust Policy (Assume Role Policy)
                          </span>
                          <span className="px-3 py-1 bg-indigo-500/20 text-indigo-800 text-xs font-black rounded-full border-2 border-indigo-300/50 shadow-sm">
                            Found
                          </span>
                        </div>
                        <button
                          onClick={() => setShowTrustPolicy(!showTrustPolicy)}
                          className="w-full flex items-center justify-between mb-4 p-6 bg-gradient-to-br from-indigo-50 via-purple-50 to-blue-50 rounded-2xl border-2 border-indigo-200/50 hover:border-indigo-300/50 transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-[1.01] relative overflow-hidden group"
                        >
                          <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-indigo-400/20 to-purple-400/20 rounded-full blur-2xl -z-0"></div>
                          <div className="relative z-10 flex items-center space-x-3">
                            <div className="w-12 h-12 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                              <Lock className="w-6 h-6 text-white" />
                            </div>
                            <span className="text-slate-800 font-black text-base">
                              View Trust Policy Document
                            </span>
                          </div>
                          <div className="relative z-10">
                            {showTrustPolicy ? (
                              <ChevronUp className="w-6 h-6 text-indigo-700 group-hover:scale-110 transition-transform duration-300" />
                            ) : (
                              <ChevronDown className="w-6 h-6 text-indigo-700 group-hover:scale-110 transition-transform duration-300" />
                            )}
                          </div>
                        </button>
                        {showTrustPolicy && (
                          <div className="bg-gradient-to-br from-indigo-50 via-purple-50 to-blue-50 rounded-2xl p-6 border-2 border-indigo-200/50 animate-in slide-in-from-top duration-300 shadow-xl relative overflow-hidden">
                            <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-indigo-400/10 to-purple-400/10 rounded-full blur-2xl -z-0"></div>
                            <div className="relative z-10">
                              <div className="flex items-center space-x-3 mb-4">
                                <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center shadow-md">
                                  <FileSearch className="w-5 h-5 text-white" />
                                </div>
                                <span className="text-slate-800 font-black text-sm uppercase tracking-wider">Trust Policy Document</span>
                              </div>
                              <pre className="bg-white text-slate-900 p-5 rounded-xl border-2 border-slate-300 overflow-x-auto text-xs font-mono max-h-96 overflow-y-auto shadow-inner mb-4">
                                {JSON.stringify(response.role_details.trust_policy, null, 2)}
                              </pre>
                              <div className="bg-white/80 backdrop-blur-sm p-4 rounded-xl border-2 border-indigo-200/50">
                                <p className="text-slate-700 text-sm leading-relaxed font-medium">
                                  <strong className="text-indigo-700">About Trust Policy:</strong> The trust policy (also called assume role policy) defines which AWS services, IAM users, or other AWS accounts can assume this role. It's a critical security component that controls who can use the role's permissions. Without a properly configured trust policy, the role cannot be assumed, even if it has permissions attached.
                                </p>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                    
                    {/* Permissions Boundary - Always Show */}
                    <div>
                      <div className="flex items-center space-x-2 mb-4">
                        <Shield className="w-5 h-5 text-blue-600" />
                        <span className="text-slate-700 font-black text-sm uppercase tracking-wider">
                          Permissions Boundary
                        </span>
                        {response.role_details?.permissions_boundary_arn ? (
                          <span className="px-3 py-1 bg-blue-500/20 text-blue-800 text-xs font-black rounded-full border-2 border-blue-300/50 shadow-sm">
                            Set
                          </span>
                        ) : (
                          <span className="px-3 py-1 bg-slate-400/20 text-slate-700 text-xs font-black rounded-full border-2 border-slate-300/50 shadow-sm">
                            Not Set
                          </span>
                        )}
                      </div>
                      {response.role_details?.permissions_boundary_arn ? (
                        <div className="bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 rounded-2xl p-6 border-2 border-blue-200/50 shadow-lg hover:shadow-xl transition-all duration-300 relative overflow-hidden group">
                          <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-blue-400/20 to-indigo-400/20 rounded-full blur-2xl -z-0"></div>
                          <div className="relative z-10">
                            <div className="flex items-center space-x-3 mb-4">
                              <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                                <Shield className="w-6 h-6 text-white" />
                              </div>
                              <div className="flex-1">
                                <p className="text-slate-800 font-medium text-sm break-all bg-white/90 backdrop-blur-sm p-4 rounded-xl border-2 border-slate-200/50 shadow-inner">
                                  {response.role_details.permissions_boundary_arn}
                                </p>
                              </div>
                            </div>
                            <div className="bg-white/80 backdrop-blur-sm p-4 rounded-xl border-2 border-blue-200/50 mt-4">
                              <p className="text-slate-700 text-sm leading-relaxed font-medium">
                                <strong className="text-blue-700">About Permissions Boundary:</strong> A permissions boundary is an advanced IAM feature that sets the maximum permissions a role can have. It acts as a safety mechanism to prevent roles from exceeding their intended scope, even if attached policies grant broader permissions. This is particularly useful for delegating permission management while maintaining control over the maximum permissions allowed.
                              </p>
                            </div>
                          </div>
                        </div>
                      ) : (
                        <div className="bg-gradient-to-br from-blue-50/50 via-indigo-50/50 to-purple-50/50 rounded-2xl p-6 border-2 border-blue-200/30 shadow-lg hover:shadow-xl transition-all duration-300 relative overflow-hidden group">
                          <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-blue-400/10 to-indigo-400/10 rounded-full blur-2xl -z-0"></div>
                          <div className="relative z-10">
                            <div className="flex items-center space-x-3 mb-4">
                              <div className="w-12 h-12 bg-gradient-to-br from-blue-400/60 to-indigo-400/60 rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                                <Shield className="w-6 h-6 text-white" />
                              </div>
                              <div className="flex-1">
                                <p className="text-slate-600 font-medium text-sm bg-white/90 backdrop-blur-sm p-4 rounded-xl border-2 border-slate-200/50 shadow-inner italic">
                                  No permissions boundary configured
                                </p>
                              </div>
                            </div>
                            <div className="bg-white/80 backdrop-blur-sm p-4 rounded-xl border-2 border-blue-200/30 mt-4">
                              <p className="text-slate-700 text-sm leading-relaxed font-medium">
                                <strong className="text-blue-700">About Permissions Boundary:</strong> A permissions boundary is an advanced IAM feature that sets the maximum permissions a role can have. It acts as a safety mechanism to prevent roles from exceeding their intended scope, even if attached policies grant broader permissions. This is particularly useful for delegating permission management while maintaining control over the maximum permissions allowed.
                              </p>
                              <p className="text-slate-600 text-sm leading-relaxed font-medium mt-3">
                                <strong className="text-blue-700">Current Status:</strong> This role does not have a permissions boundary configured. While not required, setting a permissions boundary can provide an additional layer of security by limiting the maximum permissions the role can have.
                              </p>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                    
                    {/* Attached Policies - Collapsible */}
                    {response.role_details?.attached_policies && response.role_details.attached_policies.length > 0 && (
                      <div>
                        <div className="flex items-center space-x-2 mb-4">
                          <Shield className="w-5 h-5 text-indigo-600" />
                          <span className="text-slate-700 font-black text-sm uppercase tracking-wider">
                            Attached Managed Policies ({response.role_details.attached_policies.length})
                          </span>
                        </div>
                        <div className="space-y-3">
                          {response.role_details.attached_policies.map((policy, idx) => {
                            const policyId = `policy-${idx}-${policy.arn}`;
                            const isExpanded = expandedPolicies.has(policyId);
                            const hasDocument = policy.document && typeof policy.document === 'object';
                            
                            return (
                              <div key={idx} className="bg-gradient-to-br from-indigo-50 via-purple-50 to-blue-50 border-2 border-indigo-200/50 rounded-2xl overflow-hidden hover:border-indigo-300/50 transition-all duration-300 shadow-xl hover:shadow-2xl hover:scale-[1.01] relative group">
                                {/* Decorative gradient overlay */}
                                <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-indigo-400/20 to-purple-400/20 rounded-full blur-2xl -z-0"></div>
                                
                                {/* Policy Header - Clickable */}
                                <button
                                  onClick={() => {
                                    const newExpanded = new Set(expandedPolicies);
                                    if (isExpanded) {
                                      newExpanded.delete(policyId);
                                    } else {
                                      newExpanded.add(policyId);
                                    }
                                    setExpandedPolicies(newExpanded);
                                  }}
                                  className="w-full flex items-center justify-between p-6 hover:bg-indigo-50/60 transition-colors duration-200 relative z-10"
                                >
                                  <div className="flex items-start gap-4 flex-1 min-w-0">
                                    <div className="w-12 h-12 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center flex-shrink-0 shadow-lg group-hover:scale-110 transition-transform duration-300">
                                      <Lock className="w-6 h-6 text-white" />
                                    </div>
                                    <div className="flex-1 min-w-0">
                                      <div className="flex items-center gap-3 mb-2">
                                        <p className="text-slate-900 font-black text-base">{policy.name}</p>
                                        <span className="px-3 py-1 bg-indigo-500/20 text-indigo-800 text-xs font-black rounded-full border-2 border-indigo-300/50 shadow-sm">
                                          Managed
                                        </span>
                                      </div>
                                      <p className="text-slate-600 font-mono text-xs break-all bg-white/60 backdrop-blur-sm px-3 py-2 rounded-lg border border-slate-200/50">{policy.arn}</p>
                                    </div>
                                  </div>
                                  <div className="flex items-center gap-3 flex-shrink-0 ml-4">
                                    {isExpanded ? (
                                      <ChevronUp className="w-6 h-6 text-indigo-700 transition-transform duration-200 group-hover:scale-110" />
                                    ) : (
                                      <ChevronDown className="w-6 h-6 text-indigo-700 transition-transform duration-200 group-hover:scale-110" />
                                    )}
                                  </div>
                                </button>
                                
                                {/* Policy Document - Collapsible */}
                                {isExpanded && (
                                  <div className="border-t-2 border-indigo-200/50 bg-gradient-to-br from-indigo-50/80 via-purple-50/80 to-blue-50/80 backdrop-blur-sm p-6 animate-in slide-in-from-top duration-300 relative z-10">
                                    <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-indigo-400/10 to-purple-400/10 rounded-full blur-2xl -z-0"></div>
                                    {hasDocument ? (
                                      <>
                                        <div className="relative z-10 flex items-center space-x-3 mb-4">
                                          <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center shadow-md">
                                            <FileSearch className="w-5 h-5 text-white" />
                                          </div>
                                          <span className="text-slate-800 font-black text-sm uppercase tracking-wider">Policy Document</span>
                                        </div>
                                        <pre className="bg-white text-slate-900 p-5 rounded-xl border-2 border-slate-300 overflow-x-auto text-xs font-mono max-h-96 overflow-y-auto shadow-inner mb-4">
                                          {JSON.stringify(policy.document, null, 2)}
                                        </pre>
                                        <div className="bg-white/80 backdrop-blur-sm p-4 rounded-xl border-2 border-indigo-200/50">
                                          <p className="text-slate-700 text-sm leading-relaxed font-medium">
                                            <strong className="text-indigo-700">Permissions Policy:</strong> This is the full permissions policy document that defines what actions this role can perform.
                                          </p>
                                        </div>
                                      </>
                                    ) : (
                                      <div className="relative z-10 bg-yellow-50/80 backdrop-blur-sm p-4 rounded-xl border-2 border-yellow-200/50">
                                        <p className="text-slate-700 text-sm leading-relaxed font-medium">
                                          <strong className="text-yellow-700">Policy Document Not Available:</strong> The full policy document could not be retrieved from AWS. This may be due to:
                                        </p>
                                        <ul className="list-disc list-inside mt-2 space-y-1 text-slate-600 text-sm">
                                          <li>Insufficient IAM permissions (requires <code className="bg-yellow-100 px-1 rounded">iam:GetPolicy</code> and <code className="bg-yellow-100 px-1 rounded">iam:GetPolicyVersion</code>)</li>
                                          <li>AWS managed policies that require special access</li>
                                          <li>Network or MCP server connectivity issues</li>
                                        </ul>
                                        <p className="text-slate-700 text-sm leading-relaxed font-medium mt-3">
                                          <strong className="text-yellow-700">Note:</strong> The security analysis may be incomplete without the full policy document. The agent analyzes policies based on available documents, so missing documents could affect the accuracy of security findings.
                                        </p>
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                        <div className="mt-4 bg-white/80 backdrop-blur-sm p-4 rounded-xl border-2 border-indigo-200/50">
                          <p className="text-slate-700 text-sm leading-relaxed font-medium">
                            <strong className="text-indigo-700">About Managed Policies:</strong> Managed policies can be <strong>AWS managed</strong> (created and maintained by AWS) or <strong>customer managed</strong> (created by you or your organization). Both types are displayed above. Click on any policy to view its full document.
                          </p>
                        </div>
                      </div>
                    )}
                    
                    {/* Inline Policies */}
                    {response.role_details?.inline_policies && response.role_details.inline_policies.length > 0 && (
                      <div>
                        <div className="flex items-center space-x-2 mb-4">
                          <FileSearch className="w-5 h-5 text-blue-600" />
                          <span className="text-slate-700 font-bold text-sm uppercase tracking-wide">
                            Inline Policies ({response.role_details.inline_policies.length})
                          </span>
                        </div>
                        <div className="space-y-3">
                          {response.role_details.inline_policies.map((policy, idx) => (
                            <div key={idx} className="bg-slate-50 border-2 border-slate-200/50 rounded-xl p-4 hover:border-blue-200/50 transition-all duration-300">
                              <div className="flex items-start justify-between">
                                <div className="flex-1">
                                  <p className="text-slate-900 font-bold text-base">{policy.name}</p>
                                </div>
                                <span className="px-3 py-1 bg-purple-500/10 text-purple-700 text-xs font-bold rounded border border-purple-200/50">
                                  Inline
                                </span>
                              </div>
                            </div>
                          ))}
                        </div>
                        <p className="text-slate-600 text-sm mt-4 font-medium">
                          Inline policies are embedded directly in this role. These policies are combined with attached managed policies to form the effective permissions.
                        </p>
                      </div>
                    )}
                    
                    {/* No Policies Message */}
                    {(!response.role_details?.attached_policies || response.role_details.attached_policies.length === 0) &&
                     (!response.role_details?.inline_policies || response.role_details.inline_policies.length === 0) && (
                      <div className="bg-yellow-50 border-2 border-yellow-200/50 rounded-xl p-6 text-center">
                        <Info className="w-12 h-12 text-yellow-600 mx-auto mb-3" />
                        <p className="text-slate-700 font-semibold text-base mb-2">No Policies Found</p>
                        <p className="text-slate-600 text-sm">
                          This role does not have any attached managed policies or inline policies. The role may rely on service-linked roles or have no permissions configured.
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* RISK BREAKDOWN CARDS - Premium Light Theme */}
            <div className="mb-16 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              {/* Critical */}
              <div className="bg-white/80 backdrop-blur-xl border-2 border-red-200/50 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <XCircle className="w-6 h-6 text-red-600" />
                    <span className="text-red-700 font-bold text-sm uppercase tracking-wide">Critical</span>
                  </div>
                  <span className="text-4xl font-black text-red-600">
                    {response.findings.filter(f => f.severity === 'Critical').length}
                  </span>
                </div>
                <div className="text-xs text-slate-600 font-medium">Immediate action required</div>
              </div>

              {/* High */}
              <div className="bg-white/80 backdrop-blur-xl border-2 border-orange-200/50 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <AlertTriangle className="w-6 h-6 text-orange-600" />
                    <span className="text-orange-700 font-bold text-sm uppercase tracking-wide">High</span>
                  </div>
                  <span className="text-4xl font-black text-orange-600">
                    {response.findings.filter(f => f.severity === 'High').length}
                  </span>
                </div>
                <div className="text-xs text-slate-600 font-medium">High priority fixes</div>
              </div>

              {/* Medium */}
              <div className="bg-white/80 backdrop-blur-xl border-2 border-yellow-200/50 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <AlertCircle className="w-6 h-6 text-yellow-600" />
                    <span className="text-yellow-700 font-bold text-sm uppercase tracking-wide">Medium</span>
                  </div>
                  <span className="text-4xl font-black text-yellow-600">
                    {response.findings.filter(f => f.severity === 'Medium').length}
                  </span>
                </div>
                <div className="text-xs text-slate-600 font-medium">Should be addressed</div>
              </div>

              {/* Low */}
              <div className="bg-white/80 backdrop-blur-xl border-2 border-slate-200/50 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <Info className="w-6 h-6 text-slate-600" />
                    <span className="text-slate-700 font-bold text-sm uppercase tracking-wide">Low</span>
                  </div>
                  <span className="text-4xl font-black text-slate-600">
                    {response.findings.filter(f => f.severity === 'Low').length}
                  </span>
                </div>
                <div className="text-xs text-slate-600 font-medium">Minor improvements</div>
              </div>
            </div>

            {/* SCORE BREAKDOWN - Ultra-Premium Redesign */}
            <div className="mb-16">
              <div className="relative z-10">
                {/* Premium Subsection Header */}
                <div className="flex items-center space-x-3 mb-6">
                  <div className="flex-1 flex items-center justify-between">
                    <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                      <Shield className="w-7 h-7 text-blue-600" />
                      <span>Score Breakdown</span>
                    </h3>
                    <button
                      onClick={() => setShowScoreBreakdown(!showScoreBreakdown)}
                      className="group flex items-center space-x-2 px-5 py-2.5 bg-white/80 backdrop-blur-xl hover:bg-white/90 border-2 border-slate-200 hover:border-blue-300 rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105"
                    >
                      <span className="text-sm font-bold text-slate-700 group-hover:text-blue-600 transition-colors duration-300">
                        {showScoreBreakdown ? 'Hide Details' : 'Show Details'}
                      </span>
                      {showScoreBreakdown ? (
                        <ChevronUp className="w-4 h-4 text-slate-500 group-hover:text-blue-600 transition-colors duration-300" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500 group-hover:text-blue-600 transition-colors duration-300" />
                      )}
                    </button>
                  </div>
                </div>

                {showScoreBreakdown && (
                  <div className="mt-6 relative bg-white/90 backdrop-blur-2xl border-2 border-blue-200/50 rounded-3xl p-8 shadow-2xl hover:shadow-3xl transition-all duration-500 overflow-hidden animate-in slide-in-from-top duration-300">
                    {/* Gradient accent bar at top */}
                    <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 shadow-lg"></div>
                    
                    {/* Background gradient layers */}
                    <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-purple-500/5 to-pink-500/5 rounded-3xl -z-10"></div>
                    
                    <div className="relative">
                      <p className="text-slate-700 text-base leading-relaxed mb-8 font-semibold">
                        Your policy has the following issues contributing to this score:
                      </p>

                      {/* Critical Issues - Premium Design */}
                      {response.findings.filter(f => f.severity === 'Critical').length > 0 && (
                        <CollapsibleTile
                          title="Critical Issues"
                          subtitle="Requires immediate attention"
                          icon={
                            <div className="w-12 h-12 bg-gradient-to-br from-red-500/20 to-red-600/20 rounded-xl flex items-center justify-center border-2 border-red-200/50 shadow-lg">
                              <XCircle className="w-6 h-6 text-red-600" />
                            </div>
                          }
                          badge={
                            <div className="px-4 py-2 bg-red-500/10 border-2 border-red-200/50 rounded-xl">
                              <span className="text-red-700 font-black text-lg">
                                {response.findings.filter(f => f.severity === 'Critical').length}
                              </span>
                              <span className="text-red-600 text-xs font-semibold ml-1">
                                {response.findings.filter(f => f.severity === 'Critical').length === 1 ? 'issue' : 'issues'}
                              </span>
                            </div>
                          }
                          defaultExpanded={true}
                          variant="error"
                          className="mb-8"
                        >
                          <div className="space-y-3">
                            {response.findings.filter(f => f.severity === 'Critical').map((finding, idx) => (
                              <div key={idx} className="group relative bg-gradient-to-br from-red-50/80 to-white border-2 border-red-200/50 rounded-xl p-5 hover:border-red-300 hover:shadow-xl transition-all duration-300 hover:scale-[1.01]">
                                {/* Vertical accent bar */}
                                <div className="absolute left-0 top-0 bottom-0 w-1.5 bg-gradient-to-b from-red-500 to-red-600 rounded-l-xl"></div>
                                <div className="pl-4">
                                  <div className="flex items-start justify-between mb-2">
                                    <div className="font-black text-red-700 text-base mb-1">{finding.title}</div>
                                    <div className="px-2.5 py-1 bg-red-500/10 border border-red-200/50 rounded-lg">
                                      <span className="text-red-700 text-xs font-bold">Critical</span>
                                    </div>
                                  </div>
                                  <p className="text-slate-700 text-sm leading-relaxed font-medium">{finding.description}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </CollapsibleTile>
                      )}

                      {/* High Issues - Premium Design */}
                      {response.findings.filter(f => f.severity === 'High').length > 0 && (
                        <CollapsibleTile
                          title="High Issues"
                          subtitle="Should be addressed soon"
                          icon={
                            <div className="w-12 h-12 bg-gradient-to-br from-orange-500/20 to-orange-600/20 rounded-xl flex items-center justify-center border-2 border-orange-200/50 shadow-lg">
                              <AlertTriangle className="w-6 h-6 text-orange-600" />
                            </div>
                          }
                          badge={
                            <div className="px-4 py-2 bg-orange-500/10 border-2 border-orange-200/50 rounded-xl">
                              <span className="text-orange-700 font-black text-lg">
                                {response.findings.filter(f => f.severity === 'High').length}
                              </span>
                              <span className="text-orange-600 text-xs font-semibold ml-1">
                                {response.findings.filter(f => f.severity === 'High').length === 1 ? 'issue' : 'issues'}
                              </span>
                            </div>
                          }
                          defaultExpanded={true}
                          variant="warning"
                          className="mb-8"
                        >
                          <div className="space-y-3">
                            {response.findings.filter(f => f.severity === 'High').map((finding, idx) => (
                              <div key={idx} className="group relative bg-gradient-to-br from-orange-50/80 to-white border-2 border-orange-200/50 rounded-xl p-5 hover:border-orange-300 hover:shadow-xl transition-all duration-300 hover:scale-[1.01]">
                                {/* Vertical accent bar */}
                                <div className="absolute left-0 top-0 bottom-0 w-1.5 bg-gradient-to-b from-orange-500 to-orange-600 rounded-l-xl"></div>
                                <div className="pl-4">
                                  <div className="flex items-start justify-between mb-2">
                                    <div className="font-black text-orange-700 text-base mb-1">{finding.title}</div>
                                    <div className="px-2.5 py-1 bg-orange-500/10 border border-orange-200/50 rounded-lg">
                                      <span className="text-orange-700 text-xs font-bold">High</span>
                                    </div>
                                  </div>
                                  <p className="text-slate-700 text-sm leading-relaxed font-medium">{finding.description}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </CollapsibleTile>
                      )}

                      {/* Medium Issues - Premium Design */}
                      {response.findings.filter(f => f.severity === 'Medium').length > 0 && (
                        <CollapsibleTile
                          title="Medium Issues"
                          subtitle="Consider addressing"
                          icon={
                            <div className="w-12 h-12 bg-gradient-to-br from-yellow-500/20 to-yellow-600/20 rounded-xl flex items-center justify-center border-2 border-yellow-200/50 shadow-lg">
                              <AlertCircle className="w-6 h-6 text-yellow-600" />
                            </div>
                          }
                          badge={
                            <div className="px-4 py-2 bg-yellow-500/10 border-2 border-yellow-200/50 rounded-xl">
                              <span className="text-yellow-700 font-black text-lg">
                                {response.findings.filter(f => f.severity === 'Medium').length}
                              </span>
                              <span className="text-yellow-600 text-xs font-semibold ml-1">
                                {response.findings.filter(f => f.severity === 'Medium').length === 1 ? 'issue' : 'issues'}
                              </span>
                            </div>
                          }
                          defaultExpanded={false}
                          variant="warning"
                          className="mb-8"
                        >
                          <div className="space-y-3">
                            {response.findings.filter(f => f.severity === 'Medium').map((finding, idx) => (
                              <div key={idx} className="group relative bg-gradient-to-br from-yellow-50/80 to-white border-2 border-yellow-200/50 rounded-xl p-5 hover:border-yellow-300 hover:shadow-xl transition-all duration-300 hover:scale-[1.01]">
                                {/* Vertical accent bar */}
                                <div className="absolute left-0 top-0 bottom-0 w-1.5 bg-gradient-to-b from-yellow-500 to-yellow-600 rounded-l-xl"></div>
                                <div className="pl-4">
                                  <div className="flex items-start justify-between mb-2">
                                    <div className="font-black text-yellow-700 text-base mb-1">{finding.title}</div>
                                    <div className="px-2.5 py-1 bg-yellow-500/10 border border-yellow-200/50 rounded-lg">
                                      <span className="text-yellow-700 text-xs font-bold">Medium</span>
                                    </div>
                                  </div>
                                  <p className="text-slate-700 text-sm leading-relaxed font-medium">{finding.description}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </CollapsibleTile>
                      )}

                      {/* Low Issues - Premium Design */}
                      {response.findings.filter(f => f.severity === 'Low').length > 0 && (
                        <CollapsibleTile
                          title="Low Issues"
                          subtitle="Minor improvements"
                          icon={
                            <div className="w-12 h-12 bg-gradient-to-br from-slate-500/20 to-slate-600/20 rounded-xl flex items-center justify-center border-2 border-slate-200/50 shadow-lg">
                              <Info className="w-6 h-6 text-slate-600" />
                            </div>
                          }
                          badge={
                            <div className="px-4 py-2 bg-slate-500/10 border-2 border-slate-200/50 rounded-xl">
                              <span className="text-slate-700 font-black text-lg">
                                {response.findings.filter(f => f.severity === 'Low').length}
                              </span>
                              <span className="text-slate-600 text-xs font-semibold ml-1">
                                {response.findings.filter(f => f.severity === 'Low').length === 1 ? 'issue' : 'issues'}
                              </span>
                            </div>
                          }
                          defaultExpanded={false}
                          variant="default"
                          className="mb-8"
                        >
                          <div className="space-y-3">
                            {response.findings.filter(f => f.severity === 'Low').map((finding, idx) => (
                              <div key={idx} className="group relative bg-gradient-to-br from-slate-50/80 to-white border-2 border-slate-200/50 rounded-xl p-5 hover:border-slate-300 hover:shadow-xl transition-all duration-300 hover:scale-[1.01]">
                                {/* Vertical accent bar */}
                                <div className="absolute left-0 top-0 bottom-0 w-1.5 bg-gradient-to-b from-slate-400 to-slate-500 rounded-l-xl"></div>
                                <div className="pl-4">
                                  <div className="flex items-start justify-between mb-2">
                                    <div className="font-black text-slate-700 text-base mb-1">{finding.title}</div>
                                    <div className="px-2.5 py-1 bg-slate-500/10 border border-slate-200/50 rounded-lg">
                                      <span className="text-slate-700 text-xs font-bold">Low</span>
                                    </div>
                                  </div>
                                  <p className="text-slate-700 text-sm leading-relaxed font-medium">{finding.description}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </CollapsibleTile>
                      )}

                      {/* No Issues Found - Show when all findings are 0 */}
                      {response.findings.length === 0 && (
                        <div className="mb-8 bg-gradient-to-br from-emerald-50 to-green-50 border-2 border-emerald-200/50 rounded-2xl p-8 text-center">
                          <CheckCircle className="w-16 h-16 text-emerald-600 mx-auto mb-4" />
                          <h4 className="text-emerald-700 font-black text-2xl mb-3">No Security Issues Detected</h4>
                          <p className="text-slate-700 text-base leading-relaxed font-medium mb-4">
                            Your policy follows AWS security best practices. No vulnerabilities or misconfigurations were found.
                          </p>
                          <div className="mt-6 p-4 bg-white/80 rounded-xl border border-emerald-200">
                            <p className="text-sm text-slate-600">
                              <strong>Risk Score:</strong> {response.risk_score}/100 ({getSecurityGrade(response.risk_score).label})
                            </p>
                            <p className="text-sm text-slate-600 mt-2">
                              This score reflects excellent security posture with no findings requiring remediation.
                            </p>
                          </div>
                        </div>
                      )}

                      {/* Final Score Summary - Premium Design */}
                      <div className="pt-6 mt-6 border-t-2 border-slate-200/60">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            <div className="w-10 h-10 bg-gradient-to-br from-blue-500/10 to-purple-500/10 rounded-xl flex items-center justify-center border-2 border-blue-200/50">
                              <Shield className="w-5 h-5 text-blue-600" />
                            </div>
                            <div>
                              <span className="text-slate-600 text-sm font-bold uppercase tracking-wide">Final Risk Score</span>
                              <div className="mt-1">
                                <span className={`text-xs font-semibold ${
                                  response.risk_score <= 30 ? 'text-emerald-600' :
                                  response.risk_score <= 60 ? 'text-blue-600' :
                                  response.risk_score <= 80 ? 'text-orange-600' :
                                  'text-red-600'
                                }`}>
                                  {getSecurityGrade(response.risk_score).label}
                                </span>
                              </div>
                            </div>
                          </div>
                          <div className="text-right">
                            <span className={`font-black text-4xl leading-none ${
                              response.risk_score <= 30 ? 'text-emerald-600' :
                              response.risk_score <= 60 ? 'text-blue-600' :
                              response.risk_score <= 80 ? 'text-orange-600' :
                              'text-red-600'
                            }`}>
                              {response.risk_score}
                            </span>
                            <span className="text-slate-400 text-2xl font-semibold ml-1">/100</span>
                          </div>
                        </div>
                        {response.findings.length === 0 && (
                          <div className="mt-4 p-4 bg-blue-50 rounded-xl border border-blue-200">
                            <p className="text-sm text-slate-600 text-center">
                              <strong>Score Breakdown:</strong> No security issues found. Risk score of {response.risk_score}/100 indicates excellent security posture.
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* SECURITY FINDINGS - Premium Light Theme with Collapsible */}
            <div className="mb-16">
              {/* Premium Subsection Header with Collapse Toggle */}
              <div className="flex items-center justify-between mb-8">
                <div className="flex items-center space-x-3">
                  <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                    <Shield className="w-7 h-7 text-blue-600" />
                    <span>Security Findings</span>
                  </h3>
                  {response.findings.length > 0 && (
                    <span className="px-3 py-1 bg-blue-500/10 text-blue-700 text-sm font-bold rounded-full border border-blue-200/50">
                      {response.findings.length} {response.findings.length === 1 ? 'Finding' : 'Findings'}
                    </span>
                  )}
                </div>
                {response.findings.length > 3 && (
                  <button
                    onClick={() => setShowSecurityFindings(!showSecurityFindings)}
                    className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 hover:from-blue-500/20 hover:to-purple-500/20 border-2 border-blue-200/50 hover:border-blue-300/50 rounded-xl text-blue-700 hover:text-blue-900 text-sm font-semibold transition-all duration-300 shadow-sm hover:shadow-md"
                  >
                    <span>{showSecurityFindings ? 'Hide Details' : 'Show All Details'}</span>
                    {showSecurityFindings ? (
                      <ChevronUp className="w-4 h-4" />
                    ) : (
                      <ChevronDown className="w-4 h-4" />
                    )}
                  </button>
                )}
              </div>
              
              {response.findings.length === 0 && response.risk_score <= 10 ? (
                <div className="space-y-6">
                  {/* What's Great Section */}
                  <div className="bg-gradient-to-br from-emerald-50 to-green-50 border-2 border-emerald-200/50 rounded-2xl p-8 shadow-xl">
                    <div className="flex items-center space-x-3 mb-6">
                      <CheckCircle className="w-8 h-8 text-emerald-600" />
                      <h4 className="text-emerald-700 font-black text-2xl">What's Great About This Role</h4>
                    </div>
                    <div className="space-y-4">
                      <div className="bg-white/80 rounded-xl p-4 border border-emerald-200">
                        <p className="text-slate-700 text-base leading-relaxed font-medium">
                          ✅ <strong>No Critical Security Issues:</strong> Your role follows AWS security best practices with no critical vulnerabilities detected.
                        </p>
                      </div>
                      {response.role_details?.attached_policies && response.role_details.attached_policies.length > 0 && (
                        <div className="bg-white/80 rounded-xl p-4 border border-emerald-200">
                          <p className="text-slate-700 text-base leading-relaxed font-medium">
                            ✅ <strong>Managed Policies:</strong> Using {response.role_details.attached_policies.length} managed {response.role_details.attached_policies.length === 1 ? 'policy' : 'policies'} which are easier to maintain and audit than inline policies.
                          </p>
                        </div>
                      )}
                      {response.role_details?.trust_policy && (
                        <div className="bg-white/80 rounded-xl p-4 border border-emerald-200">
                          <p className="text-slate-700 text-base leading-relaxed font-medium">
                            ✅ <strong>Trust Policy Configured:</strong> Your role has a properly configured trust policy that defines who can assume this role.
                          </p>
                        </div>
                      )}
                      <div className="bg-white/80 rounded-xl p-4 border border-emerald-200">
                        <p className="text-slate-700 text-base leading-relaxed font-medium">
                          ✅ <strong>Low Risk Score:</strong> With a score of {response.risk_score}/100, this role represents excellent security posture.
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* What Could Be Improved Section */}
                  {response.risk_score > 0 && (
                    <div className="bg-gradient-to-br from-blue-50 to-purple-50 border-2 border-blue-200/50 rounded-2xl p-8 shadow-xl">
                      <div className="flex items-center space-x-3 mb-6">
                        <Sparkles className="w-8 h-8 text-blue-600" />
                        <h4 className="text-blue-700 font-black text-2xl">How to Improve to Perfect 0/100</h4>
                      </div>
                      <div className="space-y-4">
                        {response.quick_wins && response.quick_wins.length > 0 ? (
                          response.quick_wins.map((win, idx) => (
                            <div key={idx} className="bg-white/80 rounded-xl p-4 border border-blue-200">
                              <p className="text-slate-700 text-base leading-relaxed font-medium">
                                💡 {win}
                              </p>
                            </div>
                          ))
                        ) : (
                          <>
                            <div className="bg-white/80 rounded-xl p-4 border border-blue-200">
                              <p className="text-slate-700 text-base leading-relaxed font-medium">
                                💡 <strong>Add Resource Restrictions:</strong> Replace wildcard resources (*) with specific ARNs to follow least privilege principle.
                              </p>
                            </div>
                            <div className="bg-white/80 rounded-xl p-4 border border-blue-200">
                              <p className="text-slate-700 text-base leading-relaxed font-medium">
                                💡 <strong>Enforce MFA:</strong> Add MFA requirements for sensitive operations to add an extra layer of security.
                              </p>
                            </div>
                            <div className="bg-white/80 rounded-xl p-4 border border-blue-200">
                              <p className="text-slate-700 text-base leading-relaxed font-medium">
                                💡 <strong>Enable CloudTrail Logging:</strong> Ensure all API calls are logged for audit and compliance purposes.
                              </p>
                            </div>
                          </>
                        )}
                        {response.recommendations && response.recommendations.length > 0 && (
                          <>
                            <div className="mt-4 pt-4 border-t border-blue-200">
                              <p className="text-blue-700 font-bold text-sm mb-3 uppercase tracking-wide">Additional Recommendations:</p>
                              {response.recommendations.map((rec, idx) => (
                                <div key={idx} className="bg-white/80 rounded-xl p-4 border border-purple-200 mb-3">
                                  <p className="text-slate-700 text-base leading-relaxed font-medium">
                                    📋 {rec}
                                  </p>
                                </div>
                              ))}
                            </div>
                          </>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ) : response.findings.length === 0 ? (
                <div className="bg-white/80 backdrop-blur-xl border-2 border-yellow-200/50 rounded-2xl p-16 text-center shadow-xl">
                  <Info className="w-24 h-24 text-yellow-600 mx-auto mb-6" />
                  <h4 className="text-yellow-600 font-black text-3xl mb-3">Analysis Complete</h4>
                  <p className="text-slate-700 text-lg leading-relaxed font-medium mb-4">No specific security findings detected.</p>
                  <div className="mt-6 p-4 bg-yellow-50 rounded-xl border border-yellow-200">
                    <p className="text-sm text-slate-600">
                      <strong>Risk Score:</strong> {response.risk_score}/100
                    </p>
                    <p className="text-sm text-slate-600 mt-2">
                      While no critical issues were found, consider reviewing the policy structure and compliance requirements.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Show first 3 findings always, rest are collapsible */}
                  {response.findings.slice(0, showSecurityFindings ? response.findings.length : 3).map((finding, index) => {
                    const colors = getSeverityColor(finding.severity);
                    const isExpanded = expandedFindings.has(finding.id);
                    const specificImpact = getSpecificImpact(finding);
                    
                    return (
                      <div key={index} className={`${colors.bg} backdrop-blur-xl border-2 ${colors.border} rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl transition-all duration-300 group`}>
                        {/* Gradient accent bar at top */}
                        <div className={`absolute top-0 left-0 right-0 h-1.5 ${
                          finding.severity === 'Critical' ? 'bg-gradient-to-r from-red-500 via-rose-500 to-red-600' :
                          finding.severity === 'High' ? 'bg-gradient-to-r from-orange-500 via-amber-500 to-orange-600' :
                          finding.severity === 'Medium' ? 'bg-gradient-to-r from-yellow-500 via-amber-500 to-yellow-600' :
                          'bg-gradient-to-r from-slate-400 via-slate-500 to-slate-600'
                        } shadow-lg`}></div>
                        
                        <div className="p-8 relative">
                          {/* Finding Header - Premium Design */}
                          <div className="flex items-start space-x-4 mb-6">
                            <div className={`w-16 h-16 rounded-2xl flex items-center justify-center ${colors.icon} border-2 shadow-lg group-hover:scale-110 transition-transform duration-300`}>
                              {finding.severity === 'Critical' ? <XCircle className="w-8 h-8 text-red-600" /> :
                               finding.severity === 'High' ? <AlertTriangle className="w-8 h-8 text-orange-600" /> :
                               finding.severity === 'Medium' ? <AlertCircle className="w-8 h-8 text-yellow-600" /> :
                               <Info className="w-8 h-8 text-slate-600" />}
                            </div>
                            <div className="flex-1">
                              <div className="flex items-center flex-wrap gap-3 mb-3">
                                <h4 className="text-slate-900 font-black text-2xl tracking-tight">{finding.title}</h4>
                                <span className={`px-4 py-2 rounded-xl text-sm font-bold shadow-md ${colors.badge}`}>
                                  {finding.severity}
                                </span>
                                <span className="text-xs font-mono text-slate-500 bg-slate-100 px-3 py-1.5 rounded-lg border border-slate-200">{finding.id}</span>
                              </div>
                              <p className="text-slate-700 text-base mb-6 leading-relaxed font-medium">
                                {finding.description}
                              </p>
                              
                              {/* Code Snippet - Premium Design */}
                              {finding.code_snippet && (
                                <div className="bg-gradient-to-br from-slate-50 to-white rounded-xl p-6 mb-6 border-2 border-slate-200 shadow-lg hover:shadow-xl transition-all duration-300">
                                  <div className="flex items-center justify-between mb-4">
                                    <div className="flex items-center space-x-2">
                                      <div className="w-1 h-5 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
                                      <span className="text-xs text-slate-600 font-bold uppercase tracking-wide">Problematic Code</span>
                                    </div>
                                    <button 
                                      onClick={() => {
                                        navigator.clipboard.writeText(finding.code_snippet || '');
                                        // You could add a toast notification here
                                      }}
                                      className="text-slate-500 hover:text-slate-700 transition-colors p-2 hover:bg-slate-100 rounded-lg"
                                    >
                                      <Copy className="w-4 h-4" />
                                    </button>
                                  </div>
                                  <pre className="text-sm text-slate-800 font-mono leading-relaxed overflow-x-auto bg-white/50 p-4 rounded-lg border border-slate-200">
                                    {finding.code_snippet}
                                  </pre>
                                </div>
                              )}

                              {/* ALWAYS SHOW EXPANDABLE DETAILS SECTION - Show if there's any additional detail */}
                              {(finding.detailed_explanation || finding.recommendation) && (
                                <>
                                  <button
                                    onClick={() => toggleFindingExpansion(finding.id)}
                                    className="w-full mb-4 px-6 py-4 bg-gradient-to-r from-blue-500/10 to-purple-500/10 hover:from-blue-500/20 hover:to-purple-500/20 border-2 border-blue-200/50 hover:border-blue-300 rounded-xl transition-all duration-300 flex items-center justify-between group"
                                  >
                                    <div className="flex items-center space-x-3">
                                      <Eye className="w-5 h-5 text-blue-600 group-hover:scale-110 transition-transform" />
                                      <span className="text-blue-700 font-bold text-base">
                                        {isExpanded ? 'Hide' : 'Show'} Detailed Analysis & Recommendations
                                      </span>
                                      {(finding.detailed_explanation && finding.recommendation) && (
                                        <span className="px-2 py-0.5 bg-blue-500/10 text-blue-700 text-xs font-semibold rounded border border-blue-200/50">
                                          Full Details
                                        </span>
                                      )}
                                    </div>
                                    {isExpanded ? <ChevronUp className="w-5 h-5 text-blue-600" /> : <ChevronDown className="w-5 h-5 text-blue-600" />}
                                  </button>

                                  {isExpanded && (
                                    <div className="mb-6 bg-gradient-to-br from-slate-50 to-white rounded-2xl p-8 border-2 border-slate-200/50 backdrop-blur-xl animate-in slide-in-from-top duration-300 shadow-xl">
                                      <div className="space-y-6">
                                        {/* Detailed Explanation - Parse and display Security Impact and Practical Risk Assessment separately */}
                                        {finding.detailed_explanation && (() => {
                                          const explanation = finding.detailed_explanation || '';
                                          
                                          let securityImpact = '';
                                          let practicalRisk = '';
                                          
                                          // Extract Security Impact
                                          const impactMatch = explanation.match(/Security Impact:\s*(.+?)(?:\n\n|Practical Risk Assessment:|$)/s);
                                          if (impactMatch) {
                                            securityImpact = impactMatch[1].trim();
                                          }
                                          
                                          // Extract Practical Risk Assessment
                                          const riskMatch = explanation.match(/Practical Risk Assessment:\s*(.+?)$/s);
                                          if (riskMatch) {
                                            practicalRisk = riskMatch[1].trim();
                                          }
                                          
                                          // If structured format not found, show full explanation
                                          if (!securityImpact && !practicalRisk && explanation.trim()) {
                                            return (
                                              <div className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 border-l-4 border-blue-500/50 rounded-r-xl p-5 shadow-lg">
                                                <div className="flex items-center space-x-2 mb-3">
                                                  <Shield className="w-5 h-5 text-blue-600" />
                                                  <div className="font-bold text-blue-700 text-base">Detailed Explanation</div>
                                                </div>
                                                <div className="text-slate-800 text-sm leading-relaxed font-medium prose prose-sm max-w-none whitespace-pre-wrap">
                                                  {explanation}
                                                </div>
                                              </div>
                                            );
                                          }
                                          
                                          return (
                                            <>
                                              {/* Security Impact */}
                                              {securityImpact && (
                                                <div className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 border-l-4 border-blue-500/50 rounded-r-xl p-5 shadow-lg">
                                                  <div className="flex items-center space-x-2 mb-3">
                                                    <Shield className="w-5 h-5 text-blue-600" />
                                                    <div className="font-bold text-blue-700 text-base">Security Impact</div>
                                                  </div>
                                                  <p className="text-slate-800 text-sm leading-relaxed font-medium whitespace-pre-wrap">
                                                    {securityImpact}
                                                  </p>
                                                </div>
                                              )}
                                              
                                              {/* Practical Risk Assessment */}
                                              {practicalRisk && (
                                                <div className="bg-gradient-to-r from-orange-500/10 via-red-500/10 to-pink-500/10 border-l-4 border-red-500/50 rounded-r-xl p-5 shadow-lg">
                                                  <div className="flex items-center space-x-2 mb-3">
                                                    <AlertTriangle className="w-5 h-5 text-red-600" />
                                                    <div className="font-bold text-red-700 text-base">Practical Risk Assessment</div>
                                                  </div>
                                                  <p className="text-slate-800 text-sm leading-relaxed font-medium whitespace-pre-wrap">
                                                    {practicalRisk}
                                                  </p>
                                                </div>
                                              )}
                                            </>
                                          );
                                        })()}
                                        
                                        {/* Recommendation - Show in expanded section if detailed explanation exists */}
                                        {finding.detailed_explanation && finding.recommendation && (
                                          <div className="bg-gradient-to-br from-emerald-500/10 via-green-500/10 to-teal-500/10 border-l-4 border-emerald-500/50 rounded-r-xl p-5 shadow-lg">
                                            <div className="flex items-center space-x-2 mb-3">
                                              <Sparkles className="w-5 h-5 text-emerald-600" />
                                              <div className="font-bold text-emerald-700 text-base">Recommendation</div>
                                            </div>
                                            <p className="text-slate-800 text-sm leading-relaxed font-medium whitespace-pre-wrap">
                                              {finding.recommendation}
                                            </p>
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  )}
                                </>
                              )}
                              
                              {/* Recommendation - Premium Design */}
                              <div className="bg-gradient-to-br from-blue-500/10 via-purple-500/10 to-pink-500/10 border-2 border-blue-200/50 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-300">
                                <div className="flex items-start space-x-3">
                                  <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-xl flex items-center justify-center shadow-lg flex-shrink-0">
                                    <Sparkles className="w-5 h-5 text-white" />
                                  </div>
                                  <div className="flex-1">
                                    <div className="text-blue-700 font-bold text-base mb-2 flex items-center space-x-2">
                                      <span>How to Fix This</span>
                                      <span className="px-2 py-0.5 bg-blue-500/10 text-blue-700 text-xs font-semibold rounded border border-blue-200/50">
                                        Quick Fix
                                      </span>
                                    </div>
                                    <p className="text-slate-700 text-base leading-relaxed font-medium">{finding.recommendation}</p>
                                    <button
                                      onClick={() => {
                                        setIsChatbotOpen(true);
                                        setEnhancementInput(`Fix this finding: ${finding.title}. ${finding.recommendation}`);
                                      }}
                                      className="mt-4 px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white text-sm font-bold rounded-lg transition-all duration-300 shadow-md hover:shadow-lg hover:scale-105 flex items-center space-x-2"
                                    >
                                      <Bot className="w-4 h-4" />
                                      <span>Fix with AI Assistant</span>
                                    </button>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* COMPLIANCE STATUS - Premium Light Theme with Enhanced Features */}
            <div className="mb-16">
              {response.compliance_status && Object.keys(response.compliance_status).length > 0 ? (
                <div>
                {/* Premium Subsection Header */}
                <div className="flex items-center space-x-3 mb-8">
                  <div className="flex-1">
                    <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                      <CheckCircle className="w-7 h-7 text-blue-600" />
                      <span>Compliance Status</span>
                    </h3>
                    <p className="text-slate-600 text-sm mt-2 font-medium">Compliance validation against regulatory standards</p>
                  </div>
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
                    <div className="mb-8 bg-gradient-to-r from-red-50 via-orange-50 to-yellow-50 border-2 border-red-200/50 rounded-2xl p-6 shadow-xl">
                      <div className="flex items-center justify-between flex-wrap gap-4">
                        <div className="flex items-center space-x-4">
                          <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center border-2 border-red-200/50">
                            <XCircle className="w-8 h-8 text-red-600" />
                          </div>
                          <div>
                            <div className="text-red-900 font-black text-2xl mb-1">Critical Non-Compliance</div>
                            <div className="text-slate-700 text-sm font-medium">
                              {nonCompliantCount} of {frameworks.length} frameworks failed • {totalViolations} total violations
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <div className="text-right">
                            <div className="text-slate-600 text-xs font-semibold uppercase tracking-wide mb-1">Compliance Rate</div>
                            <div className="text-red-600 font-black text-3xl">
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
                      <CollapsibleTile
                        key={key}
                        title={framework.name}
                        subtitle={`${totalIssues} ${totalIssues === 1 ? 'issue' : 'issues'} found`}
                        icon={
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
                        }
                        badge={
                          <span className={`px-3 py-1.5 rounded-full text-xs font-bold ${
                            framework.status === 'Compliant'
                              ? 'bg-green-500/10 text-green-700 border border-green-200/50'
                              : 'bg-red-500/10 text-red-700 border border-red-200/50'
                          }`}>
                            {framework.status}
                          </span>
                        }
                        defaultExpanded={framework.status !== 'Compliant'}
                        variant={framework.status === 'Compliant' ? 'success' : 'error'}
                      >
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
                            <div className="text-xs text-slate-500 mt-1 font-medium">Start remediation using AI Assistant below</div>
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
                                    <div className="text-red-700 font-bold text-sm flex items-center space-x-2">
                                      <span>{violation.requirement}</span>
                                      {(() => {
                                        // Use link from backend if available, otherwise try to generate one
                                        const link = violation.link || getComplianceLink(key, violation.requirement);
                                        if (link) {
                                          return (
                                            <a
                                              href={link}
                                              target="_blank"
                                              rel="noopener noreferrer"
                                              className="text-blue-600 hover:text-blue-800 transition-colors"
                                              title={`View official ${key.toUpperCase()} documentation for ${violation.requirement}. Note: You may need to navigate to the specific subsection within the document.`}
                                            >
                                              <ExternalLink className="w-3 h-3" />
                                            </a>
                                          );
                                        }
                                        return null;
                                      })()}
                                    </div>
                                  </div>
                                  <span className="px-2 py-0.5 bg-red-500/10 text-red-700 text-xs font-semibold rounded border border-red-200/50">
                                    High Priority
                                  </span>
                                </div>
                                <p className="text-slate-700 text-sm mb-3 leading-relaxed font-medium">{violation.description}</p>
                                <button
                                  onClick={() => {
                                    setIsChatbotOpen(true);
                                    setEnhancementInput(`Implement this fix for ${framework.name} compliance: ${violation.fix}. Requirement: ${violation.requirement}`);
                                    setTimeout(() => {
                                      const chatInput = document.querySelector('textarea[placeholder*="Ask"]') as HTMLTextAreaElement;
                                      if (chatInput) {
                                        chatInput.focus();
                                      }
                                    }, 100);
                                  }}
                                  className="w-full bg-blue-500/10 border-l-4 border-blue-500/50 rounded-r-lg p-3 hover:bg-blue-500/20 transition-all duration-200 group"
                                >
                                  <div className="text-blue-700 text-xs font-bold mb-1 flex items-center space-x-1">
                                    <Sparkles className="w-3 h-3" />
                                    <span>How to Fix:</span>
                                  </div>
                                  <div className="flex items-center justify-between">
                                    <p className="text-slate-700 text-sm font-medium flex-1">{violation.fix}</p>
                                    <ArrowRight className="w-5 h-5 text-slate-400 group-hover:text-blue-600 opacity-0 group-hover:opacity-100 transition-all duration-300 transform group-hover:translate-x-1 flex-shrink-0" />
                                  </div>
                                </button>
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
                      </CollapsibleTile>
                    );
                  })}
                </div>
              </div>
              ) : (
                <div>
                  {/* Premium Subsection Header */}
                  <div className="flex items-center space-x-3 mb-8">
                    <div className="flex-1">
                      <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                        <CheckCircle className="w-7 h-7 text-blue-600" />
                        <span>Compliance Status</span>
                      </h3>
                      <p className="text-slate-600 text-sm mt-2 font-medium">Compliance validation against regulatory standards</p>
                    </div>
                  </div>
                  <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 shadow-xl">
                    <div className="text-center mb-6">
                      <CheckCircle className="w-16 h-16 text-blue-600 mx-auto mb-4" />
                      <h4 className="text-blue-700 font-black text-xl mb-2">Compliance Validation Not Performed</h4>
                      <p className="text-slate-700 text-base leading-relaxed font-medium mb-4">
                        No compliance frameworks were selected for validation.
                      </p>
                    </div>
                    <div className="mt-6 p-4 bg-blue-50 rounded-xl border border-blue-200">
                      <p className="text-sm text-slate-600 text-center mb-2">
                        <strong>Selected Frameworks:</strong> {selectedFrameworks.length > 0 ? selectedFrameworks.map(f => AVAILABLE_FRAMEWORKS.find(af => af.id === f)?.name || f).join(', ') : 'None'}
                      </p>
                      <p className="text-sm text-slate-600 text-center">
                        To check compliance status, select one or more frameworks in the validation form and re-run the analysis.
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* QUICK WINS - Premium Light Theme */}
            {response.quick_wins && response.quick_wins.length > 0 && (
              <div className="mb-16">
                {/* Premium Subsection Header */}
                <div className="flex items-center space-x-3 mb-8">
                  <div className="flex-1">
                    <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                      <Zap className="w-7 h-7 text-blue-600" />
                      <span>Quick Wins</span>
                    </h3>
                    <p className="text-slate-600 text-sm mt-2 font-medium">Immediate actions to improve security</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {response.quick_wins.map((win, index) => (
                    <button
                      key={index}
                      onClick={() => {
                        setIsChatbotOpen(true);
                        setEnhancementInput(`Implement this quick win: ${win}`);
                        setTimeout(() => {
                          const chatInput = document.querySelector('textarea[placeholder*="Ask"]') as HTMLTextAreaElement;
                          if (chatInput) {
                            chatInput.focus();
                          }
                        }, 100);
                      }}
                      className="w-full bg-white/80 backdrop-blur-xl border-2 border-emerald-200/50 rounded-2xl p-6 shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300 text-left group"
                    >
                      <div className="flex items-start space-x-4">
                        <div className="w-12 h-12 bg-gradient-to-br from-emerald-500/20 to-green-500/20 rounded-xl flex items-center justify-center border-2 border-emerald-200/50 shadow-lg flex-shrink-0">
                          <Zap className="w-6 h-6 text-emerald-600" />
                        </div>
                        <div className="flex-1 flex items-center justify-between">
                          <div>
                            <div className="flex items-center space-x-2 mb-2">
                              <span className="px-2 py-1 bg-emerald-500/10 text-emerald-700 text-xs font-bold rounded border border-emerald-200/50">
                                Quick Fix
                              </span>
                            </div>
                            <p className="text-slate-700 text-base leading-relaxed font-medium">{win}</p>
                          </div>
                          <ArrowRight className="w-5 h-5 text-slate-400 group-hover:text-emerald-600 opacity-0 group-hover:opacity-100 transition-all duration-300 transform group-hover:translate-x-1 flex-shrink-0 ml-4" />
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* RECOMMENDATIONS - Premium Light Theme */}
            {response.recommendations && response.recommendations.length > 0 && (
              <div className="mb-16">
                {/* Premium Subsection Header */}
                <div className="flex items-center space-x-3 mb-8">
                  <div className="flex-1">
                    <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                      <Sparkles className="w-7 h-7 text-blue-600" />
                      <span>Security Recommendations</span>
                    </h3>
                    <p className="text-slate-600 text-sm mt-2 font-medium">Long-term security improvements</p>
                  </div>
                </div>

                <div className="space-y-4">
                  {response.recommendations.map((recommendation, index) => (
                    <button
                      key={index}
                      onClick={() => {
                        setIsChatbotOpen(true);
                        setEnhancementInput(`Implement this recommendation: ${recommendation}`);
                        setTimeout(() => {
                          const chatInput = document.querySelector('textarea[placeholder*="Ask"]') as HTMLTextAreaElement;
                          if (chatInput) {
                            chatInput.focus();
                          }
                        }, 100);
                      }}
                      className="w-full bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-6 shadow-xl hover:shadow-2xl transition-all duration-300 text-left group"
                    >
                      <div className="flex items-start space-x-4">
                        <div className="w-10 h-10 bg-gradient-to-br from-blue-500/20 to-purple-500/20 rounded-xl flex items-center justify-center border-2 border-blue-200/50 shadow-lg flex-shrink-0">
                          <span className="text-blue-600 font-bold text-lg">{index + 1}</span>
                        </div>
                        <div className="flex-1 flex items-center justify-between">
                          <p className="text-slate-700 text-base leading-relaxed font-medium">{recommendation}</p>
                          <ArrowRight className="w-5 h-5 text-slate-400 group-hover:text-blue-600 opacity-0 group-hover:opacity-100 transition-all duration-300 transform group-hover:translate-x-1 flex-shrink-0 ml-4" />
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* REFINE YOUR POLICY - Premium Light Theme with Enhanced Features */}
            <div className="mb-16">
              {/* Premium Subsection Header */}
              <div className="flex items-center space-x-3 mb-6">
                <div className="flex-1">
                  <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                    <Sparkles className="w-7 h-7 text-blue-600" />
                    <span>Refine Your Policy with AI</span>
                  </h3>
                  <p className="text-slate-600 text-sm mt-2 font-medium">Automated remediation powered by Claude 3.7 Sonnet</p>
                </div>
              </div>

              {/* AI Assistant CTA Banner */}
              <div className="mb-8 bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-pink-500/10 border-2 border-blue-200/50 rounded-2xl p-6 shadow-xl">
                <div className="flex items-center justify-between flex-wrap gap-4">
                  <div className="flex items-center space-x-4">
                    <div className="w-14 h-14 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full flex items-center justify-center shadow-lg">
                      <Bot className="w-7 h-7 text-white" />
                    </div>
                    <div>
                      <div className="text-slate-900 font-black text-xl mb-1">Aegis AI Assistant Ready</div>
                      <div className="text-slate-700 text-sm font-medium">
                        Click the chatbot icon (bottom right) to start automated remediation
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => setIsChatbotOpen(true)}
                    className="px-6 py-3 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white font-bold rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105 flex items-center space-x-2"
                  >
                    <Bot className="w-5 h-5" />
                    <span>Open Assistant</span>
                  </button>
                </div>
              </div>

              <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 shadow-xl">
                <p className="text-slate-700 text-base mb-6 leading-relaxed font-medium">
                  Quick actions you can request from the AI Assistant:
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Dynamic: Only show if there are critical issues */}
                  {response.findings.filter(f => f.severity === 'Critical').length > 0 && (
                    <button
                      onClick={() => {
                        setIsChatbotOpen(true);
                        const criticalFindings = response.findings.filter(f => f.severity === 'Critical');
                        setEnhancementInput(`Fix all ${criticalFindings.length} critical issue${criticalFindings.length === 1 ? '' : 's'}: ${criticalFindings.map(f => f.title).join(', ')}`);
                      }}
                      className="group bg-white/80 hover:bg-white border-2 border-red-200/50 hover:border-red-300 rounded-xl p-5 hover:scale-105 transition-all duration-300 shadow-lg hover:shadow-xl text-left"
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center space-x-2">
                          <XCircle className="w-5 h-5 text-red-600" />
                          <span className="text-red-700 font-bold text-sm">Fix Critical Issues</span>
                        </div>
                        <div className="px-2 py-1 bg-red-500/10 text-red-700 text-xs font-bold rounded border border-red-200/50">
                          {response.findings.filter(f => f.severity === 'Critical').length} issues
                        </div>
                      </div>
                      <p className="text-slate-600 text-xs font-medium mb-3">
                        {response.findings.filter(f => f.severity === 'Critical').map(f => f.title).slice(0, 2).join(', ')}
                        {response.findings.filter(f => f.severity === 'Critical').length > 2 && '...'}
                      </p>
                      <div className="flex items-center space-x-2 text-xs text-slate-500">
                        <Clock className="w-3 h-3" />
                        <span className="font-medium">~2-3 min</span>
                        <span className="mx-1">•</span>
                        <Zap className="w-3 h-3" />
                        <span className="font-medium">Auto-fix available</span>
                      </div>
                    </button>
                  )}

                  {/* Dynamic: Show based on actual findings */}
                  {response.findings.length > 0 && response.findings.filter(f => f.severity === 'High').length > 0 && (
                    <button
                      onClick={() => {
                        setIsChatbotOpen(true);
                        const highFindings = response.findings.filter(f => f.severity === 'High');
                        setEnhancementInput(`Fix ${highFindings.length} high priority issue${highFindings.length === 1 ? '' : 's'}: ${highFindings.map(f => f.title).join(', ')}`);
                      }}
                      className="group bg-white/80 hover:bg-white border-2 border-orange-200/50 hover:border-orange-300 rounded-xl p-5 hover:scale-105 transition-all duration-300 shadow-lg hover:shadow-xl text-left"
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center space-x-2">
                          <AlertTriangle className="w-5 h-5 text-orange-600" />
                          <span className="text-orange-700 font-bold text-sm">Fix High Priority Issues</span>
                        </div>
                        <div className="px-2 py-1 bg-orange-500/10 text-orange-700 text-xs font-bold rounded border border-orange-200/50">
                          {response.findings.filter(f => f.severity === 'High').length} issues
                        </div>
                      </div>
                      <p className="text-slate-600 text-xs font-medium mb-3">Address high-priority security concerns</p>
                      <div className="flex items-center space-x-2 text-xs text-slate-500">
                        <Clock className="w-3 h-3" />
                        <span className="font-medium">~3-5 min</span>
                      </div>
                    </button>
                  )}

                  {/* Dynamic: Show quick wins if available */}
                  {response.quick_wins && response.quick_wins.length > 0 && (
                    <button
                      onClick={() => {
                        setIsChatbotOpen(true);
                        setEnhancementInput(`Implement these quick wins: ${response.quick_wins!.slice(0, 3).join(', ')}`);
                      }}
                      className="group bg-white/80 hover:bg-white border-2 border-emerald-200/50 hover:border-emerald-300 rounded-xl p-5 hover:scale-105 transition-all duration-300 shadow-lg hover:shadow-xl text-left"
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center space-x-2">
                          <Zap className="w-5 h-5 text-emerald-600" />
                          <span className="text-emerald-700 font-bold text-sm">Quick Wins</span>
                        </div>
                        <div className="px-2 py-1 bg-emerald-500/10 text-emerald-700 text-xs font-bold rounded border border-emerald-200/50">
                          {response.quick_wins.length} actions
                        </div>
                      </div>
                      <p className="text-slate-600 text-xs font-medium mb-3">{response.quick_wins[0]}</p>
                      <div className="flex items-center space-x-2 text-xs text-slate-500">
                        <Clock className="w-3 h-3" />
                        <span className="font-medium">~1-2 min</span>
                      </div>
                    </button>
                  )}

                  {/* Dynamic: Show recommendations if available */}
                  {response.recommendations && response.recommendations.length > 0 && (
                    <button
                      onClick={() => {
                        setIsChatbotOpen(true);
                        setEnhancementInput(`Implement these recommendations: ${response.recommendations!.slice(0, 2).join(', ')}`);
                      }}
                      className="group bg-white/80 hover:bg-white border-2 border-blue-200/50 hover:border-blue-300 rounded-xl p-5 hover:scale-105 transition-all duration-300 shadow-lg hover:shadow-xl text-left"
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center space-x-2">
                          <Sparkles className="w-5 h-5 text-blue-600" />
                          <span className="text-blue-700 font-bold text-sm">Security Recommendations</span>
                        </div>
                        <div className="px-2 py-1 bg-blue-500/10 text-blue-700 text-xs font-bold rounded border border-blue-200/50">
                          {response.recommendations.length} items
                        </div>
                      </div>
                      <p className="text-slate-600 text-xs font-medium mb-3">{response.recommendations[0]}</p>
                      <div className="flex items-center space-x-2 text-xs text-slate-500">
                        <Clock className="w-3 h-3" />
                        <span className="font-medium">~5-10 min</span>
                      </div>
                    </button>
                  )}

                  {/* Dynamic: Show compliance fix if there are compliance issues */}
                  {response.compliance_status && Object.keys(response.compliance_status).length > 0 && 
                   Object.values(response.compliance_status).some((f: any) => f.status !== 'Compliant') && (
                    <button
                      onClick={() => {
                        setIsChatbotOpen(true);
                        const failedFrameworks = Object.entries(response.compliance_status || {})
                          .filter(([_, f]: [string, any]) => f.status !== 'Compliant')
                          .map(([key, _]) => key.toUpperCase());
                        setEnhancementInput(`Fix compliance issues for: ${failedFrameworks.join(', ')}`);
                      }}
                      className="group bg-white/80 hover:bg-white border-2 border-yellow-200/50 hover:border-yellow-300 rounded-xl p-5 hover:scale-105 transition-all duration-300 shadow-lg hover:shadow-xl text-left"
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center space-x-2">
                          <CheckCircle className="w-5 h-5 text-yellow-600" />
                          <span className="text-yellow-700 font-bold text-sm">Fix Compliance Issues</span>
                        </div>
                        <div className="px-2 py-1 bg-yellow-500/10 text-yellow-700 text-xs font-bold rounded border border-yellow-200/50">
                          {Object.values(response.compliance_status || {}).filter((f: any) => f.status !== 'Compliant').length} failed
                        </div>
                      </div>
                      <p className="text-slate-600 text-xs font-medium mb-3">
                        {Object.entries(response.compliance_status || {})
                          .filter(([_, f]: [string, any]) => f.status !== 'Compliant')
                          .map(([key, _]) => key.toUpperCase())
                          .slice(0, 2)
                          .join(', ')}
                      </p>
                      <div className="flex items-center space-x-2 text-xs text-slate-500">
                        <Clock className="w-3 h-3" />
                        <span className="font-medium">~10-15 min</span>
                      </div>
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* EXPORT ANALYSIS REPORT - Premium Light Theme */}
            <div className="mb-16">
              {/* Premium Subsection Header */}
              <div className="flex items-center space-x-3 mb-6">
                <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                  <Download className="w-7 h-7 text-blue-600" />
                  <span>Export Analysis Report</span>
                </h3>
              </div>
              <div className="bg-white/80 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl p-8 shadow-xl">
                <div className="flex flex-wrap gap-4">
                  <button 
                    onClick={() => {
                      // Generate PDF report using print dialog
                      const printWindow = window.open('', '_blank');
                      if (!printWindow) {
                        alert('Please allow popups to generate PDF report');
                        return;
                      }
                      
                      const reportHTML = `
<!DOCTYPE html>
<html>
<head>
  <title>Aegis Security Analysis Report</title>
  <style>
    @media print {
      @page { margin: 1cm; }
      body { margin: 0; }
    }
    body { font-family: Arial, sans-serif; padding: 40px; line-height: 1.6; color: #1f2937; }
    h1 { color: #1e40af; border-bottom: 3px solid #3b82f6; padding-bottom: 10px; margin-bottom: 20px; }
    h2 { color: #4b5563; margin-top: 30px; margin-bottom: 15px; border-bottom: 2px solid #e5e7eb; padding-bottom: 5px; }
    .section { margin: 20px 0; padding: 15px; background: #f9fafb; border-left: 4px solid #3b82f6; }
    .finding { margin: 15px 0; padding: 15px; background: white; border: 1px solid #e5e7eb; border-radius: 8px; }
    .severity-critical { border-left: 4px solid #dc2626; }
    .severity-high { border-left: 4px solid #ea580c; }
    .severity-medium { border-left: 4px solid #ca8a04; }
    .severity-low { border-left: 4px solid #64748b; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { padding: 12px; text-align: left; border: 1px solid #e5e7eb; }
    th { background: #3b82f6; color: white; font-weight: bold; }
    .score { font-size: 48px; font-weight: bold; color: #1e40af; margin: 10px 0; }
    .grade { font-size: 24px; color: #059669; font-weight: bold; }
    ul { margin: 10px 0; padding-left: 20px; }
    li { margin: 5px 0; }
    .role-info { background: #eff6ff; padding: 15px; border-radius: 8px; margin: 15px 0; }
  </style>
</head>
<body>
  <h1>🛡️ AEGIS IAM SECURITY ANALYSIS REPORT</h1>
  <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
  ${inputType === 'arn' ? `<p><strong>Role ARN:</strong> ${inputValue}</p>` : '<p><strong>Analysis Type:</strong> Policy JSON Validation</p>'}
  
  <div class="section">
    <h2>Risk Score</h2>
    <div class="score">${response.risk_score}/100</div>
    <div class="grade">Grade: ${getSecurityGrade(100 - response.risk_score).label}</div>
  </div>

  <div class="section">
    <h2>Findings Summary</h2>
    <table>
      <tr><th>Severity</th><th>Count</th></tr>
      <tr><td>Critical</td><td>${response.findings.filter(f => f.severity === 'Critical').length}</td></tr>
      <tr><td>High</td><td>${response.findings.filter(f => f.severity === 'High').length}</td></tr>
      <tr><td>Medium</td><td>${response.findings.filter(f => f.severity === 'Medium').length}</td></tr>
      <tr><td>Low</td><td>${response.findings.filter(f => f.severity === 'Low').length}</td></tr>
      <tr><th>Total</th><th>${response.findings.length}</th></tr>
    </table>
  </div>

  ${response.findings.length > 0 ? `
  <div class="section">
    <h2>Detailed Findings</h2>
    ${response.findings.map((f, i) => `
      <div class="finding severity-${f.severity.toLowerCase()}">
        <h3>${i + 1}. [${f.severity}] ${f.title}</h3>
        <p><strong>ID:</strong> ${f.id}</p>
        <p><strong>Description:</strong> ${f.description}</p>
        <p><strong>Recommendation:</strong> ${f.recommendation}</p>
        ${f.code_snippet ? `<p><strong>Code Snippet:</strong> <code>${f.code_snippet}</code></p>` : ''}
      </div>
    `).join('')}
  </div>
  ` : '<div class="section"><p><strong>✅ No security issues detected. Excellent security posture!</strong></p></div>'}

  ${response.quick_wins && response.quick_wins.length > 0 ? `
  <div class="section">
    <h2>Quick Wins</h2>
    <ul>
      ${response.quick_wins.map(w => `<li>${w}</li>`).join('')}
    </ul>
  </div>
  ` : ''}

  ${response.recommendations && response.recommendations.length > 0 ? `
  <div class="section">
    <h2>Security Recommendations</h2>
    <ul>
      ${response.recommendations.map(r => `<li>${r}</li>`).join('')}
    </ul>
  </div>
  ` : ''}

  ${response.role_details ? `
  <div class="section">
    <h2>IAM Role Details</h2>
    <div class="role-info">
      <p><strong>Role ARN:</strong> ${response.role_details.role_arn || 'N/A'}</p>
      <p><strong>Role Name:</strong> ${response.role_details.role_name || 'N/A'}</p>
      ${response.role_details.attached_policies && response.role_details.attached_policies.length > 0 ? `
        <p><strong>Attached Managed Policies (${response.role_details.attached_policies.length}):</strong></p>
        <ul>
          ${response.role_details.attached_policies.map(p => `<li><strong>${p.name}</strong> - ${p.arn}</li>`).join('')}
        </ul>
        <p><em>These managed policies define the permissions granted to this role. Review each policy to understand the full scope of access.</em></p>
      ` : '<p><em>No attached managed policies found.</em></p>'}
      ${response.role_details.inline_policies && response.role_details.inline_policies.length > 0 ? `
        <p><strong>Inline Policies (${response.role_details.inline_policies.length}):</strong></p>
        <ul>
          ${response.role_details.inline_policies.map(p => `<li><strong>${p.name}</strong></li>`).join('')}
        </ul>
        <p><em>Inline policies are embedded directly in this role. These policies are combined with attached managed policies to form the effective permissions.</em></p>
      ` : ''}
      ${response.role_details.trust_policy ? `
        <p><strong>Trust Policy:</strong> Configured</p>
        <p><em>This role has a properly configured trust policy that defines who can assume this role.</em></p>
      ` : ''}
    </div>
  </div>
  ` : ''}

  ${response.compliance_status && Object.keys(response.compliance_status).length > 0 ? `
  <div class="section">
    <h2>Compliance Status - Detailed Analysis</h2>
    <p><strong>Frameworks Validated:</strong> ${Object.keys(response.compliance_status).map(k => k.toUpperCase()).join(', ')}</p>
    ${Object.entries(response.compliance_status).map(([key, framework]: [string, any]) => `
      <div class="finding">
        <h3>${framework.name} Compliance</h3>
        <p><strong>Status:</strong> <span style="color: ${framework.status === 'Compliant' ? '#059669' : framework.status === 'Partial' ? '#f59e0b' : '#dc2626'}; font-weight: bold;">${framework.status}</span></p>
        ${framework.status !== 'Compliant' ? `
          <p><strong>Why This Status?</strong></p>
          <p>The policy has been evaluated against ${framework.name} requirements. The status of "${framework.status}" indicates ${framework.status === 'Partial' ? 'partial compliance with some gaps that need to be addressed' : 'non-compliance with specific violations that must be remediated'}.</p>
        ` : `
          <p><strong>Compliance Assessment:</strong></p>
          <p>✅ This policy meets ${framework.name} requirements. All necessary security controls and access restrictions are properly configured.</p>
        `}
        ${framework.violations && framework.violations.length > 0 ? `
          <p><strong>Specific Violations (${framework.violations.length}):</strong></p>
          <ul>
            ${framework.violations.map((v: any) => `
              <li>
                <strong>Requirement ${v.requirement}:</strong> ${v.description}
                <br><em>Fix:</em> ${v.fix}
              </li>
            `).join('')}
          </ul>
        ` : ''}
        ${framework.gaps && framework.gaps.length > 0 ? `
          <p><strong>Compliance Gaps (${framework.gaps.length}):</strong></p>
          <ul>
            ${framework.gaps.map((g: string) => `<li>${g}</li>`).join('')}
          </ul>
        ` : ''}
        ${framework.status === 'Compliant' ? `
          <p style="color: #059669; font-weight: bold;">✅ This policy is fully compliant with ${framework.name} requirements.</p>
        ` : ''}
      </div>
    `).join('')}
  </div>
  ` : ''}
</body>
</html>`;
                      
                      printWindow.document.write(reportHTML);
                      printWindow.document.close();
                      setTimeout(() => {
                        printWindow.print();
                      }, 250);
                    }}
                    className="group px-6 py-4 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 rounded-xl text-white font-bold transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105 flex items-center space-x-3"
                  >
                    <Download className="w-5 h-5 group-hover:translate-y-0.5 transition-transform" />
                    <span>Download PDF Report</span>
                  </button>
                  <button 
                    onClick={() => {
                      const reportText = `
AEGIS IAM SECURITY ANALYSIS REPORT
Generated: ${new Date().toLocaleString()}
================================

RISK SCORE: ${response.risk_score}/100 - ${getSecurityGrade(response.risk_score).label}

FINDINGS SUMMARY:
- Critical: ${response.findings.filter(f => f.severity === 'Critical').length}
- High: ${response.findings.filter(f => f.severity === 'High').length}
- Medium: ${response.findings.filter(f => f.severity === 'Medium').length}
- Low: ${response.findings.filter(f => f.severity === 'Low').length}

DETAILED FINDINGS:
${response.findings.map((f, i) => `
${i + 1}. [${f.severity}] ${f.title}
   ID: ${f.id}
   Description: ${f.description}
   Recommendation: ${f.recommendation}
`).join('\n')}

QUICK WINS:
${response.quick_wins?.map((w, i) => `${i + 1}. ${w}`).join('\n') || 'None'}

RECOMMENDATIONS:
${response.recommendations?.map((r, i) => `${i + 1}. ${r}`).join('\n') || 'None'}
                      `.trim();
                      navigator.clipboard.writeText(reportText);
                      alert('Report copied to clipboard!');
                    }}
                    className="group px-6 py-4 bg-white/80 hover:bg-white border-2 border-slate-200 hover:border-slate-300 rounded-xl text-slate-700 hover:text-slate-900 font-bold transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105 flex items-center space-x-3"
                  >
                    <Copy className="w-5 h-5 group-hover:scale-110 transition-transform" />
                    <span>Copy Report</span>
                  </button>
                  <button
                    onClick={() => {
                      const summaryLines = [
                        'Aegis IAM - Validation Report',
                        `Generated: ${new Date().toLocaleString()}`,
                        '',
                        `Risk Score: ${response.risk_score}/100 (${getSecurityGrade(100 - response.risk_score).label})`,
                        `Findings: ${response.findings.length} (Critical ${response.findings.filter(f => f.severity === 'Critical').length}, High ${response.findings.filter(f => f.severity === 'High').length}, Medium ${response.findings.filter(f => f.severity === 'Medium').length}, Low ${response.findings.filter(f => f.severity === 'Low').length})`,
                        '',
                        'Report generated by Aegis IAM.'
                      ];
                      const mailBody = summaryLines.join('\n');
                      const mailto = `mailto:?subject=${encodeURIComponent('Aegis IAM Validation Report')}&body=${encodeURIComponent(mailBody)}`;
                      if (navigator.share) {
                        navigator.share({ title: 'Aegis IAM Validation Report', text: mailBody }).catch(() => {
                          navigator.clipboard?.writeText(mailBody);
                          alert('Sharing blocked. Summary copied to clipboard.');
                        });
                        return;
                      }
                      try {
                        const link = document.createElement('a');
                        link.href = mailto;
                        link.target = '_self';
                        document.body.appendChild(link);
                        link.click();
                        document.body.removeChild(link);
                        setTimeout(() => { window.location.href = mailto; }, 100);
                      } catch (e) {
                        console.warn('mailto navigation failed, copying to clipboard', e);
                        navigator.clipboard?.writeText(mailBody);
                        alert('Email client could not be opened. Summary copied to clipboard instead.');
                      }
                    }}
                    className="group px-6 py-4 bg-white/90 hover:bg-white border-2 border-slate-200 hover:border-slate-300 rounded-xl text-slate-700 hover:text-slate-900 font-bold transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105 flex items-center space-x-3"
                  >
                    <Download className="w-5 h-5 group-hover:translate-y-0.5 transition-transform" />
                    <span>Email Report</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* FLOATING CHATBOT WIDGET */}
        {!loading && response && (
          <div className="fixed bottom-6 right-6 z-50">
            {!isChatbotOpen && (
              <button
                onClick={() => setIsChatbotOpen(true)}
                className="group relative w-20 h-20 bg-gradient-to-br from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 rounded-full shadow-2xl shadow-purple-500/50 hover:shadow-purple-500/70 transition-all duration-300 hover:scale-110 flex items-center justify-center animate-bounce hover:animate-none"
              >
                <Bot className="w-10 h-10 text-white" />
                <div className="absolute -top-1 -right-1 w-5 h-5 bg-cyan-400 rounded-full border-4 border-slate-950 animate-pulse"></div>
              </button>
            )}

            {isChatbotOpen && (
              <div className={`${isChatbotExpanded ? 'w-[90vw] h-[90vh]' : 'w-[480px] h-[700px]'} bg-white/95 backdrop-blur-xl border-2 border-blue-200/50 rounded-2xl shadow-2xl flex flex-col overflow-hidden transition-all duration-300`}>
                {/* Chatbot Header - Premium Light Theme */}
                <div className="p-4 bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-pink-500/10 border-b-2 border-slate-200/50 flex items-center justify-between backdrop-blur-xl">
                  <div className="flex items-center space-x-4">
                    <div className="relative">
                      <div className="absolute inset-0 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full blur-lg opacity-30 animate-pulse"></div>
                      <div className="relative w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full flex items-center justify-center shadow-lg">
                        <Bot className="w-6 h-6 text-white" />
                      </div>
                    </div>
                    <div>
                      <h3 className="text-slate-900 font-bold text-sm">Aegis AI Assistant</h3>
                      <div className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                        <p className="text-xs text-slate-600 font-medium">Ready to help</p>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => setIsChatbotExpanded(!isChatbotExpanded)}
                      className="text-slate-500 hover:text-slate-900 transition-colors duration-300 p-1 hover:bg-slate-100 rounded"
                    >
                      {isChatbotExpanded ? <Minimize2 className="w-5 h-5" /> : <Maximize2 className="w-5 h-5" />}
                    </button>
                    <button
                      onClick={() => setIsChatbotOpen(false)}
                      className="text-slate-500 hover:text-slate-900 transition-colors duration-300 p-1 hover:bg-slate-100 rounded"
                    >
                      <X className="w-5 h-5" />
                    </button>
                  </div>
                </div>

                {/* Chat Messages - Premium Light Theme */}
                <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-slate-50/30">
                  {enhancementChat.map((msg, idx) => (
                    <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'} animate-in slide-in-from-bottom duration-300`}>
                      <div className={`max-w-[85%] ${
                        msg.role === 'user' 
                          ? 'bg-gradient-to-br from-blue-500/20 to-purple-500/20 border-2 border-blue-200/50' 
                          : 'bg-white/80 border-2 border-slate-200/50'
                      } rounded-2xl p-4 shadow-lg backdrop-blur-xl`}>
                        {msg.role === 'assistant' && (
                          <div className="flex items-center space-x-2 mb-3">
                            <div className="w-5 h-5 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full flex items-center justify-center">
                              <Bot className="w-3 h-3 text-white" />
                            </div>
                            <span className="text-xs font-bold text-blue-600 uppercase tracking-wide">Aegis AI</span>
                          </div>
                        )}
                        {msg.role === 'user' && (
                          <div className="flex items-center justify-end space-x-2 mb-3">
                            <span className="text-xs font-bold text-blue-600 uppercase tracking-wide">You</span>
                          </div>
                        )}
                        <p className="text-slate-800 text-sm leading-relaxed whitespace-pre-wrap" dangerouslySetInnerHTML={{
                          __html: msg.content
                            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                            .replace(/\*(.*?)\*/g, '<em>$1</em>')
                            .replace(/•/g, '•')
                            .replace(/\n/g, '<br />')
                        }}></p>
                      </div>
                    </div>
                  ))}
                  
                  {enhancementLoading && (
                    <div className="flex justify-start animate-in slide-in-from-bottom duration-300">
                      <div className="max-w-[85%] bg-white/80 border-2 border-slate-200/50 rounded-2xl p-4 shadow-lg">
                        <div className="flex items-center space-x-3">
                          <div className="w-5 h-5 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full flex items-center justify-center">
                            <Bot className="w-3 h-3 text-white" />
                          </div>
                          <div className="flex items-center space-x-2">
                            <div className="flex space-x-1">
                              <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce"></div>
                              <div className="w-2 h-2 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                              <div className="w-2 h-2 bg-pink-500 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
                            </div>
                            <span className="text-sm text-slate-600 font-medium">Thinking...</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                  
                  <div ref={chatEndRef} />
                </div>

                {/* Chat Input - Premium Light Theme */}
                <div className="p-4 border-t-2 border-slate-200/50 bg-white/80 backdrop-blur-xl">
                  {/* Quick Actions - Dynamic based on findings */}
                  {response && (() => {
                    const criticalCount = response.findings.filter(f => f.severity === 'Critical').length;
                    const highCount = response.findings.filter(f => f.severity === 'High').length;
                    const hasCriticalIssues = criticalCount > 0 || highCount > 0;
                    const hasWildcards = response.findings.some(f => 
                      f.type?.toLowerCase().includes('wildcard') || 
                      f.description?.toLowerCase().includes('wildcard') ||
                      f.code_snippet?.includes('*')
                    );
                    const hasTrustPolicyIssues = response.findings.some(f => 
                      f.type?.toLowerCase().includes('trust') || 
                      f.title?.toLowerCase().includes('trust')
                    );
                    const hasS3Issues = response.findings.some(f => 
                      f.type?.toLowerCase().includes('s3') || 
                      f.description?.toLowerCase().includes('s3')
                    );
                    const hasQuickWins = response.quick_wins && response.quick_wins.length > 0;
                    const hasRecommendations = response.recommendations && response.recommendations.length > 0;
                    const hasMFAIssues = response.findings.some(f => 
                      f.description?.toLowerCase().includes('mfa') || 
                      f.title?.toLowerCase().includes('mfa') ||
                      f.description?.toLowerCase().includes('multi-factor')
                    );
                    
                    const quickActions = [];
                    
                    if (hasCriticalIssues) {
                      quickActions.push({
                        label: `Fix ${criticalCount > 0 ? 'Critical' : 'High'} Issues`,
                        message: `Fix all ${criticalCount > 0 ? 'critical' : 'high'} issues`,
                        color: 'red'
                      });
                    }
                    if (hasWildcards) {
                      quickActions.push({
                        label: 'Remove Wildcards',
                        message: 'Replace wildcards with specific permissions',
                        color: 'yellow'
                      });
                    }
                    if (hasTrustPolicyIssues) {
                      quickActions.push({
                        label: 'Fix Trust Policy',
                        message: 'Improve assume role policy security',
                        color: 'purple'
                      });
                    }
                    if (hasS3Issues) {
                      quickActions.push({
                        label: 'Improve S3 Permissions',
                        message: 'Enhance S3 access controls and security',
                        color: 'blue'
                      });
                    }
                    if (hasMFAIssues) {
                      quickActions.push({
                        label: 'Add MFA',
                        message: 'Add MFA requirement for all actions',
                        color: 'purple'
                      });
                    }
                    if (hasQuickWins && response.quick_wins) {
                      quickActions.push({
                        label: `Implement Quick Wins (${response.quick_wins.length})`,
                        message: `Implement these quick wins: ${response.quick_wins.slice(0, 2).join(', ')}`,
                        color: 'emerald'
                      });
                    }
                    if (hasRecommendations && response.recommendations) {
                      quickActions.push({
                        label: `Apply Recommendations (${response.recommendations.length})`,
                        message: `Apply these recommendations: ${response.recommendations.slice(0, 2).join(', ')}`,
                        color: 'blue'
                      });
                    }
                    
                    if (quickActions.length === 0) return null;
                    
                    return (
                      <div className="mb-4 p-4 bg-gradient-to-r from-blue-500/10 to-purple-500/10 rounded-xl border-2 border-blue-200/50 backdrop-blur-xl">
                        <p className="text-blue-700 font-semibold text-xs mb-3 flex items-center space-x-2">
                          <Zap className="w-4 h-4" />
                          <span>Quick Actions:</span>
                        </p>
                        <div className="flex flex-wrap gap-2">
                          {quickActions.map((action, idx) => {
                            const colorClasses = {
                              red: 'border-red-200/50 hover:border-red-300 text-red-700 hover:text-red-900',
                              yellow: 'border-yellow-200/50 hover:border-yellow-300 text-yellow-700 hover:text-yellow-900',
                              purple: 'border-purple-200/50 hover:border-purple-300 text-purple-700 hover:text-purple-900',
                              blue: 'border-blue-200/50 hover:border-blue-300 text-blue-700 hover:text-blue-900',
                              emerald: 'border-emerald-200/50 hover:border-emerald-300 text-emerald-700 hover:text-emerald-900'
                            };
                            
                            return (
                              <button 
                                key={idx}
                                onClick={() => setEnhancementInput(action.message)}
                                className={`group px-3 py-2 bg-white/80 hover:bg-white border-2 ${colorClasses[action.color as keyof typeof colorClasses]} rounded-lg text-xs font-semibold transition-all hover:scale-105 shadow-sm hover:shadow-md`}
                              >
                                <span>{action.label}</span>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })()}

                  <form onSubmit={handleEnhancementSubmit} className="space-y-3">
                    <textarea
                      value={enhancementInput}
                      onChange={(e) => setEnhancementInput(e.target.value)}
                      placeholder="Ask me to fix issues, explain findings, add security controls..."
                      className="w-full h-20 px-4 py-3 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl text-slate-900 text-sm placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none resize-none transition-all duration-300"
                      disabled={enhancementLoading}
                    />
                    
                    <button
                      type="submit"
                      disabled={enhancementLoading || !enhancementInput.trim()}
                      className="w-full bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 text-white py-2.5 px-4 rounded-xl font-bold text-sm disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-xl hover:shadow-2xl flex items-center justify-center space-x-2 hover:scale-[1.02]"
                    >
                      {enhancementLoading ? (
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
    </div>
  );
};

export default ValidatePolicy;