import React, { useState, useEffect, useRef } from 'react';
import { Shield, Send, RefreshCw, User, Bot, MessageSquare, Lock, ArrowRight, CheckCircle, AlertCircle, Download, Copy, Sparkles, Info, X, Minimize2, ChevronUp, ChevronDown, Maximize2, XCircle, Lightbulb, FileCheck, Target, UserCheck, KeySquare, ShieldCheck, Cloud, Database, Server, Activity, Globe, BookOpen, ExternalLink, Upload, FileCode, ChevronDown as ChevronDownIcon, Key, Settings } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { generatePolicy, sendFollowUp, exportToIAC, deployRole, deleteRole, explainPolicy } from '../../services/api';
import { GeneratePolicyResponse, ChatMessage } from '../../types';
import { saveToStorage, loadFromStorage, clearStorage, STORAGE_KEYS } from '@/utils/persistence';
import CollapsibleTile from '@/components/Common/CollapsibleTile';
import SecurityTips from '@/components/Common/SecurityTips';
import { getComplianceLink } from '@/utils/complianceLinks';
import AWSConfigModal from '@/components/Modals/AWSConfigModal';
import { AWSCredentials, validateCredentials, maskAccessKeyId, getRegionDisplayName } from '@/utils/awsCredentials';
import { mockGeneratePolicyResponse } from '@/utils/demoData';
// Note: Compliance links should come from agent response, not hardcoded

interface GeneratePolicyProps {
  awsCredentials: AWSCredentials | null;
  onOpenCredentialsModal: () => void;
  demoMode?: boolean;
}

const GeneratePolicy: React.FC<GeneratePolicyProps> = ({ awsCredentials: propCredentials, onOpenCredentialsModal, demoMode = false }) => {
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
  const [isChatbotOpen, setIsChatbotOpen] = useState(false);
  const [isChatbotExpanded, setIsChatbotExpanded] = useState(false);
  const [isRefining, setIsRefining] = useState(false); // Track if we're refining via chatbot
  const [renderError, setRenderError] = useState<Error | null>(null);
  const [isNewSubmission, setIsNewSubmission] = useState(false); // Track if this is a fresh submission (not restored)
  const [hasClearedState, setHasClearedState] = useState(false); // Track if user explicitly cleared state
  
  // New feature states
  const [showDeployModal, setShowDeployModal] = useState(false);
  const [showExplainModal, setShowExplainModal] = useState(false);
  const [deployLoading, setDeployLoading] = useState(false);
  const [explainLoading, setExplainLoading] = useState(false);
  const [simpleExplanation, setSimpleExplanation] = useState<string | null>(null);
  const [deployRoleName, setDeployRoleName] = useState('');
  const [deployRegion, setDeployRegion] = useState('us-east-1');
  const [deployDescription, setDeployDescription] = useState('');
  const [deploySuccess, setDeploySuccess] = useState<string | null>(null);
  const [deployError, setDeployError] = useState<string | null>(null);
  const [showCliCommands, setShowCliCommands] = useState(false);
  
  // Manage modal tab state (Deploy or Delete)
  const [manageTab, setManageTab] = useState<'deploy' | 'delete'>('deploy'); // delete tab no longer shown
  const [deleteRoleName, setDeleteRoleName] = useState('');
  const [deleteLoading, setDeleteLoading] = useState(false);
  
  // Use app-level credentials (passed as props)
  const awsCredentials = propCredentials;
  
  const [deleteSuccess, setDeleteSuccess] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  
  // Format preview states for Permissions Policy
  const [selectedFormat, setSelectedFormat] = useState<'json' | 'cloudformation' | 'terraform' | 'yaml'>('json');
  const [formatContent, setFormatContent] = useState<Record<string, string>>({});
  const [loadingFormat, setLoadingFormat] = useState<string | null>(null);
  
  // Format preview states for Trust Policy
  const [selectedTrustFormat, setSelectedTrustFormat] = useState<'json' | 'cloudformation' | 'terraform' | 'yaml'>('json');
  const [trustFormatContent, setTrustFormatContent] = useState<Record<string, string>>({});
  const [loadingTrustFormat, setLoadingTrustFormat] = useState<string | null>(null);
  
  // Collapsible sections state - Smart defaults: Show critical, collapse detailed sections
  const [showPermissionsPolicy, setShowPermissionsPolicy] = useState(true); // Always show - critical
  const [showTrustPolicy, setShowTrustPolicy] = useState(true); // Always show - critical
  const [showExplanation, setShowExplanation] = useState(false); // Collapsed by default - detailed
  const [showRefinementSuggestions, setShowRefinementSuggestions] = useState(false); // Collapsed by default - detailed
  const [showPermissionsSuggestions, setShowPermissionsSuggestions] = useState(false); // Collapsed by default
  const [showTrustSuggestions, setShowTrustSuggestions] = useState(false); // Collapsed by default
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  const [showComplianceAdherence, setShowComplianceAdherence] = useState(false); // Collapsed by default
  const [showComplianceStatus, setShowComplianceStatus] = useState(false); // Collapsed by default
  const [showScoreBreakdown, setShowScoreBreakdown] = useState(false); // Collapsed by default
  
  // Loading step tracking (only 2 steps now - no auto-validation)
  const [loadingStep, setLoadingStep] = useState<'analyzing' | 'generating' | 'complete'>('analyzing');
  
  const chatEndRef = useRef<HTMLDivElement>(null);
  const descriptionRef = useRef<HTMLTextAreaElement>(null);

  // Demo mode: Pre-fill form inputs with demo data values
  const DEMO_DESCRIPTION = 'Lambda function to read from S3 bucket my-app-bucket and write logs to CloudWatch';
  const DEMO_COMPLIANCE = 'pci-dss';
  const DEMO_RESTRICTIVE = true;
  
  // Demo mode: ALWAYS pre-fill form inputs when form is shown (including after "Generate New Policy")
  useEffect(() => {
    if (demoMode && showInitialForm) {
      // Always pre-fill with demo values when form is shown
      setDescription(DEMO_DESCRIPTION);
      setRestrictive(DEMO_RESTRICTIVE);
      setCompliance(DEMO_COMPLIANCE);
    }
  }, [demoMode, showInitialForm]);
  
  // Helper function to reload demo (used by "Generate New Policy" button)
  const reloadDemo = () => {
    if (!demoMode) return;
    // Reset to form with pre-filled inputs (don't auto-submit - let user click Generate)
    setResponse(null);
    setShowInitialForm(true);
    setDescription(DEMO_DESCRIPTION);
    setRestrictive(DEMO_RESTRICTIVE);
    setCompliance(DEMO_COMPLIANCE);
    setLoading(false);
    setLoadingStep('analyzing');
    setError(null);
  };

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ctrl+Enter or Cmd+Enter to generate
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        if (showInitialForm && description.trim() && !loading) {
          e.preventDefault();
          // Trigger form submit
          const form = document.querySelector('form');
          if (form) {
            form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
          }
        }
      }
    };
    
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showInitialForm, description, loading]);

  const complianceFrameworks = [
    { value: 'general', label: 'General Security' },
    { value: 'pci-dss', label: 'PCI DSS' },
    { value: 'hipaa', label: 'HIPAA' },
    { value: 'sox', label: 'SOX' },
    { value: 'gdpr', label: 'GDPR' },
    { value: 'cis', label: 'CIS Benchmarks' }
  ];

  // ============================================
  // PERSISTENCE: Load saved state on mount (only if form is empty AND data is valid)
  // ============================================
  useEffect(() => {
    // Check if user explicitly cleared state (stored in localStorage)
    const wasCleared = localStorage.getItem('aegis_iam_generate_policy_cleared');
    
    if (wasCleared === 'true') {
      console.log('🔄 State was explicitly cleared - skipping restoration and clearing flag');
      clearStorage(STORAGE_KEYS.GENERATE_POLICY);
      localStorage.removeItem('aegis_iam_generate_policy_cleared');
      setHasClearedState(true);
      return;
    }
    
    // Only restore if user hasn't started typing (form is empty)
    // AND the saved data is actually valid (has policies or valid conversation)
    const saved = loadFromStorage<{
      description: string;
      restrictive: boolean;
      compliance: string;
      awsAccountId: string;
      awsRegion: string;
      response: GeneratePolicyResponse | null;
      conversationId: string | null;
      chatHistory: ChatMessage[];
      showInitialForm: boolean;
      isChatbotOpen: boolean;
    }>(STORAGE_KEYS.GENERATE_POLICY);
    
    if (saved && !description && !response && !conversationId) {
      // CRITICAL: NEVER restore question responses - they're context-dependent and cause confusion
      const hasQuestionResponse = saved.response?.is_question === true;
      
      if (hasQuestionResponse) {
        console.log('⚠️ Question response detected in saved data - clearing immediately (context-dependent)');
        clearStorage(STORAGE_KEYS.GENERATE_POLICY);
        localStorage.setItem('aegis_iam_generate_policy_cleared', 'true'); // Set flag to prevent restoration
        setHasClearedState(true); // Mark as cleared
        setShowInitialForm(true); // Force show initial form
        return; // Don't restore anything if it's a question
      }
      
      // Validate saved data before restoring
      const hasValidPolicy = saved.response?.policy && 
                             typeof saved.response.policy === 'object' &&
                             Object.keys(saved.response.policy).length > 0;
      
      const hasValidConversation = saved.conversationId && 
                                    saved.chatHistory && 
                                    saved.chatHistory.length > 0;
      
      const hasValidContent = saved.response?.final_answer || 
                              saved.response?.explanation;
      
      // Only restore if we have valid data (policy OR valid conversation)
      // AND it's definitely NOT a question response
      const shouldRestore = (hasValidPolicy || (hasValidConversation && hasValidContent)) && !hasQuestionResponse;
      
      if (shouldRestore) {
        console.log('🔄 Restoring saved Generate Policy state');
        setDescription(saved.description || '');
        setRestrictive(saved.restrictive ?? true);
        setCompliance(saved.compliance || 'general');
        setAwsAccountId(saved.awsAccountId || '');
        setAwsRegion(saved.awsRegion || '');
        setResponse(saved.response);
        setConversationId(saved.conversationId);
        setChatHistory(saved.chatHistory || []);
        setShowInitialForm(saved.showInitialForm ?? true);
        setIsChatbotOpen(saved.isChatbotOpen ?? false);
        setIsNewSubmission(false); // This is restored, not new
      } else {
        // Invalid saved data - clear it
        console.log('⚠️ Invalid saved data detected - clearing');
        clearStorage(STORAGE_KEYS.GENERATE_POLICY);
      }
    }
  }, []); // Only run on mount

  // ============================================
  // PERSISTENCE: Save state whenever it changes
  // ============================================
  useEffect(() => {
    // CRITICAL: NEVER save question responses - they're context-dependent and cause confusion
    const isQuestionResponse = response?.is_question === true;
    
    if (isQuestionResponse) {
      console.log('⚠️ Question response detected - NOT saving to persistence (context-dependent)');
      // Clear any existing question responses from storage
      clearStorage(STORAGE_KEYS.GENERATE_POLICY);
      return; // Don't save question responses
    }
    
    // Only save if we have meaningful data (response or conversation)
    // AND we're not in the middle of starting fresh
    // AND it's NOT a question response
    const hasValidData = (response && response.policy) || 
                        (conversationId && chatHistory.length > 0) ||
                        (response && (response.final_answer || response.explanation));
    
    if (hasValidData && !showInitialForm && !isQuestionResponse) {
      const stateToSave = {
        description,
        restrictive,
        compliance,
        awsAccountId,
        awsRegion,
        response,
        conversationId,
        chatHistory,
        showInitialForm,
        isChatbotOpen
      };
      saveToStorage(STORAGE_KEYS.GENERATE_POLICY, stateToSave, 24); // 24 hours expiry
    } else if (showInitialForm && !description && !response && !conversationId) {
      // If form is empty and we're showing initial form, clear any stale data
      clearStorage(STORAGE_KEYS.GENERATE_POLICY);
    }
  }, [description, restrictive, compliance, awsAccountId, awsRegion, response, conversationId, chatHistory, showInitialForm, isChatbotOpen]);

  // Only update chatHistory from response if it's a new conversation or explicitly provided
  // Don't overwrite existing chat history for follow-up responses
  useEffect(() => {
    // Only set from conversation_history if:
    // 1. We have no chat history yet (initial load)
    // 2. OR the conversation_history is explicitly provided and different
    if (response?.conversation_history && response.conversation_history.length > 0) {
      // Only update if we don't have chat history yet, or if it's a completely new conversation
      setChatHistory(prev => {
        // If we have no history, use the one from response
        if (prev.length === 0) {
          return response.conversation_history || [];
        }
        // Otherwise, preserve existing history (don't overwrite)
        return prev;
      });
    }
  }, [response?.conversation_id]); // Only run when conversation_id changes (new conversation)

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatHistory]);
  
  // Debug: Log chat history changes
  useEffect(() => {
    console.log('🔄 Chat history changed:', {
      messageCount: chatHistory.length,
      lastMessage: chatHistory[chatHistory.length - 1] ? {
        role: chatHistory[chatHistory.length - 1].role,
        contentLength: chatHistory[chatHistory.length - 1].content?.length || 0,
        contentPreview: chatHistory[chatHistory.length - 1].content?.substring(0, 100)
      } : null
    });
  }, [chatHistory]);

  // Add initial greeting when chatbot opens (only once, don't clear existing history)
  useEffect(() => {
    if (isChatbotOpen && response && chatHistory.length === 0 && response.policy) {
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
  }, [isChatbotOpen, response?.conversation_id]); // Only run when conversation_id changes (new conversation)

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

  // Validation helper functions
  const validateAccountId = (accountId: string): { valid: boolean; error?: string } => {
    if (!accountId.trim()) return { valid: true }; // Optional field
    
    const cleaned = accountId.trim().replace(/[\s\-\.]/g, '');
    if (!/^\d{12}$/.test(cleaned)) {
      return {
        valid: false,
        error: 'AWS Account ID must be exactly 12 numeric digits (e.g., 123456789012)'
      };
    }
    return { valid: true };
  };

  const validateRegion = (region: string): { valid: boolean; error?: string } => {
    if (!region.trim()) return { valid: true }; // Optional field
    
    const cleaned = region.trim().toLowerCase();
    
    // Known valid regions (from aws_constants.py) - All 38 AWS regions as of 2025
    // Since we're using a dropdown, this is mainly a safety check
    const knownRegions = [
      // US Regions (4)
      'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
      // AWS GovCloud (US) Regions (2)
      'us-gov-east-1', 'us-gov-west-1',
      // Europe Regions (8)
      'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1', 'eu-south-1', 'eu-south-2', 'eu-central-2',
      // Asia Pacific Regions (14)
      'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4', 'ap-southeast-5', 'ap-southeast-6', 'ap-southeast-7',
      'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-east-1', 'ap-east-2',
      // Canada (2)
      'ca-central-1', 'ca-west-1',
      // South America (1)
      'sa-east-1',
      // Africa (1)
      'af-south-1',
      // Middle East (3)
      'me-south-1', 'me-central-1', 'il-central-1',
      // Mexico (1)
      'mx-central-1',
      // China (2)
      'cn-north-1', 'cn-northwest-1'
    ];
    
    if (!knownRegions.includes(cleaned)) {
      return {
        valid: false,
        error: `Region '${cleaned}' is not a recognized AWS region. Please select a valid region from the dropdown.`
      };
    }
    
    return { valid: true };
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Demo mode: Show demo data instead of making API call
    if (demoMode) {
      setLoading(true);
      setLoadingStep('analyzing');
      
      setTimeout(() => {
        setLoadingStep('generating');
        
        setTimeout(() => {
          const demoResponse = mockGeneratePolicyResponse({
            description,
            service: 'Lambda',
            compliance: compliance || 'pci-dss', // Use selected compliance or default to PCI DSS
            restrictive
          });
          setResponse(demoResponse);
          setShowInitialForm(false);
          setLoading(false);
          setLoadingStep('complete');
          setError(null);
        }, 1500);
      }, 1000);
      
      return;
    }
    
    // CRITICAL: Check for AWS credentials first
    if (!awsCredentials) {
      setError('Please configure your AWS credentials first');
      onOpenCredentialsModal();
      return;
    }
    
    if (!description.trim()) {
      setError('Please describe what permissions you need');
      return;
    }

    // Validate AWS Account ID if provided
    if (awsAccountId.trim()) {
      const accountValidation = validateAccountId(awsAccountId);
      if (!accountValidation.valid) {
        setError(accountValidation.error || 'Invalid AWS Account ID');
        return;
      }
    }

    // Validate AWS Region if provided
    if (awsRegion.trim()) {
      const regionValidation = validateRegion(awsRegion);
      if (!regionValidation.valid) {
        setError(regionValidation.error || 'Invalid AWS Region');
        return;
      }
    }

    // CRITICAL: Check if this is a NEW request (different description) or continuation
    const saved = loadFromStorage<{
      description: string;
      conversationId: string | null;
    }>(STORAGE_KEYS.GENERATE_POLICY);
    
    // Determine if this is a new request:
    // - No saved data
    // - Different description (user changed it)
    // - No conversation ID (fresh start)
    const isNewRequest = !saved || 
                         !saved.description || 
                         (saved.description.trim() !== description.trim()) ||
                         !saved.conversationId;
    
    // If new request, clear all old state BEFORE generating
    if (isNewRequest) {
      console.log('🆕 New request detected - clearing old state');
      // Clear persistence FIRST
      clearStorage(STORAGE_KEYS.GENERATE_POLICY);
      // Clear all state variables
      setResponse(null);
      setConversationId(null);
      setChatHistory([]);
      setIsChatbotOpen(false);
      setIsRefining(false);
      setIsNewSubmission(true); // Mark as new submission
      setHasClearedState(false); // Reset cleared flag for new request
    } else {
      setIsNewSubmission(false); // This is a continuation
      setHasClearedState(false); // Reset cleared flag for continuation
    }

    setLoading(true);
    setError(null);
    setShowInitialForm(false);
    setLoadingStep('analyzing'); // Start with analyzing step
    
    try {
      // Simulate step progression (only 2 steps - validation is optional now)
      setTimeout(() => setLoadingStep('generating'), 1500);
      // Build description with optional AWS values if provided
      let enhancedDescription = description;
      if (awsAccountId.trim()) {
        enhancedDescription += `\n\nAWS Account ID: ${awsAccountId.trim().replace(/[\s\-\.]/g, '')}`;
      }
      if (awsRegion.trim()) {
        enhancedDescription += `\n\nAWS Region: ${awsRegion.trim().toLowerCase()}`;
      }
      
      const result = await generatePolicy({
        description: enhancedDescription,
        restrictive,
        compliance
      }, awsCredentials);
      
      // Validate result before setting state
      if (!result) {
        throw new Error('No response received from server');
      }
      
      setResponse(result);
      setConversationId(result?.conversation_id || null);
      // Reset new submission flag after response received
      // This allows legitimate questions to show if agent asks for clarification
      setIsNewSubmission(false);
    } catch (err) {
      console.error("Error generating policy:", err);
      setError(err instanceof Error ? err.message : 'Failed to generate policy');
      setShowInitialForm(true);
      setIsNewSubmission(false); // Reset on error too
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
      console.log('🚀 Sending follow-up message:', currentMessage);
      console.log('🚀 Conversation ID:', conversationId);
      
      const result = await sendFollowUp(currentMessage, conversationId, undefined, awsCredentials);
      
      console.log('📥 Raw result received:', result);
      
      // Check if result is null/undefined
      if (!result) {
        console.error('❌ Result is null/undefined');
        throw new Error('No response received from server');
      }
      
      // Use the result's final_answer directly - it should already contain both policies in JSON format
      // The backend agent is now instructed to ALWAYS return both policies in JSON format
      let responseContent = result?.final_answer || result?.explanation || 'Policy updated successfully.';
      
      // Debug logging
      console.log('📨 Chatbot response received:', {
        hasFinalAnswer: !!result?.final_answer,
        finalAnswerLength: result?.final_answer?.length || 0,
        finalAnswerPreview: result?.final_answer?.substring(0, 200) || 'EMPTY',
        hasExplanation: !!result?.explanation,
        responseContentLength: responseContent.length,
        responseContentPreview: responseContent.substring(0, 200)
      });
      
      // If responseContent is still empty or just whitespace, use a fallback
      if (!responseContent || responseContent.trim() === '') {
        console.error('❌ CRITICAL: Response content is empty!', {
          resultKeys: Object.keys(result || {}),
          finalAnswer: result?.final_answer,
          explanation: result?.explanation
        });
        responseContent = 'I received your message, but the response was empty. Please try again.';
      }
      
      // CRITICAL: Always preserve existing policies unless explicitly replaced
      // Update response state - preserve policies from previous state if not in result
      setResponse(prev => {
        if (!prev) {
          // If no previous response, use result as-is
          return result as any;
        }
        
        // Determine if we have new policies in the result
        const hasNewPolicy = result?.policy && typeof result.policy === 'object' && Object.keys(result.policy).length > 0;
        const hasNewTrustPolicy = result?.trust_policy && typeof result.trust_policy === 'object' && Object.keys(result.trust_policy).length > 0;
        
        // Build merged response - only include defined values from result
        const merged: any = { ...prev };
        
        // Update fields only if they're defined in result (not undefined)
        if (result?.conversation_id) merged.conversation_id = result.conversation_id;
        if (result?.final_answer) merged.final_answer = result.final_answer;
        if (result?.message_count !== undefined) merged.message_count = result.message_count;
        
        // Policies: only update if new ones provided, otherwise preserve
        merged.policy = hasNewPolicy ? result.policy : (prev.policy || result?.policy || null);
        merged.trust_policy = hasNewTrustPolicy ? result.trust_policy : (prev.trust_policy || result?.trust_policy || null);
        
        // Scores: update if provided
        if (result?.permissions_score !== undefined) merged.permissions_score = result.permissions_score;
        if (result?.trust_score !== undefined) merged.trust_score = result.trust_score;
        if (result?.overall_score !== undefined) merged.overall_score = result.overall_score;
        
        // Text fields: update if provided
        if (result?.explanation) merged.explanation = result.explanation;
        if (result?.trust_explanation) merged.trust_explanation = result.trust_explanation;
        
        // Compliance and security: update if provided
        if (result?.compliance_status) merged.compliance_status = result.compliance_status;
        if (result?.security_findings) merged.security_findings = result.security_findings;
        if (result?.security_notes) merged.security_notes = result.security_notes;
        if (result?.security_features) merged.security_features = result.security_features;
        if (result?.score_breakdown) merged.score_breakdown = result.score_breakdown;
        if (result?.refinement_suggestions) merged.refinement_suggestions = result.refinement_suggestions;
        if (result?.conversation_history) merged.conversation_history = result.conversation_history;
        if (result?.is_question !== undefined) merged.is_question = result.is_question;
        
        return merged;
      });
      
      // Add assistant response to chat
      const assistantMessage: ChatMessage = {
        role: 'assistant',
        content: responseContent.trim() || 'I received your message, but the response was empty. Please try again.',
        timestamp: new Date().toISOString()
      };
      
      console.log('💬 Adding assistant message to chat:', {
        contentLength: assistantMessage.content.length,
        contentPreview: assistantMessage.content.substring(0, 100)
      });
      
      setChatHistory(prev => {
        const updated = [...prev, assistantMessage];
        console.log('📝 Chat history updated, total messages:', updated.length);
        console.log('📝 Last message preview:', updated[updated.length - 1]?.content?.substring(0, 100));
        return updated;
      });
      
      // Force a re-render by updating a dummy state
      setTimeout(() => {
        console.log('🔄 Forcing chat history check:', chatHistory.length);
      }, 100);
    } catch (err) {
      console.error("❌ Error sending follow-up:", err);
      console.error("❌ Error details:", {
        message: err instanceof Error ? err.message : String(err),
        stack: err instanceof Error ? err.stack : undefined
      });
      
      // Add error message to chat
      const errorMessage: ChatMessage = {
        role: 'assistant',
        content: `I encountered an error: ${err instanceof Error ? err.message : 'Failed to process your request'}. Please try again.`,
        timestamp: new Date().toISOString()
      };
      setChatHistory(prev => [...prev, errorMessage]);
      setError(err instanceof Error ? err.message : 'Failed to refine policy');
    } finally {
      setLoading(false);
      setIsRefining(false); // Done refining
    }
  };

  const handleNewConversation = () => {
    // Set flag in localStorage to persist across refreshes
    localStorage.setItem('aegis_iam_generate_policy_cleared', 'true');
    
    // Clear persistence FIRST to prevent restoration on refresh
    clearStorage(STORAGE_KEYS.GENERATE_POLICY);
    console.log('🔄 Cleared persistence storage');
    
    // Set flag to prevent showing question pages
    setHasClearedState(true);
    
    // Clear all state IMMEDIATELY
    setResponse(null);
    setConversationId(null);
    setChatHistory([]);
    setFollowUpMessage('');
    setDescription('');
    setShowInitialForm(true);
    setError(null);
    setIsChatbotOpen(false);
    setIsRefining(false);
    setIsNewSubmission(false);
    setAwsAccountId('');
    setAwsRegion('');
    setCompliance('general');
    setRestrictive(true);
    
    console.log('🔄 Cleared all state for new conversation');
  };

  const hasPolicy = response?.policy !== null && 
                    response?.policy !== undefined && 
                    typeof response?.policy === 'object' &&
                    Object.keys(response?.policy || {}).length > 0 &&
                    response?.is_question !== true;
  
  // Check if there's an explanation or final_answer to display (even without a new policy)
  // BUT only if it's not empty/null/invalid
  const hasContent = hasPolicy || 
                     (response?.final_answer && response.final_answer.trim() !== '' && response.final_answer !== 'null') ||
                     (response?.explanation && response.explanation.trim() !== '' && response.explanation !== 'null');
  
  // CRITICAL: If response exists but has no valid data, clear it
  // ALSO: If response is a question, ALWAYS clear it immediately
  useEffect(() => {
    // ALWAYS clear question responses - they cause persistence issues
    if (response && response.is_question === true) {
      console.log('⚠️ Question response detected - clearing immediately (never show question pages)');
      setResponse(null);
      setConversationId(null);
      setChatHistory([]);
      setShowInitialForm(true);
      clearStorage(STORAGE_KEYS.GENERATE_POLICY);
      localStorage.setItem('aegis_iam_generate_policy_cleared', 'true');
      setHasClearedState(true);
      return;
    }
    
    // If user explicitly cleared state and we have a question response, clear it
    if (hasClearedState && response && response.is_question === true) {
      console.log('⚠️ Question response detected after state clear - clearing immediately');
      setResponse(null);
      setConversationId(null);
      setChatHistory([]);
      setShowInitialForm(true);
      clearStorage(STORAGE_KEYS.GENERATE_POLICY);
      return;
    }
    
    // Only clear if response exists but is invalid AND we're not loading
    if (response && !loading && !hasPolicy && !hasContent) {
      // Check if it's a question without conversation context (invalid state)
      if (response.is_question && !conversationId) {
        console.log('⚠️ Invalid question response without conversation - clearing');
        setResponse(null);
        setConversationId(null);
        setChatHistory([]);
        setShowInitialForm(true);
        clearStorage(STORAGE_KEYS.GENERATE_POLICY);
        setHasClearedState(true);
      } else if (!response.is_question && !hasPolicy && !hasContent) {
        // Not a question but also no content - invalid
        console.log('⚠️ Invalid response with no content - clearing');
        setResponse(null);
        setConversationId(null);
        setChatHistory([]);
        setShowInitialForm(true);
        clearStorage(STORAGE_KEYS.GENERATE_POLICY);
      }
    }
  }, [response, hasPolicy, hasContent, loading, conversationId, hasClearedState]);

  const permissionsScore = response?.permissions_score || 0;
  const trustScore = response?.trust_score || 0;

  type ServiceIconConfig = {
    pattern: RegExp;
    icon: LucideIcon;
    gradient: string;
  };

  const serviceIconConfigs: ServiceIconConfig[] = [
    { pattern: /(s3|bucket|object|storage)/i, icon: Cloud, gradient: 'from-blue-500 to-cyan-500' },
    { pattern: /(lambda|function|runtime)/i, icon: Activity, gradient: 'from-violet-500 to-purple-500' },
    { pattern: /(log|cloudwatch|monitor|metrics)/i, icon: Server, gradient: 'from-amber-500 to-orange-500' },
    { pattern: /(dynamodb|database|table|data)/i, icon: Database, gradient: 'from-emerald-500 to-green-500' },
    { pattern: /(kms|encrypt|key|secrets?)/i, icon: KeySquare, gradient: 'from-rose-500 to-pink-500' },
    { pattern: /(iam|identity|access|role)/i, icon: ShieldCheck, gradient: 'from-indigo-500 to-blue-500' },
    { pattern: /(api|http|external|internet|global)/i, icon: Globe, gradient: 'from-teal-500 to-cyan-500' },
  ];

  const getServiceIcon = (title: string) => {
    const match = serviceIconConfigs.find((config) => config.pattern.test(title));
    return match || { icon: Lock, gradient: 'from-purple-500 to-blue-500' };
  };

  const flattenToStrings = (value: unknown): string[] => {
    if (!value) return [];
    if (Array.isArray(value)) {
      return value.flatMap((item) => flattenToStrings(item));
    }
    if (typeof value === 'object') {
      return Object.values(value as Record<string, unknown>).flatMap((item) => flattenToStrings(item));
    }
    return [String(value)];
  };

  const trustStatements = response?.trust_policy?.Statement;
  const primaryTrustStatement = Array.isArray(trustStatements)
    ? trustStatements[0]
    : trustStatements;

  const trustPrincipalValues = primaryTrustStatement?.Principal;
  const trustPrincipalLabel = flattenToStrings(trustPrincipalValues).join(', ') || 'Defined principal';
  const trustPrincipalType = trustPrincipalValues && typeof trustPrincipalValues === 'object'
    ? Object.keys(trustPrincipalValues)
        .map((key) => key.replace(/([A-Z])/g, ' $1').trim())
        .join(', ')
    : trustPrincipalValues
    ? 'Principal'
    : 'Not specified';

  const trustActionsRaw = primaryTrustStatement?.Action;
  const trustActionList = flattenToStrings(trustActionsRaw);
  const trustActionLabel = trustActionList.join(', ') || 'sts:AssumeRole';
  const trustActionCount = trustActionList.length || 1;

  const trustConditionEntries = primaryTrustStatement?.Condition
    ? Object.entries(primaryTrustStatement.Condition as Record<string, Record<string, unknown>>).flatMap(
        ([conditionType, conditions]) =>
          Object.keys(conditions).map((conditionKey) => `${conditionType} ${conditionKey}`)
      )
    : [];
  const trustConditionLabel = trustConditionEntries.length > 0
    ? trustConditionEntries.join(', ')
    : 'No additional conditions';
  const trustConditionCount = trustConditionEntries.length;

  const HeadingBadge: React.FC<{ Icon: LucideIcon; gradient: string }> = ({ Icon, gradient }) => (
    <span className={`flex-shrink-0 w-9 h-9 bg-gradient-to-br ${gradient} rounded-xl flex items-center justify-center shadow-md`}>
      <Icon className="w-4 h-4 text-white" />
    </span>
  );

  const formatDetailLabel = (label: string) => {
    const withSpaces = label
      .replace(/_/g, ' ')
      .replace(/([a-z])([A-Z])/g, '$1 $2')
      .replace(/\s+/g, ' ')
      .toLowerCase();
    return withSpaces.replace(/\b\w/g, char => char.toUpperCase());
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
      {/* Demo Mode Banner */}
      {demoMode && (
        <div className="relative z-30 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 text-white py-3 px-4 shadow-lg">
          <div className="max-w-7xl mx-auto flex items-center justify-center space-x-3">
            <Sparkles className="w-5 h-5" />
            <span className="font-bold text-sm sm:text-base">
              Demo Mode: This is sample data. Add your AWS credentials to use the real service.
            </span>
            <button
              onClick={onOpenCredentialsModal}
              className="bg-white/20 hover:bg-white/30 px-4 py-1.5 rounded-lg font-semibold text-sm transition-colors"
            >
              Add Credentials
            </button>
          </div>
        </div>
      )}
      
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
              
              {/* AWS Credentials Status - Hidden in demo mode */}
              {!demoMode && (
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
              )}
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
                              AWS Account ID (Auto-detected)
                            </label>
                            <input
                              id="awsAccountId"
                              type="text"
                              value={awsAccountId}
                              onChange={(e) => setAwsAccountId(e.target.value)}
                              placeholder="Leave blank - will use your configured account"
                              maxLength={12}
                              pattern="[0-9]{12}"
                              className="w-full px-4 py-3 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl text-slate-900 text-base placeholder-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none transition-all duration-300 font-medium"
                            />
                            <div className="mt-2 bg-blue-50 border border-blue-200 rounded-lg p-3">
                              <div className="flex items-start space-x-2">
                                <Info className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
                                <p className="text-xs text-blue-700 font-medium">
                                  <strong>Auto-detected:</strong> Your actual AWS Account ID from configured credentials will be used. This ensures policies work correctly when deployed.
                                </p>
                              </div>
                            </div>
                          </div>
                          
                          <div>
                            <label htmlFor="awsRegion" className="block text-slate-700 text-sm font-semibold mb-2">
                              AWS Region
                            </label>
                            <select
                              id="awsRegion"
                              value={awsRegion}
                              onChange={(e) => setAwsRegion(e.target.value)}
                              className="w-full px-4 py-3 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl text-slate-900 text-base focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 focus:outline-none transition-all duration-300 font-medium cursor-pointer"
                            >
                              <option value="">Select a region (optional)</option>
                              <optgroup label="US Regions">
                                <option value="us-east-1">us-east-1 - US East (N. Virginia)</option>
                                <option value="us-east-2">us-east-2 - US East (Ohio)</option>
                                <option value="us-west-1">us-west-1 - US West (N. California)</option>
                                <option value="us-west-2">us-west-2 - US West (Oregon)</option>
                              </optgroup>
                              <optgroup label="AWS GovCloud (US) Regions">
                                <option value="us-gov-east-1">us-gov-east-1 - AWS GovCloud (US-East)</option>
                                <option value="us-gov-west-1">us-gov-west-1 - AWS GovCloud (US-West)</option>
                              </optgroup>
                              <optgroup label="Europe Regions">
                                <option value="eu-west-1">eu-west-1 - Europe (Ireland)</option>
                                <option value="eu-west-2">eu-west-2 - Europe (London)</option>
                                <option value="eu-west-3">eu-west-3 - Europe (Paris)</option>
                                <option value="eu-central-1">eu-central-1 - Europe (Frankfurt)</option>
                                <option value="eu-north-1">eu-north-1 - Europe (Stockholm)</option>
                                <option value="eu-south-1">eu-south-1 - Europe (Milan)</option>
                                <option value="eu-south-2">eu-south-2 - Europe (Spain)</option>
                                <option value="eu-central-2">eu-central-2 - Europe (Zurich)</option>
                              </optgroup>
                              <optgroup label="Asia Pacific Regions">
                                <option value="ap-south-1">ap-south-1 - Asia Pacific (Mumbai)</option>
                                <option value="ap-south-2">ap-south-2 - Asia Pacific (Hyderabad)</option>
                                <option value="ap-southeast-1">ap-southeast-1 - Asia Pacific (Singapore)</option>
                                <option value="ap-southeast-2">ap-southeast-2 - Asia Pacific (Sydney)</option>
                                <option value="ap-southeast-3">ap-southeast-3 - Asia Pacific (Jakarta)</option>
                                <option value="ap-southeast-4">ap-southeast-4 - Asia Pacific (Melbourne)</option>
                                <option value="ap-southeast-5">ap-southeast-5 - Asia Pacific (Malaysia)</option>
                                <option value="ap-southeast-6">ap-southeast-6 - Asia Pacific (New Zealand)</option>
                                <option value="ap-southeast-7">ap-southeast-7 - Asia Pacific (Thailand)</option>
                                <option value="ap-northeast-1">ap-northeast-1 - Asia Pacific (Tokyo)</option>
                                <option value="ap-northeast-2">ap-northeast-2 - Asia Pacific (Seoul)</option>
                                <option value="ap-northeast-3">ap-northeast-3 - Asia Pacific (Osaka)</option>
                                <option value="ap-east-1">ap-east-1 - Asia Pacific (Hong Kong)</option>
                                <option value="ap-east-2">ap-east-2 - Asia Pacific (Taipei)</option>
                              </optgroup>
                              <optgroup label="Canada Regions">
                                <option value="ca-central-1">ca-central-1 - Canada (Central)</option>
                                <option value="ca-west-1">ca-west-1 - Canada West (Calgary)</option>
                              </optgroup>
                              <optgroup label="South America Regions">
                                <option value="sa-east-1">sa-east-1 - South America (São Paulo)</option>
                              </optgroup>
                              <optgroup label="Africa Regions">
                                <option value="af-south-1">af-south-1 - Africa (Cape Town)</option>
                              </optgroup>
                              <optgroup label="Middle East Regions">
                                <option value="me-south-1">me-south-1 - Middle East (Bahrain)</option>
                                <option value="me-central-1">me-central-1 - Middle East (UAE)</option>
                                <option value="il-central-1">il-central-1 - Israel (Tel Aviv)</option>
                              </optgroup>
                              <optgroup label="Mexico Regions">
                                <option value="mx-central-1">mx-central-1 - Mexico (Central)</option>
                              </optgroup>
                              <optgroup label="China Regions (Special)">
                                <option value="cn-north-1">cn-north-1 - China (Beijing)</option>
                                <option value="cn-northwest-1">cn-northwest-1 - China (Ningxia)</option>
                              </optgroup>
                            </select>
                            <p className="text-xs text-slate-500 mt-1 font-medium">Select from all available AWS regions</p>
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
                  
                  {/* Keyboard shortcut hint */}
                  <p className="text-center text-sm text-slate-400 mt-3">
                    <kbd className="px-2 py-0.5 bg-slate-100 rounded text-xs font-mono">Ctrl</kbd>
                    <span className="mx-1">+</span>
                    <kbd className="px-2 py-0.5 bg-slate-100 rounded text-xs font-mono">Enter</kbd>
                    <span className="ml-2">to generate</span>
                  </p>
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

      {/* LOADING STATE - Premium Light with Step Indicators */}
      {!showInitialForm && loading && !response && (
        <div className="relative min-h-screen flex items-center justify-center">
          <div className="text-center px-8 max-w-3xl">
            <div className="inline-flex items-center justify-center w-32 h-32 mb-10 relative">
              <div className="absolute inset-0 border-4 border-transparent border-t-blue-500 border-r-purple-500 rounded-full animate-spin"></div>
              <div className="absolute inset-2 border-4 border-transparent border-t-purple-500 border-r-pink-500 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '2s' }}></div>
              <div className="absolute inset-0 bg-gradient-to-br from-blue-500/20 via-purple-500/20 to-pink-500/20 rounded-full animate-ping"></div>
              <Shield className="w-16 h-16 text-blue-600 relative z-10 animate-pulse" />
            </div>
            
            <h2 className="text-4xl sm:text-5xl font-extrabold bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent mb-4 animate-pulse leading-tight pb-2">
              {loadingStep === 'analyzing' && 'Analyzing Your Request'}
              {loadingStep === 'generating' && 'Generating Secure Policy'}
              {loadingStep === 'complete' && 'Almost Done!'}
            </h2>
            
            <p className="text-xl text-slate-600 mb-10 leading-relaxed font-medium max-w-2xl mx-auto">
              {loadingStep === 'analyzing' && 'Understanding your AWS service requirements...'}
              {loadingStep === 'generating' && 'Crafting least-privilege IAM policies with security scores...'}
              {loadingStep === 'complete' && 'Finalizing your secure policy...'}
            </p>
            
            {/* Step Progress Indicator */}
            <div className="flex items-center justify-center space-x-2 sm:space-x-4 mb-10">
              {/* Step 1: Analyzing */}
              <div className={`flex flex-col items-center transition-all duration-500 ${loadingStep === 'analyzing' ? 'scale-110' : 'scale-100 opacity-60'}`}>
                <div className={`w-12 h-12 sm:w-14 sm:h-14 rounded-full flex items-center justify-center transition-all duration-500 ${
                  loadingStep === 'analyzing' 
                    ? 'bg-gradient-to-br from-blue-500 to-indigo-600 shadow-lg shadow-blue-500/40' 
                    : (loadingStep === 'generating' || loadingStep === 'complete')
                      ? 'bg-gradient-to-br from-blue-600 to-indigo-700 shadow-lg shadow-blue-500/30'
                      : 'bg-slate-200'
                }`}>
                  {loadingStep === 'analyzing' ? (
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  ) : (
                    <CheckCircle className="w-6 h-6 text-white" />
                  )}
                </div>
                <span className={`text-xs sm:text-sm mt-2 font-semibold ${loadingStep === 'analyzing' ? 'text-blue-600' : 'text-blue-700'}`}>
                  Analyze
                </span>
              </div>

              {/* Connector */}
              <div className={`w-8 sm:w-16 h-1 rounded-full transition-all duration-500 ${
                loadingStep !== 'analyzing' ? 'bg-gradient-to-r from-blue-500 via-purple-500 to-purple-600' : 'bg-slate-200'
              }`}></div>

              {/* Step 2: Generating */}
              <div className={`flex flex-col items-center transition-all duration-500 ${loadingStep === 'generating' ? 'scale-110' : 'scale-100 opacity-60'}`}>
                <div className={`w-12 h-12 sm:w-14 sm:h-14 rounded-full flex items-center justify-center transition-all duration-500 ${
                  loadingStep === 'generating' 
                    ? 'bg-gradient-to-br from-pink-500 to-pink-600 shadow-lg shadow-pink-500/40' 
                    : loadingStep === 'complete'
                      ? 'bg-gradient-to-br from-pink-600 to-pink-700 shadow-lg shadow-pink-500/30'
                      : 'bg-slate-200'
                }`}>
                  {loadingStep === 'generating' ? (
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  ) : loadingStep === 'complete' ? (
                    <CheckCircle className="w-6 h-6 text-white" />
                  ) : (
                    <span className="w-6 h-6 text-slate-400 font-bold">2</span>
                  )}
                </div>
                <span className={`text-xs sm:text-sm mt-2 font-semibold ${
                  loadingStep === 'generating' ? 'text-pink-600' 
                  : loadingStep === 'complete' ? 'text-pink-700' 
                  : 'text-slate-400'
                }`}>
                  Generate
                </span>
              </div>
            </div>

            {/* Security Tips while loading */}
            <div className="mt-10">
              <SecurityTips rotationInterval={4000} />
            </div>
          </div>
        </div>
      )}

      {/* LOADING STATE AFTER MORE INFO PAGE - Premium Light Theme */}
      {/* DISABLED: Never show loading after question responses */}
      {false && !showInitialForm && loading && response?.is_question && !isRefining && (
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
      {/* DISABLED: Question responses cause persistence issues - never show this page */}
      {false && !showInitialForm && !loading && response?.is_question === true && conversationId && !isNewSubmission && !hasClearedState && chatHistory.length > 0 && (
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
      {/* Only show if we have a policy OR valid content OR compliance status, AND it's NOT a question response */}
      {!showInitialForm && response && (hasContent || (response.compliance_status && Object.keys(response.compliance_status).length > 0)) && !response.is_question && (
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
              <div className="mb-6">
                <div className="flex flex-col gap-2">
                  <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3">
                    <HeadingBadge Icon={Shield} gradient="from-blue-500 to-purple-500" />
                    <span>Security Scores</span>
                  </h3>
                  <p className="text-slate-600 text-sm font-medium">Policy security assessment</p>
                </div>
              </div>

              {/* Quick Stats Dashboard Widget */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
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

              <div className="flex justify-end mb-6">
                <button
                  onClick={() => setShowScoreBreakdown(!showScoreBreakdown)}
                  className={`group inline-flex items-center space-x-2 px-5 py-2.5 rounded-full border-2 transition-all duration-300 shadow-md hover:shadow-lg text-sm font-semibold ${
                    showScoreBreakdown
                      ? 'bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 border-transparent text-white hover:scale-[1.03]'
                      : 'bg-white/85 border-blue-200/60 text-slate-700 hover:border-blue-300 hover:text-blue-600'
                  }`}
                >
                  {showScoreBreakdown ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  <span>{showScoreBreakdown ? 'Hide Detailed Breakdown' : 'View Detailed Breakdown'}</span>
                </button>
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
                  <div className="mt-6 pt-6 border-t border-slate-200/50 animate-in slide-in-from-top duration-300">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      {(response.score_breakdown?.permissions?.positive?.length || 0) > 0 && (
                        <div className="bg-white/90 border border-slate-200 rounded-2xl p-5 shadow-sm hover:shadow-md transition">
                          <div className="flex items-center space-x-3 mb-4">
                            <div className="w-9 h-9 rounded-full bg-blue-100 flex items-center justify-center text-blue-700 text-sm font-bold">S</div>
                            <div>
                              <h4 className="text-base font-semibold text-slate-900">Strengths</h4>
                              <p className="text-xs text-slate-500">{response.score_breakdown?.permissions?.positive?.length || 0} items</p>
                            </div>
                          </div>
                          <ul className="space-y-3">
                            {(response.score_breakdown?.permissions?.positive || []).map((item, idx) => (
                              <li key={idx} className="flex items-start space-x-3 rounded-xl border border-slate-200 bg-white px-3 py-2.5">
                                <div className="mt-1 w-2 h-2 rounded-full bg-blue-500 flex-shrink-0"></div>
                                <span className="text-sm text-slate-700 leading-snug break-words whitespace-normal flex-1">{item}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                      
                      {(response.score_breakdown?.permissions?.improvements?.length || 0) > 0 && (
                        <div className="bg-white/90 border border-slate-200 rounded-2xl p-5 shadow-sm hover:shadow-md transition">
                          <div className="flex items-center space-x-3 mb-4">
                            <div className="w-9 h-9 rounded-full bg-amber-100 flex items-center justify-center text-amber-700 text-sm font-bold">O</div>
                            <div>
                              <h4 className="text-base font-semibold text-slate-900">Opportunities</h4>
                              <p className="text-xs text-slate-500">{response.score_breakdown?.permissions?.improvements?.length || 0} items</p>
                            </div>
                          </div>
                          <ul className="space-y-3">
                            {(response.score_breakdown?.permissions?.improvements || []).map((item, idx) => (
                              <li key={idx} className="flex items-start space-x-3 rounded-xl border border-slate-200 bg-white px-3 py-2.5">
                                <div className="mt-1 w-2 h-2 rounded-full bg-amber-500 flex-shrink-0"></div>
                                <span className="text-sm text-slate-700 leading-snug break-words whitespace-normal flex-1">{item}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
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
                  <div className="mt-6 pt-6 border-t border-slate-200/50 animate-in slide-in-from-top duration-300">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      {(response.score_breakdown?.trust?.positive?.length || 0) > 0 && (
                        <div className="bg-white/90 border border-slate-200 rounded-2xl p-5 shadow-sm hover:shadow-md transition">
                          <div className="flex items-center space-x-3 mb-4">
                            <div className="w-9 h-9 rounded-full bg-teal-100 flex items-center justify-center text-teal-700 text-sm font-bold">S</div>
                            <div>
                              <h4 className="text-base font-semibold text-slate-900">Strengths</h4>
                              <p className="text-xs text-slate-500">{response.score_breakdown?.trust?.positive?.length || 0} items</p>
                            </div>
                          </div>
                          <ul className="space-y-3">
                            {(response.score_breakdown?.trust?.positive || []).map((item, idx) => (
                              <li key={idx} className="flex items-start space-x-3 rounded-xl border border-slate-200 bg-white px-3 py-2.5">
                                <div className="mt-1 w-2 h-2 rounded-full bg-teal-500 flex-shrink-0"></div>
                                <span className="text-sm text-slate-700 leading-snug break-words whitespace-normal flex-1">{item}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                      
                      {(response.score_breakdown?.trust?.improvements?.length || 0) > 0 && (
                        <div className="bg-white/90 border border-slate-200 rounded-2xl p-5 shadow-sm hover:shadow-md transition">
                          <div className="flex items-center space-x-3 mb-4">
                            <div className="w-9 h-9 rounded-full bg-rose-100 flex items-center justify-center text-rose-700 text-sm font-bold">O</div>
                            <div>
                              <h4 className="text-base font-semibold text-slate-900">Opportunities</h4>
                              <p className="text-xs text-slate-500">{response.score_breakdown?.trust?.improvements?.length || 0} items</p>
                            </div>
                          </div>
                          <ul className="space-y-3">
                            {(response.score_breakdown?.trust?.improvements || []).map((item, idx) => (
                              <li key={idx} className="flex items-start space-x-3 rounded-xl border border-slate-200 bg-white px-3 py-2.5">
                                <div className="mt-1 w-2 h-2 rounded-full bg-rose-500 flex-shrink-0"></div>
                                <span className="text-sm text-slate-700 leading-snug break-words whitespace-normal flex-1">{item}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                  )}
                </div>
              </div>
            </div>

            {/* POLICIES SECTION - Premium Subsection Design */}
            <div className="space-y-16 animate-fadeIn" style={{ animationDelay: '0.2s' }}>
              {/* PERMISSIONS POLICY */}
              <CollapsibleTile
                title="Permissions Policy"
                subtitle="IAM permissions configuration"
                icon={<Shield className="w-6 h-6 text-blue-600" />}
                defaultExpanded={true}
                variant="info"
              >
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
                    <div className="flex items-center space-x-2 flex-wrap gap-2">
                      <button
                        onClick={handleCopyPolicy}
                        className="group relative px-4 py-2 bg-white/80 hover:bg-white border-2 border-slate-200 hover:border-blue-300 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 shadow-sm hover:shadow-md"
                      >
                        <Copy className="w-4 h-4 text-slate-600 group-hover:text-blue-600 transition-colors duration-300" />
                        <span className="text-sm font-medium text-slate-700 group-hover:text-blue-600 transition-colors duration-300">
                          {copied ? 'Copied!' : 'Copy'}
                        </span>
                      </button>
                      {/* IaC Export Dropdown */}
                      <div className="relative group">
                        <button
                          className="group relative px-4 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 border border-emerald-500/50 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 shadow-lg hover:shadow-xl"
                        >
                          <FileCode className="w-4 h-4 text-white transition-transform duration-300 group-hover:translate-y-0.5" />
                          <span className="text-sm font-medium text-white">Export as</span>
                          <ChevronDownIcon className="w-3 h-3 text-white" />
                        </button>
                        <div className="absolute right-0 mt-2 w-56 bg-white rounded-xl shadow-2xl border-2 border-slate-200/50 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-300 z-50">
                          <div className="py-2">
                            <button
                              onClick={async () => {
                                try {
                                  const result = await exportToIAC({
                                    policy: response.policy,
                                    format: 'cloudformation',
                                    role_name: deployRoleName || 'GeneratedRole',
                                    trust_policy: response.trust_policy
                                  });
                                  const blob = new Blob([result.content], { type: result.mime_type });
                                  const url = URL.createObjectURL(blob);
                                  const a = document.createElement('a');
                                  a.href = url;
                                  a.download = result.filename;
                                  a.click();
                                } catch (err: any) {
                                  setError(err.message);
                                }
                              }}
                              className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-blue-50 hover:text-blue-600 transition-colors flex items-center space-x-2"
                            >
                              <Cloud className="w-4 h-4" />
                              <span>CloudFormation (YAML)</span>
                            </button>
                            <button
                              onClick={async () => {
                                try {
                                  const result = await exportToIAC({
                                    policy: response.policy,
                                    format: 'terraform',
                                    role_name: deployRoleName || 'GeneratedRole',
                                    trust_policy: response.trust_policy
                                  });
                                  const blob = new Blob([result.content], { type: result.mime_type });
                                  const url = URL.createObjectURL(blob);
                                  const a = document.createElement('a');
                                  a.href = url;
                                  a.download = result.filename;
                                  a.click();
                                } catch (err: any) {
                                  setError(err.message);
                                }
                              }}
                              className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-blue-50 hover:text-blue-600 transition-colors flex items-center space-x-2"
                            >
                              <FileCode className="w-4 h-4" />
                              <span>Terraform (HCL)</span>
                            </button>
                            <button
                              onClick={async () => {
                                try {
                                  const result = await exportToIAC({
                                    policy: response.policy,
                                    format: 'yaml',
                                    role_name: deployRoleName || 'GeneratedRole',
                                    trust_policy: response.trust_policy
                                  });
                                  const blob = new Blob([result.content], { type: result.mime_type });
                                  const url = URL.createObjectURL(blob);
                                  const a = document.createElement('a');
                                  a.href = url;
                                  a.download = result.filename;
                                  a.click();
                                } catch (err: any) {
                                  setError(err.message);
                                }
                              }}
                              className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-blue-50 hover:text-blue-600 transition-colors flex items-center space-x-2"
                            >
                              <FileCode className="w-4 h-4" />
                              <span>YAML Format</span>
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
                              className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-blue-50 hover:text-blue-600 transition-colors flex items-center space-x-2"
                            >
                              <Download className="w-4 h-4" />
                              <span>JSON Format</span>
                            </button>
                          </div>
                        </div>
                      </div>
                      
                      {/* Deploy/Manage AWS Button */}
                      <button
                        onClick={() => setShowDeployModal(true)}
                        className="group relative px-4 py-2 bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 border border-orange-500/50 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 shadow-lg hover:shadow-xl"
                      >
                        <Upload className="w-4 h-4 text-white transition-transform duration-300 group-hover:translate-y-0.5" />
                        <span className="text-sm font-medium text-white">Manage AWS</span>
                      </button>
                      
                      {/* Explain in Simple Terms Button */}
                      <button
                        onClick={async () => {
                          setShowExplainModal(true);
                          setExplainLoading(true);
                          setSimpleExplanation(null);
                          try {
                            const result = await explainPolicy({
                              policy: response.policy,
                              trust_policy: response.trust_policy,
                              explanation_type: 'simple'
                            });
                            if (result.success && result.explanation) {
                              setSimpleExplanation(result.explanation);
                            } else {
                              setError(result.error || 'Failed to generate explanation');
                            }
                          } catch (err: any) {
                            setError(err.message || 'Failed to generate explanation');
                            setSimpleExplanation(null);
                          } finally {
                            setExplainLoading(false);
                          }
                        }}
                        className="group relative px-4 py-2 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 border border-indigo-500/50 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 shadow-lg hover:shadow-xl"
                      >
                        <BookOpen className="w-4 h-4 text-white transition-transform duration-300 group-hover:translate-y-0.5" />
                        <span className="text-sm font-medium text-white">Explain Simply</span>
                      </button>
                    </div>
                  </div>

                  {/* Format Tabs */}
                  <div className="border-b-2 border-slate-200/50 bg-slate-50/50 px-6 pt-4">
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => {
                          setSelectedFormat('json');
                          if (!formatContent['json']) {
                            setFormatContent(prev => ({
                              ...prev,
                              json: JSON.stringify(response.policy, null, 2)
                            }));
                          }
                        }}
                        className={`px-4 py-2 text-sm font-semibold rounded-t-lg transition-all ${
                          selectedFormat === 'json'
                            ? 'bg-white text-blue-600 border-t-2 border-l-2 border-r-2 border-blue-300'
                            : 'text-slate-600 hover:text-blue-600 hover:bg-white/50'
                        }`}
                      >
                        JSON
                      </button>
                      <button
                        onClick={async () => {
                          setSelectedFormat('cloudformation');
                          if (!formatContent['cloudformation']) {
                            setLoadingFormat('cloudformation');
                            try {
                              const result = await exportToIAC({
                                policy: response.policy,
                                format: 'cloudformation',
                                role_name: deployRoleName || 'GeneratedRole',
                                trust_policy: response.trust_policy
                              });
                              setFormatContent(prev => ({
                                ...prev,
                                cloudformation: result.content
                              }));
                            } catch (err: any) {
                              setError(err.message);
                            } finally {
                              setLoadingFormat(null);
                            }
                          }
                        }}
                        className={`px-4 py-2 text-sm font-semibold rounded-t-lg transition-all ${
                          selectedFormat === 'cloudformation'
                            ? 'bg-white text-emerald-600 border-t-2 border-l-2 border-r-2 border-emerald-300'
                            : 'text-slate-600 hover:text-emerald-600 hover:bg-white/50'
                        }`}
                      >
                        {loadingFormat === 'cloudformation' ? (
                          <RefreshCw className="w-4 h-4 animate-spin" />
                        ) : (
                          'CloudFormation'
                        )}
                      </button>
                      <button
                        onClick={async () => {
                          setSelectedFormat('terraform');
                          if (!formatContent['terraform']) {
                            setLoadingFormat('terraform');
                            try {
                              const result = await exportToIAC({
                                policy: response.policy,
                                format: 'terraform',
                                role_name: deployRoleName || 'GeneratedRole',
                                trust_policy: response.trust_policy
                              });
                              setFormatContent(prev => ({
                                ...prev,
                                terraform: result.content
                              }));
                            } catch (err: any) {
                              setError(err.message);
                            } finally {
                              setLoadingFormat(null);
                            }
                          }
                        }}
                        className={`px-4 py-2 text-sm font-semibold rounded-t-lg transition-all ${
                          selectedFormat === 'terraform'
                            ? 'bg-white text-teal-600 border-t-2 border-l-2 border-r-2 border-teal-300'
                            : 'text-slate-600 hover:text-teal-600 hover:bg-white/50'
                        }`}
                      >
                        {loadingFormat === 'terraform' ? (
                          <RefreshCw className="w-4 h-4 animate-spin" />
                        ) : (
                          'Terraform'
                        )}
                      </button>
                      <button
                        onClick={async () => {
                          setSelectedFormat('yaml');
                          if (!formatContent['yaml']) {
                            setLoadingFormat('yaml');
                            try {
                              const result = await exportToIAC({
                                policy: response.policy,
                                format: 'yaml',
                                role_name: deployRoleName || 'GeneratedRole',
                                trust_policy: response.trust_policy
                              });
                              setFormatContent(prev => ({
                                ...prev,
                                yaml: result.content
                              }));
                            } catch (err: any) {
                              setError(err.message);
                            } finally {
                              setLoadingFormat(null);
                            }
                          }
                        }}
                        className={`px-4 py-2 text-sm font-semibold rounded-t-lg transition-all ${
                          selectedFormat === 'yaml'
                            ? 'bg-white text-purple-600 border-t-2 border-l-2 border-r-2 border-purple-300'
                            : 'text-slate-600 hover:text-purple-600 hover:bg-white/50'
                        }`}
                      >
                        {loadingFormat === 'yaml' ? (
                          <RefreshCw className="w-4 h-4 animate-spin" />
                        ) : (
                          'YAML'
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="p-6 overflow-x-auto bg-slate-50/50">
                    {loadingFormat && loadingFormat === selectedFormat ? (
                      <div className="flex items-center justify-center py-12">
                        <RefreshCw className="w-6 h-6 text-blue-600 animate-spin" />
                        <span className="ml-3 text-slate-600">Generating {selectedFormat} format...</span>
                      </div>
                    ) : (
                      <pre className="text-sm font-mono text-slate-800 leading-relaxed">
                        {formatContent[selectedFormat] || (selectedFormat === 'json' ? JSON.stringify(response.policy, null, 2) : '')}
                      </pre>
                    )}
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
                  <CollapsibleTile
                    title="What These Permissions Do"
                    subtitle="Breakdown of each permission statement"
                    icon={<BookOpen className="w-6 h-6 text-indigo-600" />}
                    defaultExpanded={false}
                    variant="info"
                    className="mt-6"
                  >
                    <div className="grid grid-cols-1 gap-4">
                      {parseExplanation(response.explanation).map((section: any, index) => {
                        const { icon: ServiceIcon, gradient } = getServiceIcon(section?.title || '');
                        return (
                          <div
                            key={index}
                            className="bg-gradient-to-br from-white to-slate-50 rounded-xl p-5 border-2 border-slate-200/50 transition-all duration-300 hover:border-blue-300 hover:shadow-lg"
                          >
                            <div className="flex items-start space-x-4 mb-4">
                              <div className={`flex-shrink-0 w-12 h-12 bg-gradient-to-br ${gradient} rounded-xl flex items-center justify-center shadow-md`}>
                                <ServiceIcon className="w-6 h-6 text-white" />
                              </div>
                            <div className="flex-1">
                                <div className="text-xs text-slate-500 mb-2 font-bold uppercase tracking-wider">Statement {section.num}</div>
                                <h5 className="text-slate-900 font-bold text-base leading-snug">{stripMarkdown(section.title)}</h5>
                            </div>
                          </div>
                          
                            <div className="space-y-3">
                            {section.details.Permission && (
                                <div className="bg-slate-100/80 rounded-lg p-3 border border-slate-200 shadow-inner">
                                  <div className="text-sm text-slate-800 font-mono whitespace-pre-wrap break-words">
                                  {section.details.Permission}
                                </div>
                              </div>
                            )}
                            
                            {section.details.Purpose && (
                                <div className="bg-white/90 border border-blue-200/40 rounded-lg p-3 shadow-sm">
                                  <div className="text-xs font-semibold text-blue-600 uppercase tracking-wide mb-1">Purpose</div>
                                  <p className="text-sm text-slate-700 leading-relaxed font-medium">
                                    {stripMarkdown(section.details.Purpose)}
                                  </p>
                              </div>
                            )}
                            
                            {section.details.Security && (
                                <div className="flex items-start space-x-3 bg-emerald-50 border-2 border-emerald-200 rounded-lg p-3 shadow-sm">
                                  <div className="w-8 h-8 bg-gradient-to-br from-emerald-500 to-green-500 rounded-full flex items-center justify-center">
                                    <CheckCircle className="w-4 h-4 text-white" />
                                  </div>
                                  <div className="text-xs text-emerald-700 font-semibold leading-relaxed">
                                  {section.details.Security}
                                </div>
                              </div>
                            )}

                            {Object.entries(section.details || {})
                              .filter(([key]) => !['Permission', 'Purpose', 'Security'].includes(key))
                              .map(([key, value]) => (
                                <div key={key} className="bg-white/90 border border-slate-200 rounded-lg p-3 shadow-sm">
                                  <div className="text-xs text-slate-500 font-semibold uppercase tracking-wide mb-1">
                                    {formatDetailLabel(key)}
                                  </div>
                                  <p className="text-sm text-slate-700 leading-relaxed">
                                    {stripMarkdown(String(value))}
                                  </p>
                                </div>
                              ))}
                          </div>
                        </div>
                        );
                      })}
                    </div>
                  </CollapsibleTile>
                )}
              </CollapsibleTile>

              {/* TRUST POLICY */}
              {response.trust_policy && (
                <CollapsibleTile
                  title="Trust Policy"
                  subtitle="IAM role trust relationship"
                  icon={<ShieldCheck className="w-6 h-6 text-purple-600" />}
                  defaultExpanded={true}
                  variant="info"
                >
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
                      <div className="flex items-center space-x-2 flex-wrap gap-2">
                        <button
                          onClick={handleCopyTrustPolicy}
                          className="group relative px-4 py-2 bg-white/80 hover:bg-white border-2 border-slate-200 hover:border-purple-300 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 shadow-sm hover:shadow-md"
                        >
                          <Copy className="w-4 h-4 text-slate-600 group-hover:text-purple-600 transition-colors duration-300" />
                          <span className="text-sm font-medium text-slate-700 group-hover:text-purple-600 transition-colors duration-300">
                            {copiedTrust ? 'Copied!' : 'Copy'}
                          </span>
                        </button>
                        
                        {/* IaC Export Dropdown for Trust Policy */}
                        <div className="relative group">
                          <button
                            className="group relative px-4 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 border border-emerald-500/50 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 shadow-lg hover:shadow-xl"
                          >
                            <FileCode className="w-4 h-4 text-white transition-transform duration-300 group-hover:translate-y-0.5" />
                            <span className="text-sm font-medium text-white">Export as</span>
                            <ChevronDownIcon className="w-3 h-3 text-white" />
                          </button>
                          <div className="absolute right-0 mt-2 w-56 bg-white rounded-xl shadow-2xl border-2 border-slate-200/50 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-300 z-50">
                            <div className="py-2">
                              <button
                                onClick={async () => {
                                  try {
                                    const result = await exportToIAC({
                                      policy: response.trust_policy,
                                      format: 'cloudformation',
                                      role_name: deployRoleName || 'GeneratedRole',
                                      trust_policy: response.trust_policy
                                    });
                                    const blob = new Blob([result.content], { type: result.mime_type });
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a');
                                    a.href = url;
                                    a.download = result.filename;
                                    a.click();
                                  } catch (err: any) {
                                    setError(err.message);
                                  }
                                }}
                                className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-purple-50 hover:text-purple-600 transition-colors flex items-center space-x-2"
                              >
                                <Cloud className="w-4 h-4" />
                                <span>CloudFormation (YAML)</span>
                              </button>
                              <button
                                onClick={async () => {
                                  try {
                                    const result = await exportToIAC({
                                      policy: response.trust_policy,
                                      format: 'terraform',
                                      role_name: deployRoleName || 'GeneratedRole',
                                      trust_policy: response.trust_policy
                                    });
                                    const blob = new Blob([result.content], { type: result.mime_type });
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a');
                                    a.href = url;
                                    a.download = result.filename;
                                    a.click();
                                  } catch (err: any) {
                                    setError(err.message);
                                  }
                                }}
                                className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-purple-50 hover:text-purple-600 transition-colors flex items-center space-x-2"
                              >
                                <FileCode className="w-4 h-4" />
                                <span>Terraform (HCL)</span>
                              </button>
                              <button
                                onClick={async () => {
                                  try {
                                    const result = await exportToIAC({
                                      policy: response.trust_policy,
                                      format: 'yaml',
                                      role_name: deployRoleName || 'GeneratedRole',
                                      trust_policy: response.trust_policy
                                    });
                                    const blob = new Blob([result.content], { type: result.mime_type });
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a');
                                    a.href = url;
                                    a.download = result.filename;
                                    a.click();
                                  } catch (err: any) {
                                    setError(err.message);
                                  }
                                }}
                                className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-purple-50 hover:text-purple-600 transition-colors flex items-center space-x-2"
                              >
                                <FileCode className="w-4 h-4" />
                                <span>YAML Format</span>
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
                                className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-purple-50 hover:text-purple-600 transition-colors flex items-center space-x-2"
                              >
                                <Download className="w-4 h-4" />
                                <span>JSON Format</span>
                              </button>
                            </div>
                          </div>
                        </div>
                        
                        {/* Deploy to AWS Button for Trust Policy */}
                        <button
                          onClick={() => setShowDeployModal(true)}
                          className="group relative px-4 py-2 bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 border border-orange-500/50 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 shadow-lg hover:shadow-xl"
                        >
                          <Upload className="w-4 h-4 text-white transition-transform duration-300 group-hover:translate-y-0.5" />
                          <span className="text-sm font-medium text-white">Deploy to AWS</span>
                        </button>
                        
                        {/* Explain Trust Policy Button */}
                        <button
                          onClick={async () => {
                            setShowExplainModal(true);
                            setExplainLoading(true);
                            setSimpleExplanation(null);
                            try {
                              const result = await explainPolicy({
                                policy: response.trust_policy,
                                trust_policy: response.trust_policy,
                                explanation_type: 'simple'
                              });
                              if (result.success && result.explanation) {
                                setSimpleExplanation(result.explanation);
                              } else {
                                setError(result.error || 'Failed to generate explanation');
                              }
                            } catch (err: any) {
                              setError(err.message || 'Failed to generate explanation');
                              setSimpleExplanation(null);
                            } finally {
                              setExplainLoading(false);
                            }
                          }}
                          className="group relative px-4 py-2 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 border border-indigo-500/50 rounded-lg transition-all duration-300 flex items-center space-x-2 hover:scale-105 shadow-lg hover:shadow-xl"
                        >
                          <BookOpen className="w-4 h-4 text-white transition-transform duration-300 group-hover:translate-y-0.5" />
                          <span className="text-sm font-medium text-white">Explain Simply</span>
                        </button>
                      </div>
                    </div>

                    {/* Format Tabs for Trust Policy */}
                    <div className="border-b-2 border-slate-200/50 bg-slate-50/50 px-6 pt-4">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => {
                            setSelectedTrustFormat('json');
                            if (!trustFormatContent['json']) {
                              setTrustFormatContent(prev => ({
                                ...prev,
                                json: JSON.stringify(response.trust_policy, null, 2)
                              }));
                            }
                          }}
                          className={`px-4 py-2 text-sm font-semibold rounded-t-lg transition-all ${
                            selectedTrustFormat === 'json'
                              ? 'bg-white text-purple-600 border-t-2 border-l-2 border-r-2 border-purple-300'
                              : 'text-slate-600 hover:text-purple-600 hover:bg-white/50'
                          }`}
                        >
                          JSON
                        </button>
                        <button
                          onClick={async () => {
                            setSelectedTrustFormat('cloudformation');
                            if (!trustFormatContent['cloudformation']) {
                              setLoadingTrustFormat('cloudformation');
                              try {
                                const result = await exportToIAC({
                                  policy: response.trust_policy,
                                  format: 'cloudformation',
                                  role_name: deployRoleName || 'GeneratedRole',
                                  trust_policy: response.trust_policy
                                });
                                setTrustFormatContent(prev => ({
                                  ...prev,
                                  cloudformation: result.content
                                }));
                              } catch (err: any) {
                                setError(err.message);
                              } finally {
                                setLoadingTrustFormat(null);
                              }
                            }
                          }}
                          className={`px-4 py-2 text-sm font-semibold rounded-t-lg transition-all ${
                            selectedTrustFormat === 'cloudformation'
                              ? 'bg-white text-emerald-600 border-t-2 border-l-2 border-r-2 border-emerald-300'
                              : 'text-slate-600 hover:text-emerald-600 hover:bg-white/50'
                          }`}
                        >
                          {loadingTrustFormat === 'cloudformation' ? (
                            <RefreshCw className="w-4 h-4 animate-spin" />
                          ) : (
                            'CloudFormation'
                          )}
                        </button>
                        <button
                          onClick={async () => {
                            setSelectedTrustFormat('terraform');
                            if (!trustFormatContent['terraform']) {
                              setLoadingTrustFormat('terraform');
                              try {
                                const result = await exportToIAC({
                                  policy: response.trust_policy,
                                  format: 'terraform',
                                  role_name: deployRoleName || 'GeneratedRole',
                                  trust_policy: response.trust_policy
                                });
                                setTrustFormatContent(prev => ({
                                  ...prev,
                                  terraform: result.content
                                }));
                              } catch (err: any) {
                                setError(err.message);
                              } finally {
                                setLoadingTrustFormat(null);
                              }
                            }
                          }}
                          className={`px-4 py-2 text-sm font-semibold rounded-t-lg transition-all ${
                            selectedTrustFormat === 'terraform'
                              ? 'bg-white text-teal-600 border-t-2 border-l-2 border-r-2 border-teal-300'
                              : 'text-slate-600 hover:text-teal-600 hover:bg-white/50'
                          }`}
                        >
                          {loadingTrustFormat === 'terraform' ? (
                            <RefreshCw className="w-4 h-4 animate-spin" />
                          ) : (
                            'Terraform'
                          )}
                        </button>
                        <button
                          onClick={async () => {
                            setSelectedTrustFormat('yaml');
                            if (!trustFormatContent['yaml']) {
                              setLoadingTrustFormat('yaml');
                              try {
                                const result = await exportToIAC({
                                  policy: response.trust_policy,
                                  format: 'yaml',
                                  role_name: deployRoleName || 'GeneratedRole',
                                  trust_policy: response.trust_policy
                                });
                                setTrustFormatContent(prev => ({
                                  ...prev,
                                  yaml: result.content
                                }));
                              } catch (err: any) {
                                setError(err.message);
                              } finally {
                                setLoadingTrustFormat(null);
                              }
                            }
                          }}
                          className={`px-4 py-2 text-sm font-semibold rounded-t-lg transition-all ${
                            selectedTrustFormat === 'yaml'
                              ? 'bg-white text-purple-600 border-t-2 border-l-2 border-r-2 border-purple-300'
                              : 'text-slate-600 hover:text-purple-600 hover:bg-white/50'
                          }`}
                        >
                          {loadingTrustFormat === 'yaml' ? (
                            <RefreshCw className="w-4 h-4 animate-spin" />
                          ) : (
                            'YAML'
                          )}
                        </button>
                      </div>
                    </div>

                    <div className="p-6 overflow-x-auto bg-slate-50/50">
                      {loadingTrustFormat && loadingTrustFormat === selectedTrustFormat ? (
                        <div className="flex items-center justify-center py-12">
                          <RefreshCw className="w-6 h-6 text-purple-600 animate-spin" />
                          <span className="ml-3 text-slate-600">Generating {selectedTrustFormat} format...</span>
                        </div>
                      ) : (
                        <pre className="text-sm font-mono text-slate-800 leading-relaxed">
                          {trustFormatContent[selectedTrustFormat] || (selectedTrustFormat === 'json' ? JSON.stringify(response.trust_policy, null, 2) : '')}
                        </pre>
                      )}
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
                    <CollapsibleTile
                      title="What This Trust Policy Does"
                      subtitle="Who can assume this role and under what conditions"
                      icon={<ShieldCheck className="w-6 h-6 text-purple-600" />}
                      defaultExpanded={true}
                      variant="default"
                      className="mt-6"
                    >
                      <div className="space-y-6">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <div className="bg-gradient-to-br from-purple-500/10 via-pink-500/10 to-orange-500/10 border-2 border-purple-200/60 rounded-xl p-5 shadow-lg">
                            <div className="flex items-start space-x-3">
                              <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center shadow-md">
                                <UserCheck className="w-5 h-5 text-white" />
                              </div>
                              <div className="flex-1">
                                <div className="text-xs font-semibold uppercase tracking-wide text-slate-600 mb-1">Trusted Principal</div>
                                <p className="text-sm font-semibold text-slate-900 leading-snug break-words">
                                  {trustPrincipalLabel}
                                </p>
                            </div>
                            </div>
                            <p className="text-xs text-slate-600 mt-3">Type: {trustPrincipalType}</p>
                          </div>
                          
                          <div className="bg-gradient-to-br from-blue-500/10 via-purple-500/10 to-pink-500/10 border-2 border-blue-200/60 rounded-xl p-5 shadow-lg">
                            <div className="flex items-start space-x-3">
                              <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-lg flex items-center justify-center shadow-md">
                                <KeySquare className="w-5 h-5 text-white" />
                              </div>
                              <div className="flex-1">
                                <div className="text-xs font-semibold uppercase tracking-wide text-slate-600 mb-1">Assume Method</div>
                                <p className="text-sm font-semibold text-slate-900 leading-snug break-words">
                                  {trustActionLabel}
                                </p>
                              </div>
                            </div>
                            <p className="text-xs text-slate-600 mt-3">
                              {trustActionCount} action{trustActionCount === 1 ? '' : 's'} defined
                            </p>
                          </div>

                          <div className="bg-gradient-to-br from-emerald-500/10 via-green-500/10 to-teal-500/10 border-2 border-emerald-200/60 rounded-xl p-5 shadow-lg">
                            <div className="flex items-start space-x-3">
                              <div className="w-10 h-10 bg-gradient-to-br from-emerald-500 to-green-500 rounded-lg flex items-center justify-center shadow-md">
                                <ShieldCheck className="w-5 h-5 text-white" />
                              </div>
                              <div className="flex-1">
                                <div className="text-xs font-semibold uppercase tracking-wide text-slate-600 mb-1">Conditions</div>
                                <p className="text-sm font-semibold text-slate-900 leading-snug break-words">
                                  {trustConditionLabel}
                                </p>
                              </div>
                            </div>
                            <p className="text-xs text-slate-600 mt-3">
                              {trustConditionCount > 0 ? `${trustConditionCount} condition${trustConditionCount === 1 ? '' : 's'} enforced` : 'No additional conditions'}
                            </p>
                          </div>
                        </div>

                        <div className="bg-white/90 border-2 border-purple-200/50 rounded-xl p-6 shadow-lg">
                          <div className="space-y-5">
                            <div className="bg-gradient-to-br from-purple-500/10 via-pink-500/10 to-orange-500/10 border border-purple-200/60 rounded-xl p-4 shadow-sm">
                              <div className="text-xs text-slate-600 font-semibold uppercase tracking-wide mb-2">Trusted Entity</div>
                              <div className="text-sm text-slate-900 font-mono break-words">
                                {trustPrincipalLabel}
                              </div>
                              <div className="text-xs text-slate-500 mt-2">Principal Type: {trustPrincipalType}</div>
                            </div>

                            <div className="space-y-4">
                              {stripMarkdown(response.trust_explanation).split('\n\n').map((section, idx) => {
                                const lines = section.split('\n');
                                const rawTitle = lines[0];
                                const details = lines.slice(1);

                                if (rawTitle && rawTitle.toLowerCase().includes('trusted entity')) {
                                  return null;
                                }

                                const detailTitle = stripMarkdown(rawTitle || `Insight ${idx + 1}`);
                                const normalizedTitle = detailTitle.toLowerCase();

                                let DetailIcon: LucideIcon = BookOpen;
                                let detailGradient = 'from-blue-500 to-purple-500';

                                if (normalizedTitle.includes('security') || normalizedTitle.includes('risk')) {
                                  DetailIcon = ShieldCheck;
                                  detailGradient = 'from-emerald-500 to-green-500';
                                } else if (normalizedTitle.includes('condition') || normalizedTitle.includes('restriction')) {
                                  DetailIcon = KeySquare;
                                  detailGradient = 'from-amber-500 to-orange-500';
                                } else if (normalizedTitle.includes('access') || normalizedTitle.includes('who')) {
                                  DetailIcon = UserCheck;
                                  detailGradient = 'from-purple-500 to-pink-500';
                                }
                                
                                return (
                                  <div key={idx} className="bg-white/90 border border-slate-200 rounded-xl p-4 shadow-sm">
                                    <div className="flex items-start space-x-3">
                                      <div className={`w-10 h-10 bg-gradient-to-br ${detailGradient} rounded-lg flex items-center justify-center shadow-md`}>
                                        <DetailIcon className="w-5 h-5 text-white" />
                                      </div>
                                      <div className="flex-1">
                                        <h5 className="text-slate-900 font-semibold text-sm mb-2 leading-snug">{detailTitle}</h5>
                                    {details.map((detail, dIdx) => (
                                      detail.trim() && (
                                            <p key={dIdx} className="text-sm text-slate-700 leading-relaxed mb-1 font-normal">
                                          {stripMarkdown(detail.trim())}
                                        </p>
                                      )
                                    ))}
                                      </div>
                                    </div>
                                  </div>
                                );
                              })}
                          </div>
                          </div>
                        </div>
                      </div>
                    </CollapsibleTile>
                  )}
                </CollapsibleTile>
              )}

              {/* PERMISSIONS POLICY REFINEMENT SUGGESTIONS - Premium Subsection */}
              {(response?.refinement_suggestions?.permissions?.length || 0) > 0 && (
                <div className="animate-fadeIn" style={{ animationDelay: '0.3s' }}>
                  {/* Premium Subsection Header */}
                  <div className="flex items-center justify-between mb-6">
                          <div>
                      <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                        <HeadingBadge Icon={Sparkles} gradient="from-blue-500 to-purple-500" />
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
                            {(response.refinement_suggestions?.permissions || []).map((suggestion, idx) => (
                              <button
                                key={idx}
                                onClick={async () => {
                                  // Auto-send the refinement suggestion
                                  if (!conversationId) {
                                    setError('Please generate a policy first');
                                    return;
                                  }
                                  
                                  setIsChatbotOpen(true);
                                  setIsRefining(true);
                                  
                                  // Add user message to chat
                                  const userMessage: ChatMessage = {
                                    role: 'user',
                                    content: `Please implement this refinement: ${suggestion}`,
                                    timestamp: new Date().toISOString()
                                  };
                                  setChatHistory(prev => [...prev, userMessage]);
                                  
                                  // Auto-send the message
                                  try {
                                    setLoading(true);
                                    setError(null);
                                    
                                    const result = await sendFollowUp(
                                      `Please implement this refinement: ${suggestion}`,
                                      conversationId,
                                      undefined,
                                      awsCredentials
                                    );
                                    
                                    if (!result) {
                                      throw new Error('No response received from server');
                                    }
                                    
                                    // Update response with new policy data
                                    setResponse(prev => {
                                      if (!prev) return result as any;
                                      
                                      const merged: any = { ...prev };
                                      if (result?.conversation_id) merged.conversation_id = result.conversation_id;
                                      if (result?.final_answer) merged.final_answer = result.final_answer;
                                      if (result?.policy) merged.policy = result.policy;
                                      if (result?.trust_policy) merged.trust_policy = result.trust_policy;
                                      if (result?.permissions_score !== undefined) merged.permissions_score = result.permissions_score;
                                      if (result?.trust_score !== undefined) merged.trust_score = result.trust_score;
                                      if (result?.overall_score !== undefined) merged.overall_score = result.overall_score;
                                      if (result?.score_breakdown) merged.score_breakdown = result.score_breakdown;
                                      if (result?.security_features) merged.security_features = result.security_features;
                                      if (result?.security_notes) merged.security_notes = result.security_notes;
                                      if (result?.refinement_suggestions) merged.refinement_suggestions = result.refinement_suggestions;
                                      if (result?.explanation) merged.explanation = result.explanation;
                                      if (result?.trust_explanation) merged.trust_explanation = result.trust_explanation;
                                      if (result?.compliance_status) merged.compliance_status = result.compliance_status;
                                      
                                      return merged;
                                    });
                                    
                                    // Add assistant response to chat
                                    const assistantMessage: ChatMessage = {
                                      role: 'assistant',
                                      content: result.final_answer || result.explanation || 'Refinement applied successfully.',
                                      timestamp: new Date().toISOString()
                                    };
                                    setChatHistory(prev => [...prev, assistantMessage]);
                                    
                                  } catch (err) {
                                    console.error("Error applying refinement:", err);
                                    setError(err instanceof Error ? err.message : 'Failed to apply refinement');
                                  } finally {
                                    setLoading(false);
                                    setIsRefining(false);
                                  }
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
              {(response?.refinement_suggestions?.trust?.length || 0) > 0 && (
                <div className="animate-fadeIn" style={{ animationDelay: '0.4s' }}>
                  {/* Premium Subsection Header */}
                  <div className="flex items-center justify-between mb-6">
                          <div>
                      <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                        <HeadingBadge Icon={Sparkles} gradient="from-purple-500 to-pink-500" />
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
                            {(response.refinement_suggestions?.trust || []).map((suggestion, idx) => (
                              <button
                                key={idx}
                                onClick={async () => {
                                  // Auto-send the refinement suggestion
                                  if (!conversationId) {
                                    setError('Please generate a policy first');
                                    return;
                                  }
                                  
                                  setIsChatbotOpen(true);
                                  setIsRefining(true);
                                  
                                  // Add user message to chat
                                  const userMessage: ChatMessage = {
                                    role: 'user',
                                    content: `Please implement this refinement: ${suggestion}`,
                                    timestamp: new Date().toISOString()
                                  };
                                  setChatHistory(prev => [...prev, userMessage]);
                                  
                                  // Auto-send the message
                                  try {
                                    setLoading(true);
                                    setError(null);
                                    
                                    const result = await sendFollowUp(
                                      `Please implement this refinement: ${suggestion}`,
                                      conversationId,
                                      undefined,
                                      awsCredentials
                                    );
                                    
                                    if (!result) {
                                      throw new Error('No response received from server');
                                    }
                                    
                                    // Update response with new policy data
                                    setResponse(prev => {
                                      if (!prev) return result as any;
                                      
                                      const merged: any = { ...prev };
                                      if (result?.conversation_id) merged.conversation_id = result.conversation_id;
                                      if (result?.final_answer) merged.final_answer = result.final_answer;
                                      if (result?.policy) merged.policy = result.policy;
                                      if (result?.trust_policy) merged.trust_policy = result.trust_policy;
                                      if (result?.permissions_score !== undefined) merged.permissions_score = result.permissions_score;
                                      if (result?.trust_score !== undefined) merged.trust_score = result.trust_score;
                                      if (result?.overall_score !== undefined) merged.overall_score = result.overall_score;
                                      if (result?.score_breakdown) merged.score_breakdown = result.score_breakdown;
                                      if (result?.security_features) merged.security_features = result.security_features;
                                      if (result?.security_notes) merged.security_notes = result.security_notes;
                                      if (result?.refinement_suggestions) merged.refinement_suggestions = result.refinement_suggestions;
                                      if (result?.explanation) merged.explanation = result.explanation;
                                      if (result?.trust_explanation) merged.trust_explanation = result.trust_explanation;
                                      if (result?.compliance_status) merged.compliance_status = result.compliance_status;
                                      
                                      return merged;
                                    });
                                    
                                    // Add assistant response to chat
                                    const assistantMessage: ChatMessage = {
                                      role: 'assistant',
                                      content: result.final_answer || result.explanation || 'Refinement applied successfully.',
                                      timestamp: new Date().toISOString()
                                    };
                                    setChatHistory(prev => [...prev, assistantMessage]);
                                    
                                  } catch (err) {
                                    console.error("Error applying refinement:", err);
                                    setError(err instanceof Error ? err.message : 'Failed to apply refinement');
                                  } finally {
                                    setLoading(false);
                                    setIsRefining(false);
                                  }
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

              {/* COMPLIANCE FRAMEWORK ADHERENCE - Premium Subsection - Collapsible */}
              {compliance && compliance !== 'general' && response && response.policy && (
                <CollapsibleTile
                  title="Compliance Framework Adherence"
                  subtitle={`How this policy adheres to ${complianceFrameworks.find(f => f.value === compliance)?.label || compliance.toUpperCase()}`}
                  icon={<ShieldCheck className="w-6 h-6 text-purple-600" />}
                  defaultExpanded={false}
                  variant="info"
                  className="mb-16 animate-fadeIn"
                >
                      {/* Compliance Framework Info Card */}
                      <div className="bg-gradient-to-br from-purple-50 via-pink-50 to-blue-50 border-2 border-purple-200/50 rounded-2xl p-8 shadow-xl mb-6">
                    <div className="flex items-start space-x-4">
                      <div className="flex-shrink-0 w-16 h-16 bg-gradient-to-br from-purple-500 to-pink-500 rounded-xl flex items-center justify-center shadow-lg">
                        <ShieldCheck className="w-8 h-8 text-white" />
                      </div>
                      <div className="flex-1">
                        <h4 className="text-xl font-bold text-slate-900 mb-2">
                          {complianceFrameworks.find(f => f.value === compliance)?.label || compliance.toUpperCase()} Compliance
                        </h4>
                        <p className="text-slate-700 text-sm font-medium leading-relaxed mb-4">
                          This policy was generated with {complianceFrameworks.find(f => f.value === compliance)?.label || compliance.toUpperCase()} requirements in mind. 
                          The following features ensure adherence to this compliance framework:
                        </p>
                        
                        {/* Framework Overview - More Descriptive */}
                        <div className="bg-white/80 rounded-xl p-5 mb-6 border-2 border-purple-200/50 shadow-lg">
                          <div className="flex items-start space-x-3 mb-3">
                            <Info className="w-5 h-5 text-purple-600 mt-0.5 flex-shrink-0" />
                            <div className="flex-1">
                              <div className="text-slate-900 font-bold text-base mb-2">About {complianceFrameworks.find(f => f.value === compliance)?.label || compliance.toUpperCase()}</div>
                              {compliance === 'pci-dss' && (
                                <p className="text-slate-700 text-sm leading-relaxed font-medium">
                                  PCI DSS (Payment Card Industry Data Security Standard) is a set of security standards designed to ensure that all companies that accept, process, store, or transmit credit card information maintain a secure environment. This policy implements key requirements including least-privilege access, access logging, and resource-level restrictions to protect cardholder data.
                                </p>
                              )}
                              {compliance === 'hipaa' && (
                                <p className="text-slate-700 text-sm leading-relaxed font-medium">
                                  HIPAA (Health Insurance Portability and Accountability Act) requires healthcare organizations to implement safeguards to protect Protected Health Information (PHI). This policy ensures access controls, audit logging, and data protection measures are in place to comply with HIPAA security rules, particularly sections 164.308 (Administrative Safeguards) and 164.312 (Technical Safeguards).
                                </p>
                              )}
                              {compliance === 'sox' && (
                                <p className="text-slate-700 text-sm leading-relaxed font-medium">
                                  SOX (Sarbanes-Oxley Act) mandates that public companies implement internal controls over financial reporting. This policy supports SOX compliance by enforcing access controls, segregation of duties, comprehensive audit logging, and change management controls to ensure financial data integrity and prevent unauthorized access or modifications.
                                </p>
                              )}
                              {compliance === 'gdpr' && (
                                <p className="text-slate-700 text-sm leading-relaxed font-medium">
                                  GDPR (General Data Protection Regulation) protects EU citizens' personal data. This policy implements data minimization principles (Article 5), access controls (Article 32), and audit logging requirements to ensure personal data is accessed only when necessary and all access is properly logged and monitored.
                                </p>
                              )}
                              {compliance === 'cis' && (
                                <p className="text-slate-700 text-sm leading-relaxed font-medium">
                                  CIS AWS Benchmarks provide prescriptive security configuration guidance for AWS environments. This policy follows CIS recommendations for IAM policies, implementing least-privilege access, resource-level permissions, and security best practices to align with CIS Benchmark controls.
                                </p>
                              )}
                            </div>
                          </div>
                        </div>
                        
                        {/* Compliance Requirements List - Enhanced with More Details */}
                        <div className="space-y-3 mb-6">
                          <div className="text-slate-900 font-bold text-base mb-3">Key Compliance Features Implemented:</div>
                          {response.compliance_features && response.compliance_features.length > 0 ? (
                            <>
                              {response.compliance_features.map((feature: any, idx: number) => (
                                <CollapsibleTile
                                  key={idx}
                                  title={feature.title}
                                  subtitle={feature.subtitle}
                                  icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                  defaultExpanded={false}
                                  variant="success"
                                >
                                  <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                    {feature.description}
                                  </div>
                                  <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-1">
                                    <span>{feature.requirement}</span>
                                    {feature.link && (
                                      <a 
                                        href={feature.link} 
                                        target="_blank" 
                                        rel="noopener noreferrer" 
                                        className="text-blue-600 hover:text-blue-800 transition-colors ml-2"
                                        title="View official compliance documentation"
                                      >
                                        <ExternalLink className="w-3 h-3" />
                                      </a>
                                    )}
                                  </div>
                                </CollapsibleTile>
                              ))}
                            </>
                          ) : (
                            <>
                              {/* Fallback to hardcoded features if agent doesn't provide them */}
                              {compliance === 'pci-dss' && (
                                <>
                                  <CollapsibleTile
                                    title="Least-Privilege Access (Requirement 7.1.2)"
                                    subtitle="Policy uses specific actions instead of wildcards"
                                    icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                    defaultExpanded={false}
                                    variant="success"
                                  >
                                    <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                      Policy uses specific actions instead of wildcards, limiting access to only necessary permissions. This ensures that even if credentials are compromised, attackers can only perform the exact operations needed for the intended function, significantly reducing the attack surface.
                                    </div>
                                    <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-1">
                                      <span>PCI DSS Requirement 7.1.2: Restrict access to cardholder data by business need-to-know</span>
                                    </div>
                                  </CollapsibleTile>
                              <CollapsibleTile
                                title="Resource-Level Restrictions"
                                subtitle="Permissions scoped to specific resources"
                                icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                defaultExpanded={false}
                                variant="success"
                              >
                                <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                  Permissions are scoped to specific resources (tables, buckets, etc.) rather than using wildcards. This prevents unauthorized access to other resources in your account, ensuring cardholder data environments are properly isolated and protected.
                                </div>
                                <a 
                                  href={getComplianceLink('PCI DSS', '7.1.2') || '#'}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-2 hover:bg-indigo-50 hover:border-indigo-300 hover:text-indigo-700 transition-all cursor-pointer"
                                >
                                  <span>PCI DSS Requirement 7.1.2: Limit access to cardholder data environment</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              </CollapsibleTile>
                              <CollapsibleTile
                                title="Access Logging Ready (Requirement 10)"
                                subtitle="CloudWatch Logs permissions enable audit trails"
                                icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                defaultExpanded={false}
                                variant="success"
                              >
                                <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                  CloudWatch Logs permissions enable comprehensive access monitoring and audit trails. All access to cardholder data can be logged and reviewed, supporting PCI DSS Requirement 10 which mandates tracking and monitoring all access to network resources and cardholder data.
                                </div>
                                <a 
                                  href={getComplianceLink('PCI DSS', '10') || '#'}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-2 hover:bg-indigo-50 hover:border-indigo-300 hover:text-indigo-700 transition-all cursor-pointer"
                                >
                                  <span>PCI DSS Requirement 10: Track and monitor all access to network resources and cardholder data</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              </CollapsibleTile>
                              <CollapsibleTile
                                title="Network Segmentation Principles"
                                subtitle="Access limited to necessary services"
                                icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                defaultExpanded={false}
                                variant="success"
                              >
                                <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                  By restricting permissions to specific resources and services, this policy supports network segmentation principles. Access is limited to only the necessary services, reducing the risk of lateral movement if one component is compromised.
                                </div>
                                <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-block">
                                  PCI DSS Requirement 1: Install and maintain network security controls
                                </div>
                              </CollapsibleTile>
                            </>
                          )}
                            </>
                          )}
                          
                          {/* Fallback: Show hardcoded features if agent doesn't provide compliance_features */}
                          {(!response.compliance_features || response.compliance_features.length === 0) && compliance === 'hipaa' && (
                            <>
                              <CollapsibleTile
                                title="Access Controls (164.308(a)(4))"
                                subtitle="Least-privilege access controls to protect PHI"
                                icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                defaultExpanded={false}
                                variant="success"
                              >
                                <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                  Policy implements least-privilege access controls to protect PHI (Protected Health Information). HIPAA requires covered entities to implement procedures to authorize access to ePHI only when such access is appropriate based on the user's role. This policy ensures that only necessary permissions are granted, reducing the risk of unauthorized PHI access.
                                </div>
                                <a 
                                  href={getComplianceLink('HIPAA', '164.308(a)(4)') || '#'}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-2 hover:bg-indigo-50 hover:border-indigo-300 hover:text-indigo-700 transition-all cursor-pointer"
                                >
                                  <span>HIPAA 164.308(a)(4): Information access management</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              </CollapsibleTile>
                              <CollapsibleTile
                                title="Audit Logging (164.312(b))"
                                subtitle="CloudWatch Logs enable audit controls for ePHI"
                                icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                defaultExpanded={false}
                                variant="success"
                              >
                                <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                  CloudWatch Logs permissions enable audit controls for access to ePHI. HIPAA requires implementation of hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI. This policy ensures all access to PHI is logged and can be audited.
                                </div>
                                <a 
                                  href={getComplianceLink('HIPAA', '164.312(b)') || '#'}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-2 hover:bg-indigo-50 hover:border-indigo-300 hover:text-indigo-700 transition-all cursor-pointer"
                                >
                                  <span>HIPAA 164.312(b): Audit controls</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              </CollapsibleTile>
                              <CollapsibleTile
                                title="Data Protection & Encryption"
                                subtitle="Resource-level restrictions limit PHI exposure"
                                icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                defaultExpanded={false}
                                variant="success"
                              >
                                <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                  Resource-level restrictions limit access to specific data stores, reducing PHI exposure risk. HIPAA requires implementation of technical policies and procedures to allow access only to persons or software programs that have been granted access rights. This policy ensures PHI is only accessible to authorized services and processes.
                                </div>
                                <a 
                                  href={getComplianceLink('HIPAA', '164.312(a)(2)(iv)') || '#'}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-2 hover:bg-indigo-50 hover:border-indigo-300 hover:text-indigo-700 transition-all cursor-pointer"
                                >
                                  <span>HIPAA 164.312(a)(2)(iv): Encryption and decryption</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              </CollapsibleTile>
                              <CollapsibleTile
                                title="Minimum Necessary Standard"
                                subtitle="Access limited to minimum amount necessary"
                                icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                defaultExpanded={false}
                                variant="success"
                              >
                                <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                  By using specific actions instead of wildcards, this policy implements the HIPAA "minimum necessary" standard, ensuring that access to PHI is limited to the minimum amount necessary to accomplish the intended purpose. This reduces the risk of unauthorized disclosure of PHI.
                                </div>
                                <a 
                                  href={getComplianceLink('HIPAA', '164.502(b)') || '#'}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-2 hover:bg-indigo-50 hover:border-indigo-300 hover:text-indigo-700 transition-all cursor-pointer"
                                >
                                  <span>HIPAA 164.502(b): Minimum necessary requirements</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              </CollapsibleTile>
                            </>
                          )}
                          
                          {compliance === 'sox' && (
                            <>
                              <CollapsibleTile
                                title="Access Controls & Segregation of Duties"
                                subtitle="Specific permissions enforce access controls"
                                icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                defaultExpanded={false}
                                variant="success"
                              >
                                <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                  Policy uses specific permissions and resource restrictions to enforce access controls. This ensures that no single role has excessive privileges, supporting SOX Section 404 requirements for internal controls over financial reporting. Segregation of duties prevents conflicts of interest and reduces fraud risk.
                                </div>
                                <a 
                                  href={getComplianceLink('SOX', 'Section 404') || '#'}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-2 hover:bg-indigo-50 hover:border-indigo-300 hover:text-indigo-700 transition-all cursor-pointer"
                                >
                                  <span>SOX Section 404: Management assessment of internal controls</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              </CollapsibleTile>
                              <CollapsibleTile
                                title="Comprehensive Audit Logging"
                                subtitle="CloudWatch Logs enable detailed audit trails"
                                icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                defaultExpanded={false}
                                variant="success"
                              >
                                <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                  CloudWatch Logs permissions enable detailed audit trails for financial data access. SOX requires organizations to maintain audit trails that track who accessed financial systems, when, and what changes were made. This policy ensures all access is logged and can be reviewed during SOX audits.
                                </div>
                                <a 
                                  href={getComplianceLink('SOX', 'Section 302') || '#'}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-2 hover:bg-indigo-50 hover:border-indigo-300 hover:text-indigo-700 transition-all cursor-pointer"
                                >
                                  <span>SOX Section 302: CEO/CFO certification of financial statements</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              </CollapsibleTile>
                              <CollapsibleTile
                                title="Change Management Controls"
                                subtitle="Least-privilege prevents unauthorized changes"
                                icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                defaultExpanded={false}
                                variant="success"
                              >
                                <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                  Least-privilege design prevents unauthorized changes to financial systems. By limiting permissions to only what's necessary, this policy ensures that changes to financial data or systems require proper authorization and can be tracked, supporting SOX requirements for change management and preventing unauthorized modifications.
                                </div>
                                <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-block">
                                  SOX Section 404: Controls over financial reporting systems
                                </div>
                              </CollapsibleTile>
                              <CollapsibleTile
                                title="Data Integrity Protection"
                                subtitle="Resource-level restrictions protect financial data"
                                icon={<CheckCircle className="w-5 h-5 text-green-600" />}
                                defaultExpanded={false}
                                variant="success"
                              >
                                <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                  Resource-level restrictions and specific action permissions ensure that financial data can only be accessed and modified by authorized processes. This protects the integrity of financial records and supports SOX requirements for accurate financial reporting.
                                </div>
                                <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-block">
                                  SOX Section 302: Accuracy of financial records
                                </div>
                              </CollapsibleTile>
                            </>
                          )}
                          
                          {(!response.compliance_features || response.compliance_features.length === 0) && compliance === 'gdpr' && (
                            <>
                              <div className="flex items-start space-x-3 bg-white/60 rounded-lg p-4 border border-purple-200/50 shadow-sm hover:shadow-md transition-shadow">
                                <CheckCircle className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
                                <div className="flex-1">
                                  <div className="text-slate-900 font-bold text-sm mb-1.5">Data Minimization (Article 5)</div>
                                  <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                    Policy grants only necessary permissions, following data minimization principles. GDPR Article 5 requires that personal data be adequate, relevant, and limited to what is necessary in relation to the purposes for which they are processed. This policy ensures that access to personal data is restricted to only what's required for the specific function.
                                  </div>
                                  <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-1">
                                    <span>GDPR Article 5(1)(c): Data minimization principle</span>
                                    {/* Links should come from agent response - TODO: Use compliance_features from agent */}
                                  </div>
                                </div>
                              </div>
                              <div className="flex items-start space-x-3 bg-white/60 rounded-lg p-4 border border-purple-200/50 shadow-sm hover:shadow-md transition-shadow">
                                <CheckCircle className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
                                <div className="flex-1">
                                  <div className="text-slate-900 font-bold text-sm mb-1.5">Access Controls (Article 32)</div>
                                  <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                    Resource-level restrictions limit access to personal data, ensuring proper access controls. GDPR Article 32 requires implementation of appropriate technical and organizational measures to ensure a level of security appropriate to the risk, including the ability to ensure the ongoing confidentiality, integrity, availability, and resilience of processing systems.
                                  </div>
                                  <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-1">
                                    <span>GDPR Article 32: Security of processing</span>
                                    {/* Links should come from agent response - TODO: Use compliance_features from agent */}
                                  </div>
                                </div>
                              </div>
                              <div className="flex items-start space-x-3 bg-white/60 rounded-lg p-4 border border-purple-200/50 shadow-sm hover:shadow-md transition-shadow">
                                <CheckCircle className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
                                <div className="flex-1">
                                  <div className="text-slate-900 font-bold text-sm mb-1.5">Audit Logging & Accountability</div>
                                  <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                    CloudWatch Logs enable audit trails for data access, supporting data subject rights. GDPR requires organizations to demonstrate compliance (Article 5(2)) and be able to show how personal data is accessed and processed. This policy ensures all access to personal data is logged, supporting accountability requirements and enabling responses to data subject access requests.
                                  </div>
                                  <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-1">
                                    <span>GDPR Article 5(2): Accountability principle</span>
                                    {/* Links should come from agent response - TODO: Use compliance_features from agent */}
                                  </div>
                                </div>
                              </div>
                              <div className="flex items-start space-x-3 bg-white/60 rounded-lg p-4 border border-purple-200/50 shadow-sm hover:shadow-md transition-shadow">
                                <CheckCircle className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
                                <div className="flex-1">
                                  <div className="text-slate-900 font-bold text-sm mb-1.5">Purpose Limitation</div>
                                  <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                    By restricting permissions to specific actions and resources, this policy ensures that personal data is processed only for specified, explicit, and legitimate purposes (GDPR Article 5(1)(b)). Access is limited to what's necessary for the intended purpose, preventing unauthorized use of personal data.
                                  </div>
                                  <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-flex items-center space-x-1">
                                    <span>GDPR Article 5(1)(b): Purpose limitation principle</span>
                                    {/* Links should come from agent response - TODO: Use compliance_features from agent */}
                                  </div>
                                </div>
                              </div>
                            </>
                          )}
                          
                          {(!response.compliance_features || response.compliance_features.length === 0) && compliance === 'cis' && (
                            <>
                              <div className="flex items-start space-x-3 bg-white/60 rounded-lg p-4 border border-purple-200/50 shadow-sm hover:shadow-md transition-shadow">
                                <CheckCircle className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
                                <div className="flex-1">
                                  <div className="text-slate-900 font-bold text-sm mb-1.5">Least-Privilege Access (CIS 1.1, 1.2)</div>
                                  <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                    Policy follows CIS AWS Benchmarks by using specific actions and resource restrictions. CIS Benchmark 1.1 and 1.2 recommend maintaining current contact details and ensuring security contact information is registered. This policy implements least-privilege principles aligned with CIS recommendations for IAM access management.
                                  </div>
                                  <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-block">
                                    CIS AWS Benchmark 1.1, 1.2: IAM access management
                                  </div>
                                </div>
                              </div>
                              <div className="flex items-start space-x-3 bg-white/60 rounded-lg p-4 border border-purple-200/50 shadow-sm hover:shadow-md transition-shadow">
                                <CheckCircle className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
                                <div className="flex-1">
                                  <div className="text-slate-900 font-bold text-sm mb-1.5">Resource-Level Permissions (CIS 1.20)</div>
                                  <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                    Policy adheres to CIS recommendations for IAM policy structure and permissions. CIS Benchmark 1.20 recommends ensuring that IAM policies are attached only to groups or roles. This policy uses resource-level restrictions and specific actions, following CIS best practices for IAM policy design.
                                  </div>
                                  <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-block">
                                    CIS AWS Benchmark 1.20: IAM policy structure
                                  </div>
                                </div>
                              </div>
                              <div className="flex items-start space-x-3 bg-white/60 rounded-lg p-4 border border-purple-200/50 shadow-sm hover:shadow-md transition-shadow">
                                <CheckCircle className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
                                <div className="flex-1">
                                  <div className="text-slate-900 font-bold text-sm mb-1.5">Monitoring & Logging (CIS 3.1, 3.2)</div>
                                  <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                    CloudWatch Logs permissions enable security monitoring as recommended by CIS. CIS Benchmarks 3.1 and 3.2 recommend ensuring CloudTrail is enabled and configured for all regions. This policy ensures logging capabilities are in place, supporting CIS monitoring and audit requirements.
                                  </div>
                                  <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-block">
                                    CIS AWS Benchmark 3.1, 3.2: Logging and monitoring
                                  </div>
                                </div>
                              </div>
                              <div className="flex items-start space-x-3 bg-white/60 rounded-lg p-4 border border-purple-200/50 shadow-sm hover:shadow-md transition-shadow">
                                <CheckCircle className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
                                <div className="flex-1">
                                  <div className="text-slate-900 font-bold text-sm mb-1.5">Security Best Practices Alignment</div>
                                  <div className="text-slate-600 text-xs font-medium leading-relaxed mb-2">
                                    This policy follows CIS AWS Benchmark recommendations for IAM security, including avoiding wildcard permissions, using resource-level restrictions, and implementing proper access controls. These practices align with CIS Framework controls for securing AWS IAM configurations.
                                  </div>
                                  <div className="text-slate-500 text-xs font-semibold bg-slate-50 px-2 py-1 rounded border border-slate-200 inline-block">
                                    CIS AWS Benchmark: IAM security best practices
                                  </div>
                                </div>
                              </div>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                      {/* Additional Info */}
                      <div className="bg-blue-50/50 border-2 border-blue-200/50 rounded-xl p-4">
                        <div className="flex items-start space-x-3">
                          <Info className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
                          <div>
                            <p className="text-blue-900 font-semibold text-sm mb-1">Compliance Validation</p>
                            <p className="text-blue-700 text-xs font-medium">
                              This policy was designed with {complianceFrameworks.find(f => f.value === compliance)?.label || compliance.toUpperCase()} requirements in mind.
                              {response.compliance_status && Object.keys(response.compliance_status).length > 0 ? (
                                <> For detailed compliance validation results, see the Compliance Status section below.</>
                              ) : (
                                <> Use the Compliance Framework selector in Quick Actions above to validate this policy against {complianceFrameworks.find(f => f.value === compliance)?.label || compliance.toUpperCase()}.</>
                              )}
                            </p>
                          </div>
                        </div>
                      </div>
                </CollapsibleTile>
              )}

              {/* COMPLIANCE STATUS - Premium Subsection - Collapsible */}
              {response.compliance_status && Object.keys(response.compliance_status).length > 0 && (
                <CollapsibleTile
                  title="Compliance Status"
                  subtitle="Detailed compliance validation results"
                  icon={<ShieldCheck className="w-6 h-6 text-green-600" />}
                  defaultExpanded={false}
                  variant="info"
                  className="mb-16 animate-fadeIn"
                >
                  <div className="mb-8">
                    <div>
                    <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                      <CheckCircle className="w-7 h-7 text-blue-600" />
                      <span>Compliance Status</span>
                    </h3>
                    <p className="text-slate-600 text-sm font-medium">Compliance validation against selected framework</p>
                    </div>
                    <button
                      onClick={() => setShowComplianceStatus(!showComplianceStatus)}
                      className="group flex items-center space-x-2 px-4 py-2 bg-white/80 backdrop-blur-xl hover:bg-white/90 border-2 border-slate-200 hover:border-blue-300 rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl"
                    >
                      <span className="text-sm font-semibold text-slate-700 group-hover:text-blue-600 transition-colors duration-300">
                        {showComplianceStatus ? 'Hide' : 'Show'}
                      </span>
                      {showComplianceStatus ? (
                        <ChevronUp className="w-4 h-4 text-slate-500 group-hover:text-blue-600 transition-colors duration-300" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500 group-hover:text-blue-600 transition-colors duration-300" />
                      )}
                    </button>
                  </div>
                  
                  {/* Overall Compliance Summary Banner */}
                      {(() => {
                    const frameworks = Object.values(response.compliance_status || {});
                    // Normalize statuses for counting
                    const normalizedFrameworks = frameworks.map((f: any) => ({
                      ...f,
                      normalizedStatus: f.status === 'Partially Compliant' 
                        ? 'Partial' 
                        : f.status === 'Non-Compliant' || f.status === 'NonCompliant'
                        ? 'NonCompliant'
                        : f.status
                    }));
                    const compliantCount = normalizedFrameworks.filter((f: any) => f.normalizedStatus === 'Compliant').length;
                    const partialCount = normalizedFrameworks.filter((f: any) => f.normalizedStatus === 'Partial').length;
                    const nonCompliantCount = normalizedFrameworks.filter((f: any) => f.normalizedStatus === 'NonCompliant').length;
                    const totalViolations = frameworks.reduce((sum: number, f: any) => {
                      return sum + (f.violations?.length || f.gaps?.length || 0);
                    }, 0);
                    const hasIssues = nonCompliantCount > 0 || partialCount > 0;
                    
                    return (
                      <div className={`mb-8 border-2 rounded-2xl p-6 shadow-xl ${
                        hasIssues
                          ? partialCount > 0 && nonCompliantCount === 0
                            ? 'bg-gradient-to-r from-yellow-50 via-orange-50 to-amber-50 border-yellow-200/50'
                            : 'bg-gradient-to-r from-red-50 via-orange-50 to-yellow-50 border-red-200/50'
                          : 'bg-gradient-to-r from-green-50 via-emerald-50 to-teal-50 border-green-200/50'
                      }`}>
                        <div className="flex items-center justify-between flex-wrap gap-4">
                          <div className="flex items-center space-x-4">
                            <div className={`w-16 h-16 rounded-full flex items-center justify-center border-2 ${
                              hasIssues
                                ? partialCount > 0 && nonCompliantCount === 0
                                  ? 'bg-yellow-500/10 border-yellow-200/50'
                                  : 'bg-red-500/10 border-red-200/50'
                                : 'bg-green-500/10 border-green-200/50'
                            }`}>
                              {hasIssues ? (
                                nonCompliantCount > 0 ? (
                                <XCircle className="w-8 h-8 text-red-600" />
                                ) : (
                                  <AlertCircle className="w-8 h-8 text-yellow-600" />
                                )
                              ) : (
                                <CheckCircle className="w-8 h-8 text-green-600" />
                              )}
                </div>
                            <div>
                              <div className={`font-black text-2xl mb-1 ${
                                hasIssues
                                  ? partialCount > 0 && nonCompliantCount === 0
                                    ? 'text-yellow-900'
                                    : 'text-red-900'
                                  : 'text-green-900'
                              }`}>
                                {hasIssues 
                                  ? nonCompliantCount > 0 
                                    ? 'Non-Compliance Detected'
                                    : 'Partially Compliant'
                                  : 'Fully Compliant'}
                              </div>
                              <div className="text-slate-700 text-sm font-medium">
                                {hasIssues
                                  ? `${nonCompliantCount + partialCount} of ${frameworks.length} frameworks need attention • ${totalViolations} total ${totalViolations === 1 ? 'issue' : 'issues'}`
                                  : `All ${frameworks.length} framework requirements met`
                                }
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            <div className="text-right">
                              <div className="text-slate-600 text-xs font-semibold uppercase tracking-wide mb-1">Compliance Rate</div>
                              <div className={`font-black text-3xl ${
                                hasIssues
                                  ? partialCount > 0 && nonCompliantCount === 0
                                    ? 'text-yellow-600'
                                    : 'text-red-600'
                                  : 'text-green-600'
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
                      // Normalize status: "Partially Compliant" -> "Partial", etc.
                      const normalizedStatus = framework.status === 'Partially Compliant' 
                        ? 'Partial' 
                        : framework.status === 'Non-Compliant' || framework.status === 'NonCompliant'
                        ? 'NonCompliant'
                        : framework.status;
                      
                      const violations = framework.violations || [];
                      const gaps = framework.gaps || [];
                      const totalIssues = violations.length + gaps.length;
                      const isCompliant = normalizedStatus === 'Compliant';
                      const isPartial = normalizedStatus === 'Partial' || normalizedStatus === 'Partially Compliant';
                      
                      return (
                        <div key={key} className={`bg-white/80 backdrop-blur-xl border-2 rounded-2xl p-6 shadow-xl hover:shadow-2xl transition-all duration-300 ${
                          isCompliant
                            ? 'border-green-200/50' 
                            : isPartial
                            ? 'border-yellow-200/50'
                            : 'border-red-200/50'
                        }`}>
                          <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center space-x-3">
                              <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
                                isCompliant
                                  ? 'bg-green-500/10 border-2 border-green-200/50'
                                  : isPartial
                                  ? 'bg-yellow-500/10 border-2 border-yellow-200/50'
                                  : 'bg-red-500/10 border-2 border-red-200/50'
                              }`}>
                                {isCompliant ? (
                                  <CheckCircle className="w-6 h-6 text-green-600" />
                                ) : isPartial ? (
                                  <AlertCircle className="w-6 h-6 text-yellow-600" />
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
                              isCompliant
                                ? 'bg-green-500/10 text-green-700 border border-green-200/50'
                                : isPartial
                                ? 'bg-yellow-500/10 text-yellow-700 border border-yellow-200/50'
                                : 'bg-red-500/10 text-red-700 border border-red-200/50'
                            }`}>
                              {normalizedStatus}
                            </span>
                          </div>
                          
                          {/* Progress Indicator */}
                          {!isCompliant && (
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
                          {isCompliant && (
                            <div className="bg-green-50 rounded-xl p-4 border-2 border-green-200/50 text-center">
                              <CheckCircle className="w-8 h-8 text-green-600 mx-auto mb-2" />
                              <p className="text-green-700 font-semibold text-sm">All requirements met</p>
                            </div>
                          )}
                          
                          {/* Partial Compliance State */}
                          {isPartial && totalIssues === 0 && (
                            <div className="bg-yellow-50 rounded-xl p-4 border-2 border-yellow-200/50 text-center">
                              <AlertCircle className="w-8 h-8 text-yellow-600 mx-auto mb-2" />
                              <p className="text-yellow-700 font-semibold text-sm">Partially compliant - some requirements need attention</p>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </CollapsibleTile>
              )}

              {/* QUICK ACTIONS - Premium Subsection */}
              {response && response.policy && (
                <div className="mb-16 animate-fadeIn" style={{ animationDelay: '0.45s' }}>
                  {/* Premium Subsection Header */}
                  <div className="mb-6">
                    <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                      <HeadingBadge Icon={Sparkles} gradient="from-purple-500 to-pink-500" />
                      <span>Quick Actions</span>
                    </h3>
                    <p className="text-slate-600 text-sm font-medium">Quick access to common tasks</p>
                  </div>

                  {/* Quick Actions Card */}
                  <div className="bg-white/80 backdrop-blur-xl border-2 border-purple-200/50 rounded-2xl p-6 shadow-xl">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Compliance Framework Selector */}
                      <div className="space-y-2">
                        <label className="block text-slate-700 text-sm font-semibold">
                          <FileCheck className="w-4 h-4 inline mr-2 text-purple-600" />
                          Compliance Framework
                        </label>
                        <select
                          value={compliance}
                          onChange={async (e) => {
                            const newCompliance = e.target.value;
                            
                            // If user selects a compliance framework, validate the policy against it
                            if (newCompliance !== 'general' && response?.policy && conversationId) {
                              try {
                                setLoading(true);
                                setError(null);
                                
                                // Send a follow-up request to validate against the new compliance framework
                                const validationMessage = `Validate this policy against ${newCompliance.toUpperCase()} compliance framework and show me the compliance status.`;
                                
                                // Add user message to chat
                                const userMessage: ChatMessage = {
                                  role: 'user',
                                  content: validationMessage,
                                  timestamp: new Date().toISOString()
                                };
                                setChatHistory(prev => [...prev, userMessage]);
                                
                                const result = await sendFollowUp(
                                  validationMessage,
                                  conversationId,
                                  newCompliance,
                                  awsCredentials
                                );
                                
                                if (result) {
                                  // Add assistant response to chat
                                  const assistantMessage: ChatMessage = {
                                    role: 'assistant',
                                    content: result.final_answer || result.explanation || 'Compliance validation completed.',
                                    timestamp: new Date().toISOString()
                                  };
                                  setChatHistory(prev => [...prev, assistantMessage]);
                                  
                                  // Update response state - preserve policies, update compliance status and compliance_features
                                  setResponse(prev => prev ? {
                                    ...prev,
                                    compliance_status: result.compliance_status || prev.compliance_status,
                                    compliance_features: result.compliance_features || prev.compliance_features,
                                    final_answer: result.final_answer || prev.final_answer,
                                    explanation: result.explanation || prev.explanation,
                                    conversation_history: result.conversation_history || prev.conversation_history
                                  } : result);
                                  
                                  // Update compliance state
                                  setCompliance(newCompliance);
                                }
                              } catch (err: any) {
                                console.error("Error validating compliance:", err);
                                setError(err.message || "Failed to validate compliance. Please try again.");
                                
                                // Add error message to chat
                                const errorMessage: ChatMessage = {
                                  role: 'assistant',
                                  content: `Sorry, I encountered an error: ${err.message || 'Failed to validate compliance. Please try again.'}`,
                                  timestamp: new Date().toISOString()
                                };
                                setChatHistory(prev => [...prev, errorMessage]);
                              } finally {
                                setLoading(false);
                                if (chatEndRef.current) {
                                  chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
                                }
                              }
                            } else {
                              // Just update the state if no validation needed
                              setCompliance(newCompliance);
                            }
                          }}
                          className="w-full px-4 py-3 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl text-slate-900 text-base focus:border-purple-500 focus:ring-2 focus:ring-purple-500/30 focus:outline-none transition-all duration-300 font-medium cursor-pointer"
                        >
                          {complianceFrameworks.map(framework => (
                            <option key={framework.value} value={framework.value}>
                              {framework.label}
                            </option>
                          ))}
                        </select>
                        <p className="text-xs text-slate-500 font-medium">
                          {compliance === 'general' 
                            ? 'Select a framework to validate your policy' 
                            : `Validating against ${complianceFrameworks.find(f => f.value === compliance)?.label}`}
                        </p>
                      </div>

                      {/* Quick Action Buttons */}
                      <div className="space-y-2">
                        <label className="block text-slate-700 text-sm font-semibold">
                          <Lightbulb className="w-4 h-4 inline mr-2 text-purple-600" />
                          Quick Actions
                        </label>
                        <div className="grid grid-cols-2 gap-2">
                          <button
                            type="button"
                            onClick={async () => {
                              // Auto-send the explain message
                              if (!conversationId) {
                                setError('Please generate a policy first');
                                return;
                              }
                              
                              setIsChatbotOpen(true);
                              setIsRefining(true);
                              
                              const explainMessage = 'Explain this policy in detail';
                              
                              // Add user message to chat
                              const userMessage: ChatMessage = {
                                role: 'user',
                                content: explainMessage,
                                timestamp: new Date().toISOString()
                              };
                              setChatHistory(prev => [...prev, userMessage]);
                              
                              // Auto-send the message
                              try {
                                setLoading(true);
                                setError(null);
                                
                                const result = await sendFollowUp(
                                  explainMessage,
                                  conversationId,
                                  undefined,
                                  awsCredentials
                                );
                                
                                if (!result) {
                                  throw new Error('No response received from server');
                                }
                                
                                // Add assistant response to chat
                                const assistantMessage: ChatMessage = {
                                  role: 'assistant',
                                  content: result.final_answer || result.explanation || 'I received your explanation request.',
                                  timestamp: new Date().toISOString()
                                };
                                setChatHistory(prev => [...prev, assistantMessage]);
                                
                                // Update response state (preserve policies and scores)
                                setResponse(prev => {
                                  if (!prev) return result as any;
                                  return {
                                    ...prev,
                                    final_answer: result.final_answer || prev.final_answer,
                                    explanation: result.explanation || prev.explanation,
                                    conversation_history: result.conversation_history || prev.conversation_history
                                  };
                                });
                                
                                setError(null);
                              } catch (err: any) {
                                console.error('Error sending explain request:', err);
                                setError(err.message || 'Failed to get explanation. Please try again.');
                                
                                // Add error message to chat
                                const errorMessage: ChatMessage = {
                                  role: 'assistant',
                                  content: `Sorry, I encountered an error: ${err.message || 'Failed to get explanation. Please try again.'}`,
                                  timestamp: new Date().toISOString()
                                };
                                setChatHistory(prev => [...prev, errorMessage]);
                              } finally {
                                setLoading(false);
                                setIsRefining(false);
                                if (chatEndRef.current) {
                                  chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
                                }
                              }
                            }}
                            className="px-4 py-2.5 bg-gradient-to-r from-blue-500/10 to-blue-600/10 hover:from-blue-500/20 hover:to-blue-600/20 border-2 border-blue-200/50 hover:border-blue-300 rounded-xl text-blue-700 hover:text-blue-800 text-sm font-semibold transition-all duration-300 flex items-center justify-center space-x-2"
                          >
                            <BookOpen className="w-4 h-4" />
                            <span>Explain</span>
                          </button>
                          
                          <button
                            type="button"
                            onClick={async () => {
                              // Auto-send the compliance help message
                              if (!conversationId) {
                                setError('Please generate a policy first');
                                return;
                              }
                              
                              setIsChatbotOpen(true);
                              setIsRefining(true);
                              
                              const complianceMessage = 'What compliance requirements should I consider for this policy?';
                              
                              // Add user message to chat
                              const userMessage: ChatMessage = {
                                role: 'user',
                                content: complianceMessage,
                                timestamp: new Date().toISOString()
                              };
                              setChatHistory(prev => [...prev, userMessage]);
                              
                              // Auto-send the message
                              try {
                                setLoading(true);
                                setError(null);
                                
                                const result = await sendFollowUp(
                                  complianceMessage,
                                  conversationId,
                                  undefined,
                                  awsCredentials
                                );
                                
                                if (!result) {
                                  throw new Error('No response received from server');
                                }
                                
                                // Add assistant response to chat
                                const assistantMessage: ChatMessage = {
                                  role: 'assistant',
                                  content: result.final_answer || result.explanation || 'I received your compliance question.',
                                  timestamp: new Date().toISOString()
                                };
                                setChatHistory(prev => [...prev, assistantMessage]);
                                
                                // Update response state (preserve policies)
                                setResponse(prev => {
                                  if (!prev) return result as any;
                                  return {
                                    ...prev,
                                    final_answer: result.final_answer || prev.final_answer,
                                    explanation: result.explanation || prev.explanation,
                                    conversation_history: result.conversation_history || prev.conversation_history
                                  };
                                });
                                
                                setError(null);
                              } catch (err: any) {
                                console.error('Error sending compliance help:', err);
                                setError(err.message || 'Failed to get compliance help. Please try again.');
                                
                                // Add error message to chat
                                const errorMessage: ChatMessage = {
                                  role: 'assistant',
                                  content: `Sorry, I encountered an error: ${err.message || 'Failed to get compliance help. Please try again.'}`,
                                  timestamp: new Date().toISOString()
                                };
                                setChatHistory(prev => [...prev, errorMessage]);
                              } finally {
                                setLoading(false);
                                setIsRefining(false);
                                if (chatEndRef.current) {
                                  chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
                                }
                              }
                            }}
                            className="px-4 py-2.5 bg-gradient-to-r from-purple-500/10 to-purple-600/10 hover:from-purple-500/20 hover:to-purple-600/20 border-2 border-purple-200/50 hover:border-purple-300 rounded-xl text-purple-700 hover:text-purple-800 text-sm font-semibold transition-all duration-300 flex items-center justify-center space-x-2"
                          >
                            <FileCheck className="w-4 h-4" />
                            <span>Compliance Help</span>
                          </button>
                          
                          <button
                            type="button"
                            onClick={() => {
                              // Scroll to refinements section - find by text content
                              const allHeadings = Array.from(document.querySelectorAll('h3'));
                              const refinementsHeading = allHeadings.find(h => 
                                h.textContent?.includes('Refinement') || h.textContent?.includes('Refinements')
                              );
                              if (refinementsHeading) {
                                refinementsHeading.scrollIntoView({ behavior: 'smooth', block: 'start' });
                              } else {
                                // Fallback: scroll to security scores section
                                const scoresHeading = allHeadings.find(h => h.textContent?.includes('Security Scores'));
                                scoresHeading?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                              }
                            }}
                            className="px-4 py-2.5 bg-gradient-to-r from-pink-500/10 to-pink-600/10 hover:from-pink-500/20 hover:to-pink-600/20 border-2 border-pink-200/50 hover:border-pink-300 rounded-xl text-pink-700 hover:text-pink-800 text-sm font-semibold transition-all duration-300 flex items-center justify-center space-x-2"
                          >
                            <Target className="w-4 h-4" />
                            <span>Refinements</span>
                          </button>
                          
                          <button
                            type="button"
                            onClick={() => {
                              setFollowUpMessage('Show me both policies in JSON format');
                              setIsChatbotOpen(true);
                              setTimeout(() => {
                                const chatbotInput = document.querySelector('textarea[placeholder*="Ask me"]') as HTMLTextAreaElement;
                                chatbotInput?.focus();
                              }, 300);
                            }}
                            className="px-4 py-2.5 bg-gradient-to-r from-emerald-500/10 to-emerald-600/10 hover:from-emerald-500/20 hover:to-emerald-600/20 border-2 border-emerald-200/50 hover:border-emerald-300 rounded-xl text-emerald-700 hover:text-emerald-800 text-sm font-semibold transition-all duration-300 flex items-center justify-center space-x-2"
                          >
                            <Copy className="w-4 h-4" />
                            <span>Get JSON</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* REFINE POLICY FORM - Premium Subsection */}
              <div className="animate-fadeIn" style={{ animationDelay: '0.5s' }}>
                {/* Premium Subsection Header */}
                <div className="mb-6">
                  <h3 className="text-3xl font-bold text-slate-900 tracking-tight flex items-center space-x-3 mb-2">
                    <HeadingBadge Icon={MessageSquare} gradient="from-blue-500 to-purple-500" />
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
                {chatHistory.length === 0 && !loading && (
                  <div className="text-center text-slate-500 text-sm py-8">
                    No messages yet. Start a conversation!
                  </div>
                )}
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
                    <div key={`msg-${msg.timestamp || idx}-${msg.role}`} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
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
                            {/* Text explanation (if any) - with markdown formatting */}
                            {hasText && (
                              <div className="text-sm text-slate-700 leading-relaxed prose prose-sm max-w-none space-y-1">
                                {textContent.split('\n').map((line, lineIdx) => {
                                  // Parse markdown headers
                                  if (line.match(/^##\s+/)) {
                                    const headerText = line.replace(/^##\s+/, '').trim();
                                    // Check if next non-empty line is JSON block or another header
                                    const nextNonEmptyLine = textContent.split('\n').slice(lineIdx + 1).find(l => l.trim());
                                    const isFollowedByJSON = nextNonEmptyLine?.includes('```json') || nextNonEmptyLine?.includes('{');
                                    return (
                                      <h3 key={lineIdx} className={`text-base font-bold text-slate-900 ${lineIdx === 0 ? 'mt-0' : 'mt-4'} ${isFollowedByJSON ? 'mb-1' : 'mb-2'}`}>
                                        {headerText}
                                      </h3>
                                    );
                                  }
                                  if (line.match(/^###\s+/)) {
                                    const headerText = line.replace(/^###\s+/, '').trim();
                                    return (
                                      <h4 key={lineIdx} className="text-sm font-bold text-slate-800 mt-3 mb-1.5">
                                        {headerText}
                                      </h4>
                                    );
                                  }
                                  // Parse bold text (**text**)
                                  if (line.includes('**')) {
                                    const parts = line.split(/(\*\*[^*]+\*\*)/g);
                                    return (
                                      <p key={lineIdx} className="mb-2">
                                        {parts.map((part, partIdx) => {
                                          if (part.startsWith('**') && part.endsWith('**')) {
                                            return <strong key={partIdx} className="font-bold text-slate-900">{part.slice(2, -2)}</strong>;
                                          }
                                          return <span key={partIdx}>{part}</span>;
                                        })}
                                      </p>
                                    );
                                  }
                                  // Parse bullet points (- or •)
                                  if (line.match(/^[-•*]\s+/)) {
                                    const bulletText = line.replace(/^[-•*]\s+/, '').trim();
                                    // Check if bullet text contains bold (**text**)
                                    if (bulletText.includes('**')) {
                                      const parts = bulletText.split(/(\*\*[^*]+\*\*)/g);
                                    return (
                                        <div key={lineIdx} className="flex items-start mb-2">
                                          <span className="text-slate-500 mr-2 mt-0.5 flex-shrink-0">•</span>
                                          <span className="flex-1">
                                            {parts.map((part, partIdx) => {
                                              if (part.startsWith('**') && part.endsWith('**')) {
                                                return <strong key={partIdx} className="font-semibold text-slate-900">{part.slice(2, -2)}</strong>;
                                              }
                                              return <span key={partIdx}>{part}</span>;
                                            })}
                                          </span>
                                        </div>
                                      );
                                    }
                                    return (
                                      <div key={lineIdx} className="flex items-start mb-2">
                                        <span className="text-slate-500 mr-2 mt-0.5 flex-shrink-0">•</span>
                                        <span className="flex-1">{bulletText}</span>
                                      </div>
                                    );
                                  }
                                  // Parse numbered lists (1. 2. etc.)
                                  if (line.match(/^\d+\.\s+/)) {
                                    const listText = line.replace(/^\d+\.\s+/, '').trim();
                                    const number = line.match(/^\d+/)?.[0];
                                    // Check if list text contains bold (**text**)
                                    if (listText.includes('**')) {
                                      const parts = listText.split(/(\*\*[^*]+\*\*)/g);
                                    return (
                                        <div key={lineIdx} className="flex items-start mb-2">
                                          <span className="text-slate-500 mr-2 mt-0.5 font-semibold flex-shrink-0">{number}.</span>
                                          <span className="flex-1">
                                            {parts.map((part, partIdx) => {
                                              if (part.startsWith('**') && part.endsWith('**')) {
                                                return <strong key={partIdx} className="font-semibold text-slate-900">{part.slice(2, -2)}</strong>;
                                              }
                                              return <span key={partIdx}>{part}</span>;
                                            })}
                                          </span>
                                        </div>
                                      );
                                    }
                                    return (
                                      <div key={lineIdx} className="flex items-start mb-2">
                                        <span className="text-slate-500 mr-2 mt-0.5 font-semibold flex-shrink-0">{number}.</span>
                                        <span className="flex-1">{listText}</span>
                                      </div>
                                    );
                                  }
                                  // Parse horizontal rules (---)
                                  if (line.trim() === '---' || line.trim().match(/^-{3,}$/)) {
                                    return (
                                      <hr key={lineIdx} className="my-4 border-t-2 border-slate-200" />
                                    );
                                  }
                                  // Regular paragraph
                                  if (line.trim()) {
                                    // Check if this is a numbered list item (1., 2., etc.) or bullet point
                                    const isNumberedList = /^\d+\.\s+/.test(line.trim());
                                    const isBulletPoint = /^[-•*]\s+/.test(line.trim());
                                    const isBoldText = line.includes('**');
                                    
                                    if (isBoldText) {
                                      // Parse bold text
                                      const parts = line.split(/(\*\*[^*]+\*\*)/g);
                                      return (
                                        <p key={lineIdx} className="mb-2 last:mb-0 text-slate-700 leading-relaxed">
                                          {parts.map((part, partIdx) => {
                                            if (part.startsWith('**') && part.endsWith('**')) {
                                              return <strong key={partIdx} className="font-bold text-slate-900">{part.slice(2, -2)}</strong>;
                                            }
                                            return <span key={partIdx}>{part}</span>;
                                          })}
                                        </p>
                                      );
                                    }
                                    
                                    if (isNumberedList || isBulletPoint) {
                                      // Already handled above, but keep as fallback
                                    return (
                                      <p key={lineIdx} className="mb-2 last:mb-0 text-slate-700 leading-relaxed">
                                        {line}
                                      </p>
                                    );
                                  }
                                    
                                    return (
                                      <p key={lineIdx} className="mb-2 last:mb-0 text-slate-700 leading-relaxed">
                                        {line}
                                      </p>
                                    );
                                  }
                                  // Empty line - skip if previous line was a header or if next line is JSON
                                  const prevLine = lineIdx > 0 ? textContent.split('\n')[lineIdx - 1] : '';
                                  const nextLine = textContent.split('\n')[lineIdx + 1] || '';
                                  const isAfterHeader = prevLine.match(/^##\s+/);
                                  const isBeforeJSON = nextLine.includes('```json') || nextLine.trim().startsWith('{');
                                  // Skip empty lines after headers or before JSON to prevent gaps
                                  if (isAfterHeader || isBeforeJSON) {
                                    return null;
                                  }
                                  // Only add spacing for meaningful empty lines
                                  return <br key={lineIdx} />;
                                })}
                              </div>
                            )}
                            
                            {/* JSON blocks (both policies) */}
                            {hasJSON && jsonBlocks.map((jsonBlock, jsonIdx) => {
                              try {
                                const parsed = JSON.parse(jsonBlock);
                                const isTrustPolicy = JSON.stringify(parsed).includes('"Principal"');
                                return (
                                  <div key={jsonIdx} className={`bg-slate-100 rounded-lg p-3 border border-slate-200 ${jsonIdx === 0 ? 'mt-1' : 'mt-3'}`}>
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
                <form onSubmit={(e) => handleFollowUp(e, true)} className="space-y-2">
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
      
      {/* Validation Results Section - REMOVED */}
      {false && (
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="bg-white rounded-2xl shadow-xl border-2 border-emerald-200/50 p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-2xl font-bold text-slate-900 flex items-center space-x-3">
                <Shield className="w-6 h-6 text-emerald-600" />
                <span>Validation Results</span>
              </h3>
              <button
                onClick={() => {}}
                className="text-slate-400 hover:text-slate-600 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            
            {/* Risk Score */}
            <div className="bg-gradient-to-r from-emerald-50 to-teal-50 rounded-xl p-4 mb-6">
              <div className="text-center">
                <div className="text-4xl font-black text-emerald-600 mb-2">
                  {0}/100
                </div>
                <div className="text-sm font-semibold text-emerald-700">Security Risk Score</div>
              </div>
            </div>
            
            {/* Findings Summary */}
            {false && (
              <div className="mb-4">
                <h4 className="text-lg font-bold text-slate-800 mb-3">Security Findings</h4>
                <div className="space-y-2">
                  {[].slice(0, 5).map((finding: any, index: number) => (
                    <div key={index} className="flex items-start space-x-3 bg-slate-50 rounded-lg p-3">
                      <AlertCircle className={`w-5 h-5 mt-0.5 ${
                        finding.severity === 'Critical' ? 'text-red-600' :
                        finding.severity === 'High' ? 'text-orange-600' :
                        finding.severity === 'Medium' ? 'text-yellow-600' :
                        'text-blue-600'
                      }`} />
                      <div className="flex-1">
                        <div className="font-semibold text-slate-900">{finding.title}</div>
                        <div className="text-sm text-slate-600">{finding.description}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            <div className="mt-4 text-center">
              <button
                onClick={() => {}}
                className="px-6 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg font-semibold transition-all"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
      
      {/* Manage AWS Modal (Deploy/Delete) */}
      {showDeployModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto border-2 border-orange-200/50">
            <div className="sticky top-0 bg-gradient-to-r from-orange-50 to-red-50 px-6 py-4 border-b-2 border-orange-200/50">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-2xl font-bold text-slate-900 flex items-center space-x-3">
                  <Upload className="w-6 h-6 text-orange-600" />
                  <span>Manage IAM Roles</span>
                </h3>
                <button
                  onClick={() => {
                    setShowDeployModal(false);
                    setDeployError(null);
                    setDeploySuccess(null);
                    setDeleteError(null);
                    setDeleteSuccess(null);
                    setManageTab('deploy');
                  }}
                  className="text-slate-400 hover:text-slate-600 transition-colors"
                >
                  <X className="w-6 h-6" />
                </button>
              </div>
              
              {/* Single tab (deploy only) */}
              <div className="flex space-x-2">
                <button
                  className="flex-1 px-4 py-2 rounded-lg font-semibold transition-all bg-white text-orange-600 shadow-md cursor-default"
                  disabled
                >
                  Deploy Role
                </button>
              </div>
            </div>
            
            <div className="p-6 space-y-6">
              {/* Deploy Tab Content */}
              {manageTab === 'deploy' && (
                <>
              {deploySuccess && (
                <div className="bg-emerald-50 border-2 border-emerald-200 rounded-xl p-4">
                  <div className="flex items-center space-x-3">
                    <CheckCircle className="w-6 h-6 text-emerald-600" />
                    <div>
                      <div className="font-bold text-emerald-800">Deployment Successful!</div>
                      <div className="text-sm text-emerald-700 mt-1">{deploySuccess}</div>
                    </div>
                  </div>
                </div>
              )}
              
              {deployError && (
                <div className="bg-red-50 border-2 border-red-200 rounded-xl p-4">
                  <div className="flex items-center space-x-3">
                    <AlertCircle className="w-6 h-6 text-red-600" />
                    <div>
                      <div className="font-bold text-red-800">Deployment Failed</div>
                      <div className="text-sm text-red-700 mt-1">{deployError}</div>
                    </div>
                  </div>
                </div>
              )}
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-bold text-slate-700 mb-2">
                    Role Name <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={deployRoleName}
                    onChange={(e) => setDeployRoleName(e.target.value)}
                    placeholder="my-lambda-role"
                    className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:border-orange-400 focus:ring-2 focus:ring-orange-200 transition-all"
                    required
                  />
                  <p className="text-xs text-slate-500 mt-1">Must be unique in your AWS account</p>
                </div>
                
                <div>
                  <label className="block text-sm font-bold text-slate-700 mb-2">
                    AWS Region
                  </label>
                  <select
                    value={deployRegion}
                    onChange={(e) => setDeployRegion(e.target.value)}
                    className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:border-orange-400 focus:ring-2 focus:ring-orange-200 transition-all"
                  >
                    <option value="us-east-1">US East (N. Virginia) - us-east-1</option>
                    <option value="us-west-2">US West (Oregon) - us-west-2</option>
                    <option value="eu-west-1">Europe (Ireland) - eu-west-1</option>
                    <option value="ap-southeast-1">Asia Pacific (Singapore) - ap-southeast-1</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-bold text-slate-700 mb-2">
                    Description (Optional)
                  </label>
                  <textarea
                    value={deployDescription}
                    onChange={(e) => setDeployDescription(e.target.value)}
                    placeholder="IAM role for Lambda function to access S3 and DynamoDB"
                    rows={3}
                    className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:border-orange-400 focus:ring-2 focus:ring-orange-200 transition-all resize-none"
                  />
                </div>
                
                <div className="bg-blue-50 border-2 border-blue-200 rounded-xl p-4">
                  <div className="flex items-start space-x-3">
                    <Info className="w-5 h-5 text-blue-600 mt-0.5" />
                    <div className="text-sm text-blue-800">
                      <div className="font-bold mb-1">What will be deployed:</div>
                      <ul className="list-disc list-inside space-y-1 text-blue-700">
                        <li>IAM Role with the trust policy</li>
                        <li>Permissions policy attached as inline policy</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="flex flex-col space-y-3 pt-4 border-t-2 border-slate-200">
                <div className="flex items-center space-x-3">
                  <button
                    onClick={async () => {
                      if (!deployRoleName.trim()) {
                        setDeployError('Role name is required');
                        return;
                      }
                      
                      setDeployLoading(true);
                      setDeployError(null);
                      setDeploySuccess(null);
                      
                      try {
                        if (!response || !response.policy) {
                          setDeployError('No policy available to deploy');
                          setDeployLoading(false);
                          return;
                        }
                        
                        const policy = response.policy;
                        const trustPolicy = response.trust_policy || {};
                        
                        const result = await deployRole({
                          role_name: deployRoleName.trim(),
                          trust_policy: trustPolicy,
                          permissions_policy: policy,
                          description: deployDescription.trim() || undefined,
                          aws_region: deployRegion,
                          deploy_as_inline: true
                        });
                        
                        if (result.success) {
                          setDeploySuccess(result.message || `Role ${deployRoleName} deployed successfully! ARN: ${result.role_arn}`);
                          setTimeout(() => {
                            setShowDeployModal(false);
                            setDeploySuccess(null);
                          }, 3000);
                        } else {
                          setDeployError(result.error || 'Deployment failed');
                        }
                      } catch (err: any) {
                        setDeployError(err.message || 'Failed to deploy role');
                      } finally {
                        setDeployLoading(false);
                      }
                    }}
                    disabled={deployLoading || !deployRoleName.trim()}
                    className="flex-1 px-6 py-3 bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 text-white font-bold rounded-xl transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-xl flex items-center justify-center space-x-2"
                  >
                    {deployLoading ? (
                      <>
                        <RefreshCw className="w-5 h-5 animate-spin" />
                        <span>Deploying...</span>
                      </>
                    ) : (
                      <>
                        <Upload className="w-5 h-5" />
                        <span>Deploy to AWS</span>
                      </>
                    )}
                  </button>
                  <button
                    onClick={() => {
                      setShowDeployModal(false);
                      setDeployError(null);
                      setDeploySuccess(null);
                    }}
                    className="px-6 py-3 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold rounded-xl transition-all duration-300"
                  >
                    Cancel
                  </button>
                </div>
                
                {/* AWS CLI Command Option (advanced) */}
                {response && response.policy && response.trust_policy && (
                  <div className="border-t border-slate-200 pt-3">
                    <button
                      type="button"
                      onClick={() => setShowCliCommands((prev) => !prev)}
                      className="w-full px-4 py-2 text-sm font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition flex items-center justify-between"
                    >
                      <span className="flex items-center space-x-2">
                        <Info className="w-4 h-4 text-slate-600" />
                        <span>Advanced (optional): Show AWS CLI commands</span>
                      </span>
                      <span className="text-xs text-slate-500">{showCliCommands ? 'Hide' : 'Show'}</span>
                    </button>

                    {showCliCommands && (
                      <div className="mt-3 bg-slate-50 border-2 border-slate-200 rounded-xl p-4">
                        <div className="flex items-start justify-between space-x-3 mb-3">
                          <div className="flex items-start space-x-2 flex-1">
                            <Info className="w-5 h-5 text-slate-600 mt-0.5 flex-shrink-0" />
                            <div className="text-sm text-slate-700">
                              <div className="font-bold mb-1">💡 Deploy to Your Own AWS Account</div>
                              <p className="text-slate-600">
                                Copy these AWS CLI commands and run them in your terminal. This uses YOUR AWS credentials.
                              </p>
                            </div>
                          </div>
                          <button
                            onClick={() => {
                              const trustPolicyJson = JSON.stringify(response.trust_policy, null, 2);
                              const permissionsPolicyJson = JSON.stringify(response.policy, null, 2);
                              const roleName = deployRoleName.trim() || 'my-iam-role';
                              const description = deployDescription.trim() || 'IAM role generated by Aegis IAM';
                              
                              const commands = `# Step 1: Create the IAM role with trust policy
aws iam create-role \\
  --role-name ${roleName} \\
  --assume-role-policy-document '${trustPolicyJson.replace(/'/g, "'\"'\"'")}' \\
  --description "${description}"

# Step 2: Attach the permissions policy as an inline policy
aws iam put-role-policy \\
  --role-name ${roleName} \\
  --policy-name ${roleName}-permissions \\
  --policy-document '${permissionsPolicyJson.replace(/'/g, "'\"'\"'")}'

# Verify the role was created
aws iam get-role --role-name ${roleName}`;
                              
                              navigator.clipboard.writeText(commands);
                              setCopied(true);
                              setTimeout(() => setCopied(false), 2000);
                            }}
                            className="px-4 py-2 bg-slate-700 hover:bg-slate-800 text-white text-sm font-semibold rounded-lg transition-all flex items-center space-x-2 whitespace-nowrap"
                          >
                            {copied ? (
                              <>
                                <CheckCircle className="w-4 h-4" />
                                <span>Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-4 h-4" />
                                <span>Copy AWS CLI Commands</span>
                              </>
                            )}
                          </button>
                        </div>
                        <div className="bg-slate-900 text-green-400 p-3 rounded-lg font-mono text-xs overflow-x-auto max-h-40 overflow-y-auto">
                          <div className="whitespace-pre-wrap">{`# Deploy to your AWS account
# Prerequisites: aws configure (uses YOUR credentials)

# 1. Create role with trust policy
aws iam create-role \\
  --role-name ${deployRoleName.trim() || '[ROLE_NAME]'} \\
  --assume-role-policy-document file://trust-policy.json \\
  --description "${deployDescription.trim() || 'IAM role generated by Aegis IAM'}"

# 2. Attach permissions as inline policy  
aws iam put-role-policy \\
  --role-name ${deployRoleName.trim() || '[ROLE_NAME]'} \\
  --policy-name ${(deployRoleName.trim() || 'ROLE_NAME')}-permissions \\
  --policy-document file://permissions-policy.json

# 3. Verify creation
aws iam get-role --role-name ${deployRoleName.trim() || '[ROLE_NAME]'}

# Note: Save trust-policy.json and permissions-policy.json files first`}</div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
                </>
              )}
              
              {/* Delete Tab Content */}
              {manageTab === 'delete' && (
                <>
                  {deleteSuccess && (
                    <div className="bg-emerald-50 border-2 border-emerald-200 rounded-xl p-4">
                      <div className="flex items-center space-x-3">
                        <CheckCircle className="w-6 h-6 text-emerald-600" />
                        <div>
                          <div className="font-bold text-emerald-800">Role Deleted Successfully!</div>
                          <div className="text-sm text-emerald-700 mt-1">{deleteSuccess}</div>
                        </div>
                      </div>
                    </div>
                  )}
                  
                  {deleteError && (
                    <div className="bg-red-50 border-2 border-red-200 rounded-xl p-4">
                      <div className="flex items-center space-x-3">
                        <AlertCircle className="w-6 h-6 text-red-600" />
                        <div>
                          <div className="font-bold text-red-800">Delete Failed</div>
                          <div className="text-sm text-red-700 mt-1">{deleteError}</div>
                        </div>
                      </div>
                    </div>
                  )}
                  
                  <div className="bg-red-50 border-2 border-red-200 rounded-xl p-4">
                    <div className="flex items-start space-x-3">
                      <AlertCircle className="w-5 h-5 text-red-600 mt-0.5" />
                      <div className="text-sm text-red-800">
                        <strong>Warning:</strong> This will permanently delete the IAM role and all attached policies. This action cannot be undone.
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-bold text-slate-700 mb-2">
                        Role Name <span className="text-red-500">*</span>
                      </label>
                      <input
                        type="text"
                        value={deleteRoleName}
                        onChange={(e) => setDeleteRoleName(e.target.value)}
                        placeholder="test-role or my-lambda-role"
                        className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:border-red-400 focus:ring-2 focus:ring-red-200 transition-all"
                        required
                      />
                      <p className="text-xs text-slate-500 mt-1">Enter the exact role name to delete</p>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-bold text-slate-700 mb-2">
                        AWS Region
                      </label>
                      <select
                        value={deployRegion}
                        onChange={(e) => setDeployRegion(e.target.value)}
                        className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:border-red-400 focus:ring-2 focus:ring-red-200 transition-all"
                      >
                        <option value="us-east-1">US East (N. Virginia) - us-east-1</option>
                        <option value="us-west-2">US West (Oregon) - us-west-2</option>
                        <option value="eu-west-1">Europe (Ireland) - eu-west-1</option>
                        <option value="ap-southeast-1">Asia Pacific (Singapore) - ap-southeast-1</option>
                      </select>
                    </div>
                  </div>
                  
                  <div className="flex space-x-3 pt-4 border-t-2 border-slate-200">
                    <button
                      onClick={async () => {
                        if (!deleteRoleName.trim()) {
                          setDeleteError('Please enter a role name');
                          return;
                        }
                        
                        setDeleteLoading(true);
                        setDeleteError(null);
                        setDeleteSuccess(null);
                        
                        try {
                          const result = await deleteRole({
                            role_name: deleteRoleName,
                            aws_region: deployRegion
                          });
                          
                          if (result.success) {
                            setDeleteSuccess(result.message || `Role "${deleteRoleName}" deleted successfully`);
                            setDeleteRoleName('');
                          } else {
                            setDeleteError(result.error || 'Failed to delete role');
                          }
                        } catch (err) {
                          setDeleteError(err instanceof Error ? err.message : 'An error occurred');
                        } finally {
                          setDeleteLoading(false);
                        }
                      }}
                      disabled={deleteLoading || !deleteRoleName.trim()}
                      className="flex-1 bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white py-3 px-6 rounded-xl font-bold transition-all duration-300 shadow-lg hover:shadow-xl flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {deleteLoading ? (
                        <>
                          <RefreshCw className="w-5 h-5 animate-spin" />
                          <span>Deleting...</span>
                        </>
                      ) : (
                        <>
                          <AlertCircle className="w-5 h-5" />
                          <span>Delete Role</span>
                        </>
                      )}
                    </button>
                    <button
                      onClick={() => {
                        setShowDeployModal(false);
                        setDeleteError(null);
                        setDeleteSuccess(null);
                        setDeleteRoleName('');
                        setManageTab('deploy');
                      }}
                      className="px-6 py-3 border-2 border-slate-300 text-slate-700 rounded-xl font-bold hover:bg-slate-50 transition-all"
                    >
                      Cancel
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
      
      {/* Explain in Simple Terms Modal */}
      {showExplainModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto border-2 border-indigo-200/50">
            <div className="sticky top-0 bg-gradient-to-r from-indigo-50 to-purple-50 px-6 py-4 border-b-2 border-indigo-200/50 flex items-center justify-between">
              <h3 className="text-2xl font-bold text-slate-900 flex items-center space-x-3">
                <BookOpen className="w-6 h-6 text-indigo-600" />
                <span>Simple Explanation</span>
              </h3>
              <button
                onClick={() => {
                  setShowExplainModal(false);
                  setSimpleExplanation(null);
                }}
                className="text-slate-400 hover:text-slate-600 transition-colors"
              >
                <X className="w-6 h-6" />
              </button>
            </div>
            
            <div className="p-6">
              {explainLoading ? (
                <div className="flex items-center justify-center py-12">
                  <RefreshCw className="w-8 h-8 text-indigo-600 animate-spin" />
                  <span className="ml-3 text-slate-600 font-medium">Generating explanation...</span>
                </div>
              ) : simpleExplanation ? (
                <div className="prose prose-slate max-w-none">
                  <div className="bg-gradient-to-br from-indigo-50 to-purple-50 rounded-xl p-6 border-2 border-indigo-200/50">
                    <div className="text-slate-800 leading-relaxed space-y-4">
                      {simpleExplanation.split('\n').map((line, index) => {
                        // Handle headers (## headings - subsections)
                        if (line.startsWith('## ')) {
                          return (
                            <h3 key={index} className="text-lg font-bold text-indigo-800 mt-4 mb-2">
                              {line.replace('## ', '')}
                            </h3>
                          );
                        }
                        if (line.startsWith('# ')) {
                          return (
                            <h2 key={index} className="text-xl font-bold text-indigo-900 mb-3 border-b border-indigo-200 pb-2">
                              {line.replace('# ', '')}
                            </h2>
                          );
                        }
                        // Handle bullet points (keep the bullet for list items, but detect if it's a heading)
                        if (line.startsWith('- ')) {
                          const content = line.replace('- ', '').trim();
                          const formattedLine = content.replace(/\*\*(.*?)\*\*/g, '<strong class="text-indigo-700">$1</strong>');
                          
                          // Check if this is a main heading (ends with colon or question mark)
                          const isHeading = content.endsWith(':') || content.endsWith('?');
                          
                          if (isHeading) {
                            // Render as heading without bullet
                            return (
                              <h4 key={index} className="text-base font-bold text-indigo-800 mt-3 mb-1" dangerouslySetInnerHTML={{ __html: formattedLine }} />
                            );
                          }
                          
                          // Regular bullet point
                          return (
                            <div key={index} className="flex items-start gap-3 ml-4">
                              <span className="text-indigo-500 mt-1.5">•</span>
                              <span dangerouslySetInnerHTML={{ __html: formattedLine }} />
                            </div>
                          );
                        }
                        // Handle numbered lists
                        const numberedMatch = line.match(/^(\d+)\.\s+(.+)/);
                        if (numberedMatch) {
                          const formattedLine = numberedMatch[2].replace(/\*\*(.*?)\*\*/g, '<strong class="text-indigo-700">$1</strong>');
                          return (
                            <div key={index} className="flex items-start gap-3 ml-4 mb-2">
                              <span className="bg-indigo-600 text-white text-xs font-bold w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0">
                                {numberedMatch[1]}
                              </span>
                              <span dangerouslySetInnerHTML={{ __html: formattedLine }} />
                            </div>
                          );
                        }
                        // Regular text with bold formatting
                        if (line.trim()) {
                          const formattedLine = line.replace(/\*\*(.*?)\*\*/g, '<strong class="text-indigo-700">$1</strong>');
                          return (
                            <p key={index} className="text-slate-700" dangerouslySetInnerHTML={{ __html: formattedLine }} />
                          );
                        }
                        return null;
                      })}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-slate-500">
                  No explanation available
                </div>
              )}
              
              <div className="mt-6 flex justify-end">
                <button
                  onClick={() => {
                    setShowExplainModal(false);
                    setSimpleExplanation(null);
                  }}
                  className="px-6 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default GeneratePolicy;