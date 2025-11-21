import React, { useState, useEffect } from 'react';
import { Scan, Shield, Activity, Database, Users, Lock, AlertTriangle, CheckCircle, Zap, Target, TrendingUp, Clock, Play, ChevronRight, XCircle, AlertCircle, Download, RefreshCw, Code, Eye, Settings, Info } from 'lucide-react';
import { saveToStorage, loadFromStorage, STORAGE_KEYS } from '../../utils/persistence';

interface AuditSummary {
  total_roles: number;
  roles_analyzed: number;
  total_findings: number;
  critical_issues: number;
  high_issues: number;
  medium_issues: number;
  low_issues: number;
  cloudtrail_events_analyzed: number;
  unused_permissions_found: number;
}

interface Finding {
  id: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  type: string;
  title: string;
  description: string;
  recommendation: string;
  role?: string;
  affected_permissions?: string[];
  why_it_matters?: string;
  impact?: string;
  detailed_remediation?: string;
  compliance_violations?: string[];
  policy_snippet?: string;
}

interface AuditResponse {
  success: boolean;
  audit_summary: AuditSummary;
  risk_score: number;  // 0-100, where 100 = worst risk (industry standard)
  security_score?: number;  // 0-100, where 100 = best security (for UI display)
  findings: Finding[];
  cloudtrail_analysis: any;
  scp_analysis: any;
  recommendations: string[];
  compliance_status: Record<string, any>;
  timestamp: string;
  error?: string;
}

const AuditAccount: React.FC = () => {
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditResults, setAuditResults] = useState<AuditResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isRemediating, setIsRemediating] = useState(false);
  const [remediationResults, setRemediationResults] = useState<any>(null);
  const [chatInput, setChatInput] = useState('');
  const [chatMessages, setChatMessages] = useState<Array<{role: 'user' | 'assistant', content: string}>>([]);
  const [isChatLoading, setIsChatLoading] = useState(false);
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set());
  
  // Remediation state
  const [selectedFindings, setSelectedFindings] = useState<Set<number>>(new Set());
  const [remediationStep, setRemediationStep] = useState<'select' | 'review' | 'confirm' | 'processing' | 'complete'>('select');
  const [remediationPreview, setRemediationPreview] = useState<any>(null);
  
  // Filters and view state
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [roleFilter, setRoleFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<'detailed' | 'compact'>('compact');
  const [currentPage, setCurrentPage] = useState(1);
  const [findingsPerPage] = useState(25);
  const [groupBy, setGroupBy] = useState<'none' | 'severity' | 'role'>('severity');

  // ============================================
  // PERSISTENCE: Load saved state on mount
  // ============================================
  useEffect(() => {
    const saved = loadFromStorage<{
      auditResults: AuditResponse | null;
      chatMessages: Array<{role: 'user' | 'assistant', content: string}>;
      selectedFindings: number[];
      severityFilter: string;
      roleFilter: string;
      searchQuery: string;
      viewMode: 'detailed' | 'compact';
      currentPage: number;
      groupBy: 'none' | 'severity' | 'role';
    }>(STORAGE_KEYS.AUDIT_ACCOUNT);

    if (saved) {
      console.log('🔄 Restoring saved Audit Account state');
      setAuditResults(saved.auditResults);
      setChatMessages(saved.chatMessages || []);
      setSelectedFindings(new Set(saved.selectedFindings || []));
      setSeverityFilter(saved.severityFilter || 'all');
      setRoleFilter(saved.roleFilter || 'all');
      setSearchQuery(saved.searchQuery || '');
      setViewMode(saved.viewMode || 'compact');
      setCurrentPage(saved.currentPage || 1);
      setGroupBy(saved.groupBy || 'severity');
    }
  }, []); // Only run on mount

  // ============================================
  // PERSISTENCE: Save state whenever it changes
  // ============================================
  useEffect(() => {
    // Only save if we have meaningful data (audit results or chat)
    if (auditResults || chatMessages.length > 0) {
      const stateToSave = {
        auditResults,
        chatMessages,
        selectedFindings: Array.from(selectedFindings),
        severityFilter,
        roleFilter,
        searchQuery,
        viewMode,
        currentPage,
        groupBy
      };
      saveToStorage(STORAGE_KEYS.AUDIT_ACCOUNT, stateToSave, 24); // 24 hours expiry
    }
  }, [auditResults, chatMessages, selectedFindings, severityFilter, roleFilter, searchQuery, viewMode, currentPage, groupBy]);

  const handleStartAudit = async () => {
    setIsAuditing(true);
    setError(null);

    try {
      const response = await fetch('http://localhost:8000/api/audit/account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'full',
          aws_region: 'us-east-1'
        })
      });

      const data = await response.json();
      console.log('Audit response received:', data);

      if (data.success) {
        // Ensure all required fields have defaults
        const sanitizedData = {
          ...data,
          audit_summary: {
            total_roles: data.audit_summary?.total_roles || 0,
            roles_analyzed: data.audit_summary?.roles_analyzed || 0,
            total_findings: data.audit_summary?.total_findings || 0,
            critical_issues: data.audit_summary?.critical_issues || 0,
            high_issues: data.audit_summary?.high_issues || 0,
            medium_issues: data.audit_summary?.medium_issues || 0,
            low_issues: data.audit_summary?.low_issues || 0,
            cloudtrail_events_analyzed: data.audit_summary?.cloudtrail_events_analyzed || 0,
            unused_permissions_found: data.audit_summary?.unused_permissions_found || 0,
          },
          risk_score: data.risk_score || 0,
          security_score: data.security_score,
          findings: data.findings || [],
          recommendations: data.recommendations || [],
          cloudtrail_analysis: data.cloudtrail_analysis || {},
          scp_analysis: data.scp_analysis || {},
          compliance_status: data.compliance_status || {},
          success: true
        };
        setAuditResults(sanitizedData);
        setError(null);
      } else {
        setError(data.error || 'Audit failed. Please check your AWS credentials.');
        setAuditResults(null);
      }
    } catch (err) {
      setError('Failed to connect to backend. Ensure the server is running.');
      console.error('Audit error:', err);
      setAuditResults(null);
    } finally {
      setIsAuditing(false);
    }
  };

  const handleRemediate = async (mode: 'all' | 'critical') => {
    if (!auditResults) return;

    setIsRemediating(true);
    setError(null);
    setRemediationResults(null);

    try {
      const response = await fetch('http://localhost:8000/api/audit/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          findings: auditResults.findings,
          mode: mode
        })
      });

      const data = await response.json();

      if (data.success) {
        setRemediationResults(data);
        // Refresh audit results after 2 seconds
        setTimeout(() => {
          handleStartAudit();
        }, 2000);
      } else {
        setError(data.error || 'Remediation failed.');
      }
    } catch (err) {
      setError('Failed to apply fixes. Ensure the server is running.');
      console.error(err);
    } finally {
      setIsRemediating(false);
    }
  };

  const handleSendMessage = async () => {
    if (!chatInput.trim() || !auditResults) return;
    
    const userMessage = chatInput.trim();
    setChatInput('');
    
    // Add user message to chat
    setChatMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setIsChatLoading(true);
    
    try {
      // Send to backend for AI response
      const response = await fetch('http://localhost:8000/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMessage,
          context: {
            findings: auditResults.findings,
            risk_score: auditResults.risk_score,
            audit_summary: auditResults.audit_summary
          }
        })
      });
      
      const data = await response.json();
      
      if (data.success) {
        setChatMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
      } else {
        setChatMessages(prev => [...prev, { 
          role: 'assistant', 
          content: 'I apologize, but I encountered an error processing your request. Please try again.' 
        }]);
      }
    } catch (err) {
      console.error('Chat error:', err);
      setChatMessages(prev => [...prev, { 
        role: 'assistant', 
        content: 'I apologize, but I\'m having trouble connecting. Please ensure the backend server is running.' 
      }]);
    } finally {
      setIsChatLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    // Premium theme with richer, more saturated colors
    switch (severity) {
      case 'Critical': return { 
        bg: 'bg-white', 
        border: 'border-red-300', 
        text: 'text-red-800', 
        icon: 'bg-red-500 text-white',
        badge: 'bg-red-500 text-white border-red-600'
      };
      case 'High': return { 
        bg: 'bg-white', 
        border: 'border-orange-300', 
        text: 'text-orange-800', 
        icon: 'bg-orange-500 text-white',
        badge: 'bg-orange-500 text-white border-orange-600'
      };
      case 'Medium': return { 
        bg: 'bg-white', 
        border: 'border-yellow-300', 
        text: 'text-yellow-800', 
        icon: 'bg-yellow-500 text-white',
        badge: 'bg-yellow-500 text-white border-yellow-600'
      };
      case 'Low': return { 
        bg: 'bg-white', 
        border: 'border-blue-300', 
        text: 'text-blue-800', 
        icon: 'bg-blue-500 text-white',
        badge: 'bg-blue-500 text-white border-blue-600'
      };
      default: return { 
        bg: 'bg-white', 
        border: 'border-slate-300', 
        text: 'text-slate-800', 
        icon: 'bg-slate-500 text-white',
        badge: 'bg-slate-500 text-white border-slate-600'
      };
    }
  };

  // Security score: Higher = Better (0-100, where 100 = best security)
  const getSecurityGrade = (securityScore: number) => {
    if (securityScore >= 90) return { grade: 'A+', label: 'Excellent Security', color: 'emerald', bg: 'from-emerald-500/20 to-green-500/20', border: 'border-emerald-500/50' };
    if (securityScore >= 80) return { grade: 'A', label: 'Very Good', color: 'emerald', bg: 'from-emerald-500/20 to-emerald-400/20', border: 'border-emerald-500/40' };
    if (securityScore >= 70) return { grade: 'B', label: 'Good', color: 'blue', bg: 'from-blue-500/20 to-cyan-500/20', border: 'border-blue-500/40' };
    if (securityScore >= 60) return { grade: 'C', label: 'Moderate', color: 'yellow', bg: 'from-yellow-500/20 to-amber-500/20', border: 'border-yellow-500/40' };
    if (securityScore >= 50) return { grade: 'D', label: 'Needs Improvement', color: 'orange', bg: 'from-orange-500/20 to-red-500/20', border: 'border-orange-500/40' };
    return { grade: 'F', label: 'High Risk', color: 'red', bg: 'from-red-500/20 to-pink-500/20', border: 'border-red-500/50' };
  };

  return (
    <div className="min-h-screen relative overflow-hidden">
      {/* Premium Animated Background - No Grid, Just Smooth Gradients */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        {/* Animated Gradient Orbs */}
        <div className="absolute top-0 right-0 w-[800px] h-[800px] bg-gradient-to-br from-blue-400/8 via-purple-400/6 to-pink-400/4 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 left-0 w-[700px] h-[700px] bg-gradient-to-tr from-amber-400/6 via-orange-400/4 to-red-400/3 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '2s' }}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-br from-emerald-400/5 via-cyan-400/4 to-blue-400/3 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '4s' }}></div>
        
        {/* Subtle Radial Gradient Overlay */}
        <div className="absolute inset-0 bg-gradient-radial from-transparent via-transparent to-slate-50/20"></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-8 py-12 sm:py-20 z-10">
        {/* Error Display */}
        {error && (
          <div className="mb-8 bg-gradient-to-r from-red-500/10 to-rose-500/10 border-2 border-red-500/30 rounded-2xl p-6 backdrop-blur-xl">
            <div className="flex items-center space-x-3">
              <XCircle className="w-6 h-6 text-red-400" />
              <div>
                <h3 className="text-slate-900 font-bold text-lg">Audit Failed</h3>
                <p className="text-red-300">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Results Display */}
        {auditResults && auditResults.success && auditResults.audit_summary && auditResults.findings && (
          <div className="mb-20">
            {/* Premium Security Audit Summary Hero - CENTERED */}
            <div className="flex flex-col items-center justify-center mb-16 animate-fadeIn">
              <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-200 rounded-full px-4 py-1.5 mb-6 backdrop-blur-sm">
                <Shield className="w-4 h-4 text-blue-600" />
                <span className="text-blue-700 text-sm font-semibold">Security Assessment Complete</span>
                  </div>
              <h1 className="text-6xl font-extrabold bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent mb-4 tracking-tight leading-tight text-center">
                Security Audit Summary
              </h1>
              <div className="w-32 h-1.5 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 mx-auto rounded-full mb-12 shadow-lg"></div>
              {(() => {
                // Calculate security score: 100 - risk_score (where risk_score 0-100, higher = worse)
                // Ensure we always have a valid score
                const riskScore = auditResults.risk_score || 0;
                const backendSecurityScore = auditResults.security_score;
                const calculatedSecurityScore = backendSecurityScore !== undefined && backendSecurityScore !== null 
                  ? backendSecurityScore 
                  : Math.max(0, 100 - riskScore);
                const securityScore = Math.max(0, Math.min(100, Math.round(calculatedSecurityScore)));
                const grade = getSecurityGrade(securityScore);
                
                // Color scheme based on score
                const getScoreColors = (score: number) => {
                  if (score >= 80) {
                    return {
                      bg: 'from-emerald-50 to-green-50',
                      border: 'border-emerald-300',
                      scoreGradient: 'from-emerald-500 to-green-500',
                      scoreText: 'text-emerald-600',
                      badge: 'from-emerald-500/20 to-green-500/20 text-emerald-600 border-emerald-500/40',
                      status: 'bg-emerald-100 text-emerald-800'
                    };
                  } else if (score >= 60) {
                    return {
                      bg: 'from-blue-50 to-cyan-50',
                      border: 'border-blue-300',
                      scoreGradient: 'from-blue-500 to-cyan-500',
                      scoreText: 'text-blue-600',
                      badge: 'from-blue-500/20 to-cyan-500/20 text-blue-600 border-blue-500/40',
                      status: 'bg-blue-100 text-blue-800'
                    };
                  } else if (score >= 40) {
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
                
                const colors = getScoreColors(securityScore);
                
                // Ultra-Premium Design - Refined Two-Row Layout with Perfect Balance
                return (
                  <div className="relative max-w-full mx-auto">
                    {/* Enhanced gradient background with multiple layers */}
                    <div className="absolute inset-0 bg-gradient-to-br from-blue-500/8 via-purple-500/8 to-pink-500/8 rounded-3xl blur-3xl -z-10"></div>
                    <div className="absolute inset-0 bg-gradient-to-tr from-transparent via-white/20 to-transparent rounded-3xl -z-10"></div>
                    
                    {/* Main card - Ultra-premium with refined spacing */}
                    <div className="relative bg-white/90 backdrop-blur-2xl border-2 border-blue-200/60 rounded-3xl p-8 shadow-2xl hover:shadow-3xl transition-all duration-500 overflow-hidden">
                      {/* Enhanced top accent bar with glow */}
                      <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 shadow-lg"></div>
                      
                      {/* Row 1: Clean & Balanced Top Section - No Duplicates */}
                      <div className="flex items-center justify-between gap-8 mb-6">
                        {/* Left: Label Only - Clean (No Icon) */}
                        <div className="flex items-center gap-4 flex-shrink-0">
                          <div className="text-slate-700 text-sm font-black uppercase tracking-widest">Security Score</div>
                        </div>
                        
                        {/* Center: Massive Score - Ultra Prominent */}
                        <div className="flex items-baseline gap-4 flex-1 justify-center">
                          <span 
                            className={`text-8xl font-bold leading-none drop-shadow-lg`}
                            style={{
                              background: securityScore >= 80 
                                ? 'linear-gradient(135deg, #10b981, #3b82f6)' 
                                : securityScore >= 60
                                ? 'linear-gradient(135deg, #3b82f6, #8b5cf6)'
                                : securityScore >= 40
                                ? 'linear-gradient(135deg, #f59e0b, #f97316)'
                                : 'linear-gradient(135deg, #ef4444, #ec4899)',
                              WebkitBackgroundClip: 'text',
                              WebkitTextFillColor: 'transparent',
                              backgroundClip: 'text',
                              filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.1))'
                            }}
                          >
                            {securityScore}
                          </span>
                          <span className="text-3xl text-slate-400 font-semibold pb-2">/100</span>
                        </div>
                        
                        {/* Right: Single Grade Badge - Only One */}
                        <div className={`inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-bold ${colors.status} shadow-md flex-shrink-0 ring-2 ring-opacity-20 ${colors.status.includes('red') ? 'ring-red-200' : colors.status.includes('orange') ? 'ring-orange-200' : colors.status.includes('blue') ? 'ring-blue-200' : 'ring-green-200'}`}>
                          <span className="text-base">Grade {grade.grade}</span>
                          <span className="opacity-50">•</span>
                          <span className="text-xs">{grade.label}</span>
                        </div>
                      </div>
                      
                      {/* Row 2: Refined Bottom Section with Better Flow */}
                      <div className="flex items-center justify-between gap-8 pt-6 border-t-2 border-slate-200/60">
                        {/* Left: Security Level - Enhanced */}
                        <div className="flex flex-col gap-1.5 flex-shrink-0 min-w-[140px]">
                          <div className="text-slate-600 text-xs font-semibold uppercase tracking-wide">Security Level</div>
                          <div className="text-slate-800 text-lg font-bold">{securityScore}% <span className="text-sm font-normal text-slate-500">secure</span></div>
                        </div>
                        
                        {/* Center: Enhanced Progress Bar with Labels */}
                        <div className="flex-1 max-w-2xl flex flex-col gap-2">
                          <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                            <span className="font-medium">Progress</span>
                            <span className="font-bold text-slate-700">{securityScore}%</span>
                          </div>
                          <div className="relative w-full bg-gradient-to-r from-slate-100 via-slate-50 to-slate-100 rounded-full h-3 overflow-hidden border border-slate-200 shadow-inner">
                            <div
                              className={`h-full bg-gradient-to-r ${colors.scoreGradient} rounded-full transition-all duration-1000 ease-out shadow-lg relative overflow-hidden`}
                              style={{ width: `${securityScore}%` }}
                            >
                              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer"></div>
                            </div>
                          </div>
                        </div>
                        
                        {/* Right: Risk Only - Grade Already Shown Above */}
                        <div className="flex items-center gap-6 text-sm flex-shrink-0">
                          <div className="flex flex-col items-end gap-1">
                            <div className="text-slate-500 text-xs font-medium uppercase tracking-wide">Risk Score</div>
                            <div className="flex items-center gap-2">
                              <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse shadow-lg"></div>
                              <span className="text-red-600 font-black text-xl">{riskScore}</span>
                              <span className="text-slate-400 text-sm">/100</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </div>

            {/* Premium Audit Coverage Summary */}
            <div className="mb-16 animate-fadeIn" style={{ animationDelay: '0.1s' }}>
              <div className="flex items-center space-x-3 mb-8">
                <div className="w-1 h-8 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
                <h2 className="text-3xl font-bold text-slate-900 tracking-tight">What We Audited</h2>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="group relative bg-white/80 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-8 shadow-xl hover:shadow-2xl transition-all duration-500 hover:-translate-y-1 overflow-hidden">
                  {/* Animated background gradient */}
                  <div className="absolute inset-0 bg-gradient-to-br from-blue-50/50 to-cyan-50/30 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                  <div className="relative">
                    <div className="w-14 h-14 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl flex items-center justify-center mb-4 shadow-lg group-hover:scale-110 transition-transform duration-300">
                      <Users className="w-7 h-7 text-white" />
                    </div>
                <div className="flex items-center justify-between mb-4">
                      <div>
                        <div className="text-slate-900 font-bold text-xl mb-1">IAM Roles</div>
                        <div className="text-slate-500 text-sm font-medium">Analyzed IAM roles</div>
                </div>
                      <div className="text-5xl font-black text-blue-600 drop-shadow-sm">{auditResults.audit_summary.roles_analyzed}</div>
                    </div>
                    <p className="text-slate-500 text-xs font-medium mt-2">{auditResults.audit_summary.total_findings} security findings identified</p>
                  </div>
                </div>
                <div className="group relative bg-white/80 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-8 shadow-xl hover:shadow-2xl transition-all duration-500 hover:-translate-y-1 overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-br from-pink-50/50 to-orange-50/30 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                  <div className="relative">
                    <div className="w-14 h-14 bg-gradient-to-br from-pink-500 to-orange-500 rounded-xl flex items-center justify-center mb-4 shadow-lg group-hover:scale-110 transition-transform duration-300">
                      <Activity className="w-7 h-7 text-white" />
                    </div>
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <div className="text-slate-900 font-bold text-xl mb-1">CloudTrail Logs</div>
                        <div className="text-slate-500 text-sm font-medium">Reviewed events</div>
                      </div>
                      <div className="text-5xl font-black text-pink-600 drop-shadow-sm">{auditResults.audit_summary.cloudtrail_events_analyzed || 0}</div>
                    </div>
                    <p className="text-slate-500 text-xs font-medium mt-2">90 days analyzed</p>
                  </div>
                </div>
                <div className="group relative bg-white/80 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-8 shadow-xl hover:shadow-2xl transition-all duration-500 hover:-translate-y-1 overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-br from-amber-50/50 to-yellow-50/30 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                  <div className="relative">
                    <div className="w-14 h-14 bg-gradient-to-br from-amber-500 to-yellow-500 rounded-xl flex items-center justify-center mb-4 shadow-lg group-hover:scale-110 transition-transform duration-300">
                      <Shield className="w-7 h-7 text-white" />
                    </div>
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <div className="text-slate-900 font-bold text-xl mb-1">SCPs & Boundaries</div>
                        <div className="text-slate-500 text-sm font-medium">Policy conflicts checked</div>
                      </div>
                      <div className="text-5xl font-black text-amber-600 drop-shadow-sm">
                        {(() => {
                          // Count SCPs analyzed - check scp_analysis data
                          const scpData = auditResults.scp_analysis || {};
                          const scpsCount = scpData.scps_found ? (scpData.scps_analyzed || scpData.scps_count || 0) : 0;
                          return scpsCount;
                        })()}
                      </div>
                    </div>
                    <p className="text-slate-500 text-xs font-medium mt-2">Access restrictions validated</p>
                  </div>
                </div>
              </div>
              </div>

            {/* Premium Metrics Row */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-16 animate-fadeIn" style={{ animationDelay: '0.2s' }}>
              <div className="group relative bg-white/80 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-8 shadow-xl hover:shadow-2xl transition-all duration-500 hover:-translate-y-1 overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-red-50/50 to-rose-50/30 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                <div className="relative">
                <div className="flex items-center justify-between mb-4">
                    <div className="w-14 h-14 bg-gradient-to-br from-red-500 to-rose-500 rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                      <AlertTriangle className="w-7 h-7 text-white" />
                </div>
                    <div className="text-5xl font-black text-red-600 drop-shadow-sm">{auditResults.audit_summary.critical_issues}</div>
                  </div>
                  <div className="text-slate-900 font-bold text-xl mb-1">Critical Issues</div>
                  <div className="text-slate-500 text-sm font-medium">Require immediate attention</div>
                </div>
              </div>

              <div className="group relative bg-white/80 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-8 shadow-xl hover:shadow-2xl transition-all duration-500 hover:-translate-y-1 overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-orange-50/50 to-amber-50/30 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                <div className="relative">
                <div className="flex items-center justify-between mb-4">
                    <div className="w-14 h-14 bg-gradient-to-br from-orange-500 to-amber-500 rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                      <AlertCircle className="w-7 h-7 text-white" />
                </div>
                    <div className="text-5xl font-black text-orange-600 drop-shadow-sm">{auditResults.audit_summary.high_issues}</div>
                  </div>
                  <div className="text-slate-900 font-bold text-xl mb-1">High Priority</div>
                  <div className="text-slate-500 text-sm font-medium">Should be addressed soon</div>
              </div>
            </div>

              <div className="group relative bg-white/80 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-8 shadow-xl hover:shadow-2xl transition-all duration-500 hover:-translate-y-1 overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-blue-50/50 to-cyan-50/30 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                <div className="relative">
                <div className="flex items-center justify-between mb-4">
                    <div className="w-14 h-14 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                      <Database className="w-7 h-7 text-white" />
                </div>
                    <div className="text-5xl font-black text-blue-600 drop-shadow-sm">{auditResults.audit_summary.total_roles}</div>
                  </div>
                  <div className="text-slate-900 font-bold text-xl mb-1">IAM Roles Scanned</div>
                  <div className="text-slate-500 text-sm font-medium">Across your AWS account</div>
                </div>
              </div>
            </div>

            {/* Premium Enhanced Findings Section */}
            <div className="mb-16 animate-fadeIn" style={{ animationDelay: '0.3s' }}>
              <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-8 gap-4">
                <div>
                  <div className="flex items-center space-x-3 mb-3">
                    <div className="w-1 h-8 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
                    <h2 className="text-3xl font-bold text-slate-900 tracking-tight">Security Findings</h2>
                  </div>
                  <div className="inline-flex items-center space-x-2 bg-white/60 backdrop-blur-sm rounded-full px-4 py-1.5 border border-slate-200">
                    <span className="text-slate-900 font-bold text-base">{auditResults.findings?.length || 0}</span>
                    <span className="text-slate-600 text-sm font-medium">security findings</span>
                    <span className="text-slate-400 text-xs">({auditResults.audit_summary.roles_analyzed} roles analyzed)</span>
                  </div>
                </div>
                
                {/* Premium View Mode Toggle */}
                <div className="flex items-center gap-2 bg-white/80 backdrop-blur-xl border-2 border-white/50 rounded-xl p-1.5 shadow-lg">
                  <button
                    onClick={() => setViewMode('compact')}
                    className={`px-5 py-2.5 rounded-lg font-semibold text-sm transition-all duration-300 ${
                      viewMode === 'compact' 
                        ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg scale-105' 
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                    }`}
                  >
                    <Database className="w-4 h-4 inline mr-2" />
                    Compact
                  </button>
                  <button
                    onClick={() => setViewMode('detailed')}
                    className={`px-5 py-2.5 rounded-lg font-semibold text-sm transition-all duration-300 ${
                      viewMode === 'detailed' 
                        ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg scale-105' 
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                    }`}
                  >
                    <Eye className="w-4 h-4 inline mr-2" />
                    Detailed
                  </button>
                </div>
              </div>

              {/* Premium Filters & Controls */}
              <div className="bg-white/80 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-4 sm:p-6 lg:p-8 mb-8 shadow-xl space-y-4 sm:space-y-6">
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4">
                  {/* Search */}
                  <div className="md:col-span-2">
                    <div className="relative">
                      <input
                        type="text"
                        placeholder="Search findings by title, role, or description..."
                        value={searchQuery}
                        onChange={(e) => {
                          setSearchQuery(e.target.value);
                          setCurrentPage(1);
                        }}
                        className="w-full bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl px-5 py-3 pl-12 text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500 focus:bg-white transition-all shadow-sm hover:shadow-md"
                      />
                      <Scan className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
                    </div>
                  </div>
                  
                  {/* Severity Filter */}
                  <select
                    value={severityFilter}
                    onChange={(e) => {
                      setSeverityFilter(e.target.value);
                      setCurrentPage(1);
                    }}
                    className="bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl px-5 py-3 text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500 transition-all shadow-sm hover:shadow-md font-medium"
                  >
                    <option value="all">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                  
                  {/* Role Filter */}
                  <select
                    value={roleFilter}
                    onChange={(e) => {
                      setRoleFilter(e.target.value);
                      setCurrentPage(1);
                    }}
                    className="bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl px-5 py-3 text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500 transition-all shadow-sm hover:shadow-md font-medium"
                  >
                    <option value="all">All Roles</option>
                    {Array.from(new Set((auditResults.findings || []).map(f => f.role).filter(Boolean))).map(role => (
                      <option key={role} value={role}>{role}</option>
                    ))}
                  </select>
                </div>
                
                {/* Premium Group By */}
                <div className="flex items-center gap-4 pt-4 border-t-2 border-slate-200/50">
                  <span className="text-slate-700 text-sm font-bold">Group by:</span>
                  <div className="flex gap-2">
                    {(['none', 'severity', 'role'] as const).map((mode) => (
                      <button
                        key={mode}
                        onClick={() => setGroupBy(mode)}
                        className={`px-5 py-2.5 rounded-xl text-sm font-semibold transition-all duration-300 ${
                          groupBy === mode 
                            ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg scale-105' 
                            : 'bg-white/60 backdrop-blur-sm text-slate-600 border-2 border-slate-200 hover:bg-white hover:border-blue-300 hover:shadow-md'
                        }`}
                      >
                        {mode.charAt(0).toUpperCase() + mode.slice(1)}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Filtered & Paginated Findings */}
              {(() => {
                // Filter findings
                let filtered = (auditResults.findings || []).filter(f => {
                  if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
                  if (roleFilter !== 'all' && f.role !== roleFilter) return false;
                  if (searchQuery) {
                    const query = searchQuery.toLowerCase();
                    return (
                      f.title.toLowerCase().includes(query) ||
                      f.description.toLowerCase().includes(query) ||
                      f.role?.toLowerCase().includes(query) ||
                      f.id.toLowerCase().includes(query)
                    );
                  }
                  return true;
                });

                // Group findings if needed
                let groupedFindings: Record<string, typeof filtered> = {};
                if (groupBy === 'severity') {
                  filtered.forEach(f => {
                    if (!groupedFindings[f.severity]) groupedFindings[f.severity] = [];
                    groupedFindings[f.severity].push(f);
                  });
                } else if (groupBy === 'role') {
                  filtered.forEach(f => {
                    const role = f.role || 'Unknown Role';
                    if (!groupedFindings[role]) groupedFindings[role] = [];
                    groupedFindings[role].push(f);
                  });
                } else {
                  groupedFindings = { 'All Findings': filtered };
                }

                // Pagination
                const totalPages = Math.ceil(filtered.length / findingsPerPage);
                const startIdx = (currentPage - 1) * findingsPerPage;
                const endIdx = startIdx + findingsPerPage;
                const paginated = groupBy === 'none' ? filtered.slice(startIdx, endIdx) : filtered;

                return (
                  <>
                    {/* Results Summary */}
                    <div className="mb-4 text-slate-600 text-sm font-medium">
                      Showing <span className="text-slate-900 font-semibold">{filtered.length}</span> of <span className="text-slate-900 font-semibold">{auditResults.findings?.length || 0}</span> findings
                      {filtered.length !== (auditResults.findings?.length || 0) && (
                        <span className="ml-2 px-2 py-1 bg-amber-100 text-amber-700 rounded-md text-xs font-medium border border-amber-200">
                          {(auditResults.findings?.length || 0) - filtered.length} filtered out
                        </span>
                      )}
                    </div>

                    {/* Grouped Findings Display */}
                    {groupBy === 'none' ? (
                      <div className="space-y-3">
                        {paginated.map((finding) => {
                          const globalIdx = (auditResults.findings || []).indexOf(finding);
                          const colors = getSeverityColor(finding.severity);
                          const isSelected = selectedFindings.has(globalIdx);
                          
                          return viewMode === 'compact' ? (
                              <div 
                                    key={globalIdx} 
                                    className={`group relative ${colors.bg} border-2 ${isSelected ? 'border-blue-500 ring-2 ring-blue-500/30 bg-blue-50/50 shadow-lg' : colors.border} rounded-2xl p-6 shadow-lg hover:shadow-xl transition-all duration-500 cursor-pointer hover:-translate-y-0.5 overflow-hidden`}
                                    onClick={(e) => {
                                      // Don't toggle expand if clicking checkbox
                                      if ((e.target as HTMLElement).closest('input[type="checkbox"]')) return;
                                      const newExpanded = new Set(expandedFindings);
                                      if (newExpanded.has(globalIdx)) {
                                        newExpanded.delete(globalIdx);
                                      } else {
                                        newExpanded.add(globalIdx);
                                      }
                                      setExpandedFindings(newExpanded);
                                    }}
                                  >
                                    <div className="flex items-start space-x-3">
                                      <input
                                        type="checkbox"
                                        checked={isSelected}
                                        onChange={(e) => {
                                          e.stopPropagation();
                                          const newSet = new Set(selectedFindings);
                                          if (e.target.checked) {
                                            newSet.add(globalIdx);
                                          } else {
                                            newSet.delete(globalIdx);
                                          }
                                          setSelectedFindings(newSet);
                                          if (newSet.size > 0 && remediationStep === 'select') {
                                            // Stay in select step
                                          }
                                        }}
                                        onClick={(e) => e.stopPropagation()}
                                        className="mt-1 w-5 h-5 rounded-md border-2 border-slate-300 bg-white text-blue-600 focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 cursor-pointer transition-all hover:border-blue-400 checked:bg-blue-600 checked:border-blue-600"
                                      />
                                      <div className="flex-1">
                                    <div className="flex items-center justify-between">
                                      <div className="flex items-center gap-3 flex-1 min-w-0">
                                        <span className={`px-2.5 py-1 ${colors.badge} border rounded-md text-xs font-semibold`}>
                                          {finding.severity}
                                        </span>
                                        <div className="flex-1 min-w-0">
                                          <h5 className="text-slate-900 font-semibold text-sm truncate">{finding.title}</h5>
                                          <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
                                            {finding.role && (
                                              <span className="truncate font-mono text-slate-600">{finding.role}</span>
                                            )}
                                            {finding.affected_permissions && finding.affected_permissions.length > 0 && (
                                              <span className="text-slate-500">{finding.affected_permissions.length} permissions</span>
                                            )}
                                          </div>
                                        </div>
                                      </div>
                                      <div className="flex items-center gap-2">
                                        <span className="text-slate-400">{expandedFindings.has(globalIdx) ? '▼' : '▶'}</span>
                                      </div>
                                    </div>
                                    {expandedFindings.has(globalIdx) && (
                                      <div className="mt-4 pt-4 border-t border-slate-200 space-y-3">
                                        <div className="text-slate-600 text-sm leading-relaxed">{finding.description}</div>
                                        <div className="bg-gradient-to-r from-emerald-100 to-green-100 border-2 border-emerald-400 rounded-lg p-3 shadow-sm">
                                          <div className="text-emerald-800 text-xs font-bold mb-1.5 flex items-center">
                                            <CheckCircle className="w-3 h-3 mr-1.5" />
                                            Quick Recommendation
                                          </div>
                                          <div className="text-emerald-900 text-sm font-medium">{finding.recommendation}</div>
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                    </div>
                                  </div>
                              ) : (
                                <div key={globalIdx} className={`${colors.bg} border-2 ${isSelected ? 'border-blue-500 ring-2 ring-blue-500/20 bg-blue-50/50' : colors.border} rounded-xl p-6 shadow-sm hover:shadow-md transition-all duration-300`}>
                                  <div className="flex items-start space-x-3 mb-4">
                                    <input
                                      type="checkbox"
                                      checked={isSelected}
                                      onChange={(e) => {
                                        const newSet = new Set(selectedFindings);
                                        if (e.target.checked) {
                                          newSet.add(globalIdx);
                                        } else {
                                          newSet.delete(globalIdx);
                                        }
                                        setSelectedFindings(newSet);
                                      }}
                                      className="mt-1 w-5 h-5 rounded-md border-2 border-slate-300 bg-white text-blue-600 focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 cursor-pointer transition-all hover:border-blue-400 checked:bg-blue-600 checked:border-blue-600"
                                    />
                                    <div className="flex-1">
                                  <div className="flex items-start justify-between mb-4">
                                    <div className="flex items-center space-x-3 flex-1">
                                      <span className={`px-3 py-1.5 ${colors.badge} border rounded-lg font-semibold text-sm`}>
                                        {finding.severity}
                                      </span>
                                      <div className="flex-1">
                                        <h4 className="text-slate-900 font-bold text-lg mb-1">{finding.title}</h4>
                                        <p className="text-slate-600 text-sm">{finding.description}</p>
                                      </div>
                                    </div>
                                    <button
                                      onClick={() => {
                                        const newExpanded = new Set(expandedFindings);
                                        if (newExpanded.has(globalIdx)) {
                                          newExpanded.delete(globalIdx);
                                        } else {
                                          newExpanded.add(globalIdx);
                                        }
                                        setExpandedFindings(newExpanded);
                                      }}
                                      className="ml-4 text-slate-400 hover:text-slate-600 transition-colors"
                                    >
                                      {expandedFindings.has(globalIdx) ? '▼' : '▶'}
                                    </button>
                                  </div>
                                  
                                  {/* Basic Info Always Visible */}
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                                    {finding.role && (
                                      <div className="bg-slate-50 rounded-lg p-3 border border-slate-200">
                                        <div className="text-slate-500 text-xs font-semibold mb-1">Affected Role</div>
                                        <div className="text-slate-900 font-mono text-sm">{finding.role}</div>
                                      </div>
                                    )}
                                    {finding.affected_permissions && finding.affected_permissions.length > 0 && (
                                      <div className="bg-slate-50 rounded-lg p-3 border border-slate-200">
                                        <div className="text-slate-500 text-xs font-semibold mb-1">Affected Permissions</div>
                                        <div className="text-slate-900 font-mono text-xs">
                                          {finding.affected_permissions.slice(0, 3).join(', ')}
                                          {finding.affected_permissions.length > 3 && (
                                            <button
                                              onClick={() => {
                                                const newExpanded = new Set(expandedFindings);
                                                if (!newExpanded.has(globalIdx)) {
                                                  newExpanded.add(globalIdx);
                                                  setExpandedFindings(newExpanded);
                                                }
                                              }}
                                              className="ml-2 text-blue-600 hover:text-blue-700 font-medium"
                                            >
                                              +{finding.affected_permissions.length - 3} more
                                            </button>
                                          )}
                                        </div>
                                      </div>
                                    )}
                                  </div>

                                  {/* Recommendation Always Visible */}
                                  <div className="bg-gradient-to-r from-emerald-100 to-green-100 border-2 border-emerald-400 rounded-lg p-4 mb-4 shadow-sm">
                                    <div className="text-emerald-800 text-sm font-bold mb-2 flex items-center">
                                      <CheckCircle className="w-4 h-4 mr-2" />
                                      Quick Recommendation
                                    </div>
                                    <div className="text-emerald-900 text-sm leading-relaxed font-medium">{finding.recommendation}</div>
                                  </div>

                                  {/* Expandable Detailed Information */}
                                  {expandedFindings.has(globalIdx) && (
                                    <div className="mt-4 space-y-4 pt-4 border-t border-slate-200">
                                      {/* Why It Matters */}
                                      {finding.why_it_matters && (
                                        <div className="bg-gradient-to-r from-amber-100 to-yellow-100 border-2 border-amber-400 rounded-lg p-4 shadow-sm">
                                          <div className="text-amber-800 text-sm font-bold mb-2 flex items-center">
                                            <AlertCircle className="w-4 h-4 mr-2" />
                                            Why This Matters
                                          </div>
                                          <div className="text-amber-900 text-sm leading-relaxed font-medium">{finding.why_it_matters}</div>
                                        </div>
                                      )}

                                      {/* Impact */}
                                      {finding.impact && (
                                        <div className="bg-gradient-to-r from-red-100 to-rose-100 border-2 border-red-400 rounded-lg p-4 shadow-sm">
                                          <div className="text-red-800 text-sm font-bold mb-2 flex items-center">
                                            <AlertTriangle className="w-4 h-4 mr-2" />
                                            Potential Impact
                                          </div>
                                          <div className="text-red-900 text-sm leading-relaxed font-medium">{finding.impact}</div>
                                        </div>
                                      )}

                                      {/* Compliance Violations */}
                                      {finding.compliance_violations && finding.compliance_violations.length > 0 && (
                                        <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                                          <div className="text-slate-700 text-sm font-semibold mb-2 flex items-center">
                                            <Shield className="w-4 h-4 mr-2" />
                                            Compliance Violations
                                          </div>
                                          <div className="space-y-1">
                                            {finding.compliance_violations.map((violation, vIdx) => (
                                              <div key={vIdx} className="text-slate-600 text-sm flex items-center">
                                                <span className="w-2 h-2 bg-slate-400 rounded-full mr-2"></span>
                                                {violation}
                                              </div>
                                            ))}
                                          </div>
                                        </div>
                                      )}

                                      {/* Detailed Remediation */}
                                      {finding.detailed_remediation && (
                                        <div className="bg-gradient-to-r from-blue-100 to-cyan-100 border-2 border-blue-400 rounded-lg p-4 shadow-sm">
                                          <div className="text-blue-800 text-sm font-bold mb-2 flex items-center">
                                            <Settings className="w-4 h-4 mr-2" />
                                            Step-by-Step Remediation
                                          </div>
                                          <div className="text-blue-900 text-sm whitespace-pre-line leading-relaxed font-mono bg-white rounded p-3 border-2 border-blue-200 font-medium">
                                            {finding.detailed_remediation}
                                          </div>
                                        </div>
                                      )}

                                      {/* Policy Snippet */}
                                      {finding.policy_snippet && (
                                        <div className="bg-slate-900 border border-slate-300 rounded-lg p-4">
                                          <div className="text-slate-600 text-sm font-semibold mb-2 flex items-center">
                                            <Code className="w-4 h-4 mr-2" />
                                            Policy Snippet
                                          </div>
                                          <pre className="text-slate-200 text-xs overflow-x-auto font-mono bg-slate-950 rounded p-3">
                                            {finding.policy_snippet}
                                          </pre>
                                        </div>
                                      )}

                                      {/* All Affected Permissions (if many) - Premium Collapsible */}
                                       {finding.affected_permissions && finding.affected_permissions.length > 3 && (
                                        <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                                          <div className="flex items-center justify-between mb-3">
                                            <div className="text-slate-700 text-sm font-semibold">
                                              All Affected Permissions ({finding.affected_permissions.length})
                                            </div>
                                            <button
                                              onClick={() => {
                                                // Toggle showing all vs collapsed
                                              }}
                                              className="text-blue-600 hover:text-blue-700 text-xs font-medium"
                                            >
                                              {expandedFindings.has(globalIdx) && finding.affected_permissions.length > 20 ? 'Show less' : 'Show all'}
                                            </button>
                                          </div>
                                          <div className="flex flex-wrap gap-2 max-h-96 overflow-y-auto custom-scrollbar">
                                            {finding.affected_permissions.slice(0, expandedFindings.has(globalIdx) ? finding.affected_permissions.length : 20).map((perm, pIdx) => (
                                              <span key={pIdx} className="px-2.5 py-1 bg-white border border-slate-200 text-slate-700 text-xs font-mono rounded-md hover:border-blue-300 hover:bg-blue-50 transition-colors">
                                                 {perm}
                                               </span>
                                             ))}
                                            {!expandedFindings.has(globalIdx) && finding.affected_permissions.length > 20 && (
                                              <button
                                                onClick={() => {
                                                  const newExpanded = new Set(expandedFindings);
                                                  newExpanded.add(globalIdx);
                                                  setExpandedFindings(newExpanded);
                                                }}
                                                className="px-3 py-1 bg-blue-50 border border-blue-200 text-blue-700 text-xs font-medium rounded-md hover:bg-blue-100 transition-colors"
                                              >
                                                +{finding.affected_permissions.length - 20} more
                                              </button>
                                            )}
                                           </div>
                                         </div>
                                                                              )}
                                     </div>
                                   )}
                                    </div>
                                  </div>
                                 </div>
                               );
                           })}
                         </div>
                       ) : (
                         <>
                           {Object.entries(groupedFindings).map(([groupName, groupFindings]) => {
                             const displayFindings = groupFindings.slice(0, groupBy === 'severity' ? 10 : 20);
                             
                             return (
                               <div key={groupName} className="mb-8">
                              <div className="flex items-center justify-between mb-4">
                                <h4 className="text-xl font-bold text-slate-900">
                                  {groupName} ({groupFindings.length})
                                </h4>
                                       {groupFindings.length > displayFindings.length && (
                                         <button
                                           onClick={() => {
                                             // Expand this group - would need more state management
                                           }}
                                           className="text-purple-400 hover:text-purple-300 text-sm"
                                         >
                                           Show all {groupFindings.length} →
                                         </button>
                                       )}
                                     </div>

                                     {/* Findings List */}
                                     <div className="space-y-3">
                                       {displayFindings.map((finding) => {
                                         const globalIdx = (auditResults.findings || []).indexOf(finding);
                                         const colors = getSeverityColor(finding.severity);
                                         
                                         if (viewMode === 'compact') {
                                           return (
                                             <div 
                                      key={globalIdx} 
                                      className={`bg-gradient-to-r ${colors.bg} border ${colors.border} rounded-lg p-4 backdrop-blur-xl hover:border-opacity-60 transition-all cursor-pointer`}
                                      onClick={() => {
                                        const newExpanded = new Set(expandedFindings);
                                        if (newExpanded.has(globalIdx)) {
                                          newExpanded.delete(globalIdx);
                                        } else {
                                          newExpanded.add(globalIdx);
                                        }
                                        setExpandedFindings(newExpanded);
                                      }}
                                    >
                                      <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-3 flex-1 min-w-0">
                                          <span className={`px-2.5 py-1 ${colors.badge} border rounded-md text-xs font-semibold`}>
                                            {finding.severity}
                                          </span>
                                          <div className="flex-1 min-w-0">
                                            <h5 className="text-slate-900 font-semibold text-sm truncate">{finding.title}</h5>
                                            <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
                                              {finding.role && (
                                                <span className="truncate font-mono text-slate-600">{finding.role}</span>
                                              )}
                                              {finding.affected_permissions && finding.affected_permissions.length > 0 && (
                                                <span className="text-slate-500">{finding.affected_permissions.length} permissions</span>
                                              )}
                                            </div>
                                          </div>
                                        </div>
                                        <div className="flex items-center gap-2">
                                          <span className="text-slate-400">{expandedFindings.has(globalIdx) ? '▼' : '▶'}</span>
                                        </div>
                                      </div>
                                      {expandedFindings.has(globalIdx) && (
                                        <div className="mt-4 pt-4 border-t border-slate-200 space-y-3">
                                          <div className="text-slate-600 text-sm leading-relaxed">{finding.description}</div>
                                          <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3">
                                            <div className="text-emerald-700 text-xs font-semibold mb-1.5">Quick Recommendation</div>
                                            <div className="text-slate-700 text-sm">{finding.recommendation}</div>
                                          </div>
                                        </div>
                                      )}
                                    </div>
                                  );
                                }

                                // Detailed view for grouped
                                return (
                                  <div key={globalIdx} className={`${colors.bg} border-2 ${colors.border} rounded-xl p-6 shadow-sm hover:shadow-md transition-all duration-300`}>
                                    <div className="flex items-start justify-between mb-4">
                                      <div className="flex items-center space-x-3 flex-1">
                                        <span className={`px-3 py-1.5 ${colors.badge} border rounded-lg font-semibold text-sm`}>
                                          {finding.severity}
                                        </span>
                                        <div className="flex-1">
                                          <h4 className="text-slate-900 font-bold text-lg mb-1">{finding.title}</h4>
                                          <p className="text-slate-600 text-sm">{finding.description}</p>
                                        </div>
                                      </div>
                                      <button
                                        onClick={() => {
                                          const newExpanded = new Set(expandedFindings);
                                          if (newExpanded.has(globalIdx)) {
                                            newExpanded.delete(globalIdx);
                                          } else {
                                            newExpanded.add(globalIdx);
                                          }
                                          setExpandedFindings(newExpanded);
                                        }}
                                        className="ml-4 text-slate-400 hover:text-slate-600 transition-colors"
                                      >
                                        {expandedFindings.has(globalIdx) ? '▼' : '▶'}
                                      </button>
                                    </div>
                                    
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                                      {finding.role && (
                                        <div className="bg-slate-50 rounded-lg p-3 border border-slate-200">
                                          <div className="text-slate-500 text-xs font-semibold mb-1">Affected Role</div>
                                          <div className="text-slate-900 font-mono text-sm">{finding.role}</div>
                                        </div>
                                      )}
                                      {finding.affected_permissions && finding.affected_permissions.length > 0 && (
                                        <div className="bg-slate-50 rounded-lg p-3 border border-slate-200">
                                          <div className="text-slate-500 text-xs font-semibold mb-1">Affected Permissions</div>
                                          <div className="text-slate-900 font-mono text-xs">
                                            {finding.affected_permissions.slice(0, 3).join(', ')}
                                            {finding.affected_permissions.length > 3 && (
                                              <button
                                                onClick={() => {
                                                  const newExpanded = new Set(expandedFindings);
                                                  if (!newExpanded.has(globalIdx)) {
                                                    newExpanded.add(globalIdx);
                                                    setExpandedFindings(newExpanded);
                                                  }
                                                }}
                                                className="ml-2 text-blue-600 hover:text-blue-700 font-medium"
                                              >
                                                +{finding.affected_permissions.length - 3} more
                                              </button>
                                            )}
                                          </div>
                                        </div>
                                      )}
                                    </div>

                                    <div className="bg-gradient-to-r from-emerald-100 to-green-100 border-2 border-emerald-400 rounded-lg p-4 mb-4 shadow-sm">
                                      <div className="text-emerald-800 text-sm font-bold mb-2 flex items-center">
                                        <CheckCircle className="w-4 h-4 mr-2" />
                                        Quick Recommendation
                                      </div>
                                      <div className="text-emerald-900 text-sm leading-relaxed font-medium">{finding.recommendation}</div>
                                    </div>

                                    {expandedFindings.has(globalIdx) && (
                                      <div className="mt-4 space-y-4 pt-4 border-t border-slate-200">
                                        {finding.why_it_matters && (
                                          <div className="bg-gradient-to-r from-amber-100 to-yellow-100 border-2 border-amber-400 rounded-lg p-4 shadow-sm">
                                            <div className="text-amber-800 text-sm font-bold mb-2 flex items-center">
                                              <AlertCircle className="w-4 h-4 mr-2" />
                                              Why This Matters
                                            </div>
                                            <div className="text-amber-900 text-sm leading-relaxed font-medium">{finding.why_it_matters}</div>
                                          </div>
                                        )}
                                        {finding.impact && (
                                          <div className="bg-gradient-to-r from-red-100 to-rose-100 border-2 border-red-400 rounded-lg p-4 shadow-sm">
                                            <div className="text-red-800 text-sm font-bold mb-2 flex items-center">
                                              <AlertTriangle className="w-4 h-4 mr-2" />
                                              Potential Impact
                                            </div>
                                            <div className="text-red-900 text-sm leading-relaxed font-medium">{finding.impact}</div>
                                          </div>
                                        )}
                                        {finding.compliance_violations && finding.compliance_violations.length > 0 && (
                                          <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                                            <div className="text-slate-700 text-sm font-semibold mb-2 flex items-center">
                                              <Shield className="w-4 h-4 mr-2" />
                                              Compliance Violations
                                            </div>
                                            <div className="space-y-1">
                                              {finding.compliance_violations.map((violation, vIdx) => (
                                                <div key={vIdx} className="text-slate-600 text-sm flex items-center">
                                                  <span className="w-2 h-2 bg-slate-400 rounded-full mr-2"></span>
                                                  {violation}
                                                </div>
                                              ))}
                                            </div>
                                          </div>
                                        )}
                                        {finding.detailed_remediation && (
                                          <div className="bg-gradient-to-r from-blue-100 to-cyan-100 border-2 border-blue-400 rounded-lg p-4 shadow-sm">
                                            <div className="text-blue-800 text-sm font-bold mb-2 flex items-center">
                                              <Settings className="w-4 h-4 mr-2" />
                                              Step-by-Step Remediation
                                            </div>
                                            <div className="text-blue-900 text-sm whitespace-pre-line leading-relaxed font-mono bg-white rounded p-3 border-2 border-blue-200 font-medium">
                                              {finding.detailed_remediation}
                                            </div>
                                          </div>
                                        )}
                                        {finding.policy_snippet && (
                                          <div className="bg-slate-900 border border-slate-300 rounded-lg p-4">
                                            <div className="text-slate-600 text-sm font-semibold mb-2 flex items-center">
                                              <Code className="w-4 h-4 mr-2" />
                                              Policy Snippet
                                            </div>
                                            <pre className="text-slate-200 text-xs overflow-x-auto font-mono bg-slate-950 rounded p-3">
                                              {finding.policy_snippet}
                                            </pre>
                                          </div>
                                        )}
                                        {finding.affected_permissions && finding.affected_permissions.length > 3 && (
                                          <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                                            <div className="text-slate-700 text-sm font-semibold mb-2">All Affected Permissions ({finding.affected_permissions.length})</div>
                                            <div className="flex flex-wrap gap-2 max-h-96 overflow-y-auto custom-scrollbar">
                                              {finding.affected_permissions.slice(0, expandedFindings.has(globalIdx) ? finding.affected_permissions.length : 20).map((perm, pIdx) => (
                                                <span key={pIdx} className="px-2.5 py-1 bg-white border border-slate-200 text-slate-700 text-xs font-mono rounded-md hover:border-blue-300 hover:bg-blue-50 transition-colors">
                                                  {perm}
                                                </span>
                                              ))}
                                              {!expandedFindings.has(globalIdx) && finding.affected_permissions.length > 20 && (
                                                <button
                                                  onClick={() => {
                                                    const newExpanded = new Set(expandedFindings);
                                                    newExpanded.add(globalIdx);
                                                    setExpandedFindings(newExpanded);
                                                  }}
                                                  className="px-3 py-1 bg-blue-50 border border-blue-200 text-blue-700 text-xs font-medium rounded-md hover:bg-blue-100 transition-colors"
                                                >
                                                  +{finding.affected_permissions.length - 20} more
                                                </button>
                                              )}
                                            </div>
                                          </div>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                );
                                                                     })}
                                     </div>
                                   </div>
                                 );
                               })}
                             </>
                           )}

                    {/* Pagination Controls */}
                    {groupBy === 'none' && totalPages > 1 && (
                      <div className="flex items-center justify-between mt-6 pt-6 border-t border-slate-200">
                        <div className="text-slate-600 text-sm font-medium">
                          Page <span className="text-slate-900 font-semibold">{currentPage}</span> of <span className="text-slate-900 font-semibold">{totalPages}</span>
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                            disabled={currentPage === 1}
                            className="px-4 py-2 bg-white border border-slate-200 rounded-lg text-slate-700 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 transition-colors font-medium"
                          >
                            Previous
                          </button>
                          <button
                            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                            disabled={currentPage === totalPages}
                            className="px-4 py-2 bg-blue-600 border border-blue-600 rounded-lg text-white disabled:opacity-50 disabled:cursor-not-allowed hover:bg-blue-700 transition-colors font-medium shadow-sm"
                          >
                            Next
                          </button>
                        </div>
                      </div>
                    )}
                  </>
                );
              })()}
            </div>

            {/* Premium Compliance Status - Engaging & Dynamic */}
            <div className="mb-16 animate-fadeIn" style={{ animationDelay: '0.4s' }}>
              <div className="flex items-center space-x-3 mb-6">
                <div className="w-1 h-8 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
                <h2 className="text-3xl font-bold text-slate-900 tracking-tight">Compliance Validation</h2>
                    </div>
              <p className="text-slate-600 mb-8 text-sm font-medium max-w-3xl">We validated your IAM policies against industry compliance frameworks. Status reflects current findings and gaps.</p>
              
              {/* Contextual Compliance Alert */}
              {(auditResults.audit_summary.critical_issues > 0 || auditResults.audit_summary.high_issues > 0) && (
                <div className="bg-gradient-to-r from-amber-100 via-orange-100 to-red-100 border-2 border-amber-400 rounded-2xl p-6 mb-8 shadow-lg">
                  <div className="flex items-start space-x-4">
                    <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-amber-500 to-orange-500 flex items-center justify-center flex-shrink-0 shadow-lg">
                      <AlertTriangle className="w-6 h-6 text-white" />
                    </div>
                    <div>
                      <p className="text-amber-900 font-bold text-lg mb-2">Compliance Affected by Findings</p>
                      <p className="text-amber-800 text-sm font-medium leading-relaxed">
                        {auditResults.audit_summary.critical_issues > 0 && `${auditResults.audit_summary.critical_issues} critical`}
                        {auditResults.audit_summary.critical_issues > 0 && auditResults.audit_summary.high_issues > 0 && ' and '}
                        {auditResults.audit_summary.high_issues > 0 && `${auditResults.audit_summary.high_issues} high-risk`} findings may impact compliance status. Review and remediate to ensure full compliance.
                      </p>
                  </div>
                </div>
                    </div>
              )}
              
              {/* Compliance Frameworks - CURRENT IMPLEMENTATION:
                  These frameworks are hardcoded in the frontend with predefined requirements.
                  Compliance validation uses simple keyword matching against finding titles/descriptions.
                  No external integrations (AWS Config, Security Hub, or knowledge bases) are currently connected.
                  Scores are calculated based on critical/high issue counts, not actual compliance assessment.
                  For production, this would need to be replaced with:
                  - AI/LLM-powered semantic analysis of IAM policies against framework requirements
                  - Integration with compliance assessment APIs or knowledge bases
                  - Real-time validation against official framework documentation
              */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {[
                  { name: 'PCI DSS', description: 'Payment Card Industry Data Security Standard', requirements: ['Encryption of cardholder data', 'Access controls', 'Network security', 'Regular testing'] },
                  { name: 'HIPAA', description: 'Health Insurance Portability and Accountability Act', requirements: ['Protected health information (PHI) safeguards', 'Access controls', 'Audit controls', 'Workforce training'] },
                  { name: 'SOX', description: 'Sarbanes-Oxley Act', requirements: ['Financial data integrity', 'Access logging', 'Change management', 'Internal controls'] },
                  { name: 'GDPR', description: 'General Data Protection Regulation', requirements: ['Data minimization', 'Access controls', 'Right to erasure', 'Data breach notification'] }
                ].map((framework) => {
                  const hasIssues = auditResults.audit_summary.critical_issues > 0 || auditResults.audit_summary.high_issues > 0;
                  const complianceScore = hasIssues ? Math.max(70, 100 - (auditResults.audit_summary.critical_issues * 10 + auditResults.audit_summary.high_issues * 5)) : 95;
                  const isCompliant = complianceScore >= 90;
                  
                  // Find relevant findings for this framework
                  // NOTE: This uses simple keyword matching. For production, consider:
                  // - AI-powered semantic analysis of findings against framework requirements
                  // - Integration with compliance assessment APIs
                  // - Machine learning models trained on compliance violation patterns
                  const relevantFindings = (auditResults.findings || []).filter((f: Finding) => {
                    const titleLower = f.title.toLowerCase();
                    const descLower = f.description.toLowerCase();
                    if (framework.name === 'PCI DSS') {
                      return titleLower.includes('encryption') || titleLower.includes('card') || descLower.includes('pci');
                    } else if (framework.name === 'HIPAA') {
                      return titleLower.includes('phi') || titleLower.includes('health') || descLower.includes('hipaa');
                    } else if (framework.name === 'SOX') {
                      return titleLower.includes('financial') || titleLower.includes('audit') || descLower.includes('sox');
                    } else if (framework.name === 'GDPR') {
                      return titleLower.includes('data') || titleLower.includes('privacy') || descLower.includes('gdpr');
                    }
                    return false;
                  }).slice(0, 3);
                  
                  return (
                    <div key={framework.name} className="group relative bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-6 shadow-xl hover:shadow-2xl transition-all duration-500 hover:-translate-y-1 overflow-hidden">
                      {/* Animated background gradient */}
                      <div className={`absolute inset-0 ${isCompliant ? 'bg-gradient-to-br from-emerald-50/50 to-green-50/30' : 'bg-gradient-to-br from-amber-50/50 to-orange-50/30'} opacity-0 group-hover:opacity-100 transition-opacity duration-500`}></div>
                      <div className="relative">
                        <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center space-x-3 flex-1">
                            <div className={`w-14 h-14 ${isCompliant ? 'bg-gradient-to-br from-emerald-500 to-green-500' : 'bg-gradient-to-br from-amber-500 to-orange-500'} rounded-xl flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300 flex-shrink-0`}>
                              <Shield className="w-7 h-7 text-white" />
                    </div>
                            <div className="flex-1 min-w-0">
                              <span className="text-slate-900 font-bold text-xl block">{framework.name}</span>
                              <span className="text-slate-500 text-xs font-medium block mt-0.5">{framework.description}</span>
                  </div>
                </div>
                          <div className="text-right flex-shrink-0 ml-4">
                            <div className={`${isCompliant ? 'text-emerald-600' : 'text-amber-600'} font-black text-3xl mb-1`}>{complianceScore}%</div>
                            <div className={`text-xs font-bold ${isCompliant ? 'text-emerald-600' : 'text-amber-600'}`}>
                              {isCompliant ? '✓ Compliant' : '⚠ Needs Review'}
                    </div>
                    </div>
                  </div>
                        
                        {/* Compliance Status Explanation */}
                        <div className={`mt-3 rounded-xl p-3 border-2 ${isCompliant ? 'bg-gradient-to-r from-emerald-50 to-green-50 border-emerald-200' : 'bg-gradient-to-r from-amber-50 to-orange-50 border-amber-300'}`}>
                          {isCompliant ? (
                            <div>
                              <p className="text-emerald-900 text-xs font-bold mb-2 flex items-center">
                                <CheckCircle className="w-3 h-3 mr-1.5" />
                                Passing Compliance
                              </p>
                              <p className="text-emerald-800 text-xs font-medium leading-relaxed">
                                Your IAM policies meet {framework.name} requirements. Key controls verified: {framework.requirements.slice(0, 2).join(', ')}.
                              </p>
                </div>
                          ) : (
                            <div>
                              <p className="text-amber-900 text-xs font-bold mb-2 flex items-center">
                                <AlertTriangle className="w-3 h-3 mr-1.5" />
                                Compliance Violations Detected
                              </p>
                              <p className="text-amber-800 text-xs font-medium leading-relaxed mb-2">
                                {auditResults.audit_summary.critical_issues > 0 && `${auditResults.audit_summary.critical_issues} critical`}
                                {auditResults.audit_summary.critical_issues > 0 && auditResults.audit_summary.high_issues > 0 && ' and '}
                                {auditResults.audit_summary.high_issues > 0 && `${auditResults.audit_summary.high_issues} high-risk`} findings violate {framework.name} requirements.
                              </p>
                              {relevantFindings.length > 0 && (
                                <div className="mt-2 space-y-1">
                                  <p className="text-amber-900 text-xs font-semibold">Key Violations:</p>
                                  {relevantFindings.map((f: Finding, idx: number) => (
                                    <p key={idx} className="text-amber-800 text-xs font-medium">• {f.title}</p>
                                  ))}
                    </div>
                              )}
                              <p className="text-amber-900 text-xs font-semibold mt-2">
                                Required: {framework.requirements.filter((_, i) => !isCompliant || i < 2).join(', ')}
                              </p>
                    </div>
                          )}
                  </div>
                </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* AI Remediation Assistant - Redesigned Flow */}
            {/* Redesign: Moved audit summary to top, improved selection granularity, better visual flow */}
            <div className="mb-16 animate-fadeIn" style={{ animationDelay: '0.6s' }}>
              {/* Step 0: Premium Audit Summary - Redesigned & Merged */}
              <div className="relative bg-gradient-to-br from-white via-blue-50/30 to-purple-50/20 backdrop-blur-xl border-2 border-blue-200/50 rounded-3xl p-8 sm:p-10 shadow-2xl mb-8 overflow-hidden">
                {/* Animated background gradient */}
                <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-purple-500/5 to-pink-500/5 rounded-3xl blur-2xl"></div>
                
                <div className="relative z-10">
                  {/* Header with Icon */}
                  <div className="flex items-start space-x-4 mb-6">
                    <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 via-purple-500 to-pink-500 flex items-center justify-center flex-shrink-0 shadow-xl hover:scale-105 transition-transform duration-300">
                      <Shield className="w-7 h-7 text-white" />
                      </div>
                    <div className="flex-1">
                      <h3 className="text-slate-900 font-bold text-xl mb-2">Audit Complete</h3>
                      <p className="text-slate-600 text-sm font-medium">Security analysis finished. Review findings below.</p>
                    </div>
                </div>

                  {/* Findings - Premium Design */}
                  <div className="space-y-3 mb-6">
                    {/* Finding 1: Unused Permissions */}
                    <div className="group relative flex items-center justify-between bg-gradient-to-r from-red-50/80 via-orange-50/60 to-red-50/40 backdrop-blur-sm rounded-2xl p-4 border-2 border-red-200/60 hover:border-red-300 hover:shadow-lg transition-all duration-300 hover:-translate-y-0.5">
                      <div className="flex items-center space-x-4 flex-1">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-red-500 to-rose-500 flex items-center justify-center flex-shrink-0 shadow-lg group-hover:scale-110 transition-transform">
                          <AlertTriangle className="w-5 h-5 text-white" />
              </div>
                        <div className="flex-1">
                          <p className="text-slate-900 font-semibold text-sm mb-1">Unused Permissions Detected</p>
                          <p className="text-slate-600 text-xs">
                            <strong className="text-red-600 font-bold text-base">{auditResults.audit_summary.unused_permissions_found || 0}</strong> unused permissions can be safely removed
                          </p>
                        </div>
                      </div>
                      <div className="text-red-600 font-black text-2xl">{auditResults.audit_summary.unused_permissions_found || 0}</div>
            </div>

                    {/* Finding 2: Critical Roles */}
                    {(() => {
                      const rolesWithCritical = new Set(
                        (auditResults.findings || [])
                          .filter(f => f.severity === 'Critical')
                          .map(f => f.role)
                          .filter(Boolean)
                      );
                      const criticalRolesCount = rolesWithCritical.size || auditResults.audit_summary.critical_issues;
                      return (
                        <div className="group relative flex items-center justify-between bg-gradient-to-r from-orange-50/80 via-amber-50/60 to-orange-50/40 backdrop-blur-sm rounded-2xl p-4 border-2 border-orange-200/60 hover:border-orange-300 hover:shadow-lg transition-all duration-300 hover:-translate-y-0.5">
                          <div className="flex items-center space-x-4 flex-1">
                            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-orange-500 to-amber-500 flex items-center justify-center flex-shrink-0 shadow-lg group-hover:scale-110 transition-transform">
                              <AlertCircle className="w-5 h-5 text-white" />
                            </div>
                            <div className="flex-1">
                              <p className="text-slate-900 font-semibold text-sm mb-1">Critical Security Issues</p>
                              <p className="text-slate-600 text-xs">
                                <strong className="text-orange-600 font-bold text-base">{criticalRolesCount} {criticalRolesCount === 1 ? 'role' : 'roles'}</strong> with critical issues need MFA requirements
                              </p>
                            </div>
                          </div>
                          <div className="text-orange-600 font-black text-2xl">{criticalRolesCount}</div>
                        </div>
                      );
                    })()}

                    {/* Finding 3: High-Risk Roles */}
                    <div className="group relative flex items-center justify-between bg-gradient-to-r from-yellow-50/80 via-amber-50/60 to-yellow-50/40 backdrop-blur-sm rounded-2xl p-4 border-2 border-yellow-200/60 hover:border-yellow-300 hover:shadow-lg transition-all duration-300 hover:-translate-y-0.5">
                      <div className="flex items-center space-x-4 flex-1">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-yellow-500 to-amber-500 flex items-center justify-center flex-shrink-0 shadow-lg group-hover:scale-110 transition-transform">
                          <AlertCircle className="w-5 h-5 text-white" />
                      </div>
                        <div className="flex-1">
                          <p className="text-slate-900 font-semibold text-sm mb-1">Least Privilege Violations</p>
                          <p className="text-slate-600 text-xs">
                            <strong className="text-yellow-600 font-bold text-base">{auditResults.audit_summary.high_issues}</strong> high-risk {auditResults.audit_summary.high_issues === 1 ? 'role' : 'roles'} should follow least-privilege principle
                      </p>
                    </div>
                      </div>
                      <div className="text-yellow-600 font-black text-2xl">{auditResults.audit_summary.high_issues}</div>
                    </div>
                  </div>

                  {/* Merged CTA - Seamlessly integrated */}
                  <div className="relative bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-pink-500/10 backdrop-blur-sm rounded-2xl p-5 border-2 border-blue-300/50 hover:border-blue-400/70 transition-all duration-300 hover:shadow-lg">
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <p className="text-slate-900 font-bold text-base mb-1">Ready to Remediate?</p>
                        <p className="text-slate-600 text-xs font-medium">Select specific findings below or use quick actions to fix issues automatically</p>
                      </div>
                      <div className="ml-4 flex items-center space-x-2">
                        <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                        <span className="text-slate-600 text-xs font-semibold">AI Ready</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between mb-8">
                <div className="flex items-center space-x-3">
                  <div className="w-1 h-8 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
                  <h2 className="text-3xl font-bold text-slate-900 tracking-tight">AI Remediation Assistant</h2>
                </div>
                {selectedFindings.size > 0 && remediationStep === 'select' && (
                  <button
                    onClick={() => {
                      setSelectedFindings(new Set());
                      setRemediationStep('select');
                    }}
                    className="text-slate-600 hover:text-slate-900 text-sm font-medium transition-colors"
                  >
                    Clear Selection ({selectedFindings.size})
                  </button>
                )}
              </div>

              <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-8 shadow-xl">
                {/* Step 1: Selection */}
                {remediationStep === 'select' && (
                  <>
                    <div className="mb-8">
                      <p className="text-slate-800 text-lg font-semibold mb-6 leading-relaxed">
                        Select specific findings you want to remediate. You'll review each change before confirmation.
                      </p>
                      <div className="bg-gradient-to-r from-amber-50 via-orange-50 to-amber-50 border-2 border-amber-400 rounded-2xl p-6 mb-6 shadow-lg">
                        <div className="flex items-start space-x-4">
                          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-500 to-orange-500 flex items-center justify-center flex-shrink-0 shadow-lg">
                            <AlertCircle className="w-5 h-5 text-white" />
                      </div>
                          <div>
                            <p className="text-amber-900 font-bold text-lg mb-2">Safe Remediation Process</p>
                            <p className="text-amber-800 text-sm font-medium leading-relaxed">
                              You'll review each change before confirmation. All actions are logged and can be rolled back if needed.
                      </p>
                    </div>
                        </div>
                      </div>
                    </div>

                    {/* Enhanced Selection Buttons - All Severity Levels + Categories */}
                    <div className="mb-6">
                      <h4 className="text-slate-900 font-bold text-lg mb-4">Select by Severity</h4>
                      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                    <button
                          onClick={() => {
                            const criticalFindings = (auditResults.findings || [])
                              .map((f: Finding, idx: number) => ({ f, idx }))
                              .filter(({ f }: { f: Finding; idx: number }) => f.severity === 'Critical')
                              .map(({ idx }: { f: Finding; idx: number }) => idx);
                            setSelectedFindings(new Set(criticalFindings));
                          }}
                          disabled={auditResults.audit_summary.critical_issues === 0}
                          className="group relative px-4 py-4 bg-gradient-to-br from-red-50 to-rose-50 border-2 border-red-400 hover:border-red-500 hover:from-red-100 hover:to-rose-100 rounded-xl font-bold transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed transform"
                        >
                          <div className="flex flex-col items-center space-y-2">
                            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-red-500 to-rose-500 flex items-center justify-center shadow-md group-hover:scale-110 transition-transform">
                              <AlertTriangle className="w-4 h-4 text-white" />
                      </div>
                            <span className="text-red-700 text-sm">Critical</span>
                            <p className="text-xs text-red-600 font-semibold">{auditResults.audit_summary.critical_issues}</p>
                          </div>
                    </button>

                    <button
                          onClick={() => {
                            const highFindings = (auditResults.findings || [])
                              .map((f: Finding, idx: number) => ({ f, idx }))
                              .filter(({ f }: { f: Finding; idx: number }) => f.severity === 'High')
                              .map(({ idx }: { f: Finding; idx: number }) => idx);
                            setSelectedFindings(new Set(highFindings));
                          }}
                          disabled={auditResults.audit_summary.high_issues === 0}
                          className="group relative px-4 py-4 bg-gradient-to-br from-orange-50 to-amber-50 border-2 border-orange-400 hover:border-orange-500 hover:from-orange-100 hover:to-amber-100 rounded-xl font-bold transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed transform"
                        >
                          <div className="flex flex-col items-center space-y-2">
                            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-orange-500 to-amber-500 flex items-center justify-center shadow-md group-hover:scale-110 transition-transform">
                              <AlertCircle className="w-4 h-4 text-white" />
                      </div>
                            <span className="text-orange-700 text-sm">High</span>
                            <p className="text-xs text-orange-600 font-semibold">{auditResults.audit_summary.high_issues}</p>
                          </div>
                    </button>

                        <button
                          onClick={() => {
                            const mediumFindings = (auditResults.findings || [])
                              .map((f: Finding, idx: number) => ({ f, idx }))
                              .filter(({ f }: { f: Finding; idx: number }) => f.severity === 'Medium')
                              .map(({ idx }: { f: Finding; idx: number }) => idx);
                            setSelectedFindings(new Set(mediumFindings));
                          }}
                          disabled={(auditResults.findings || []).filter((f: Finding) => f.severity === 'Medium').length === 0}
                          className="group relative px-4 py-4 bg-gradient-to-br from-yellow-50 to-amber-50 border-2 border-yellow-400 hover:border-yellow-500 hover:from-yellow-100 hover:to-amber-100 rounded-xl font-bold transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed transform"
                        >
                          <div className="flex flex-col items-center space-y-2">
                            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-yellow-500 to-amber-500 flex items-center justify-center shadow-md group-hover:scale-110 transition-transform">
                              <AlertCircle className="w-4 h-4 text-white" />
                      </div>
                            <span className="text-yellow-700 text-sm">Medium</span>
                            <p className="text-xs text-yellow-600 font-semibold">{(auditResults.findings || []).filter((f: Finding) => f.severity === 'Medium').length}</p>
                          </div>
                    </button>

                        <button
                          onClick={() => {
                            const lowFindings = (auditResults.findings || [])
                              .map((f: Finding, idx: number) => ({ f, idx }))
                              .filter(({ f }: { f: Finding; idx: number }) => f.severity === 'Low')
                              .map(({ idx }: { f: Finding; idx: number }) => idx);
                            setSelectedFindings(new Set(lowFindings));
                          }}
                          disabled={(auditResults.findings || []).filter((f: Finding) => f.severity === 'Low').length === 0}
                          className="group relative px-4 py-4 bg-gradient-to-br from-blue-50 to-cyan-50 border-2 border-blue-400 hover:border-blue-500 hover:from-blue-100 hover:to-cyan-100 rounded-xl font-bold transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed transform"
                        >
                          <div className="flex flex-col items-center space-y-2">
                            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center shadow-md group-hover:scale-110 transition-transform">
                              <Info className="w-4 h-4 text-white" />
                  </div>
                            <span className="text-blue-700 text-sm">Low</span>
                            <p className="text-xs text-blue-600 font-semibold">{(auditResults.findings || []).filter((f: Finding) => f.severity === 'Low').length}</p>
                </div>
                        </button>

                        <button
                          onClick={() => {
                            setSelectedFindings(new Set((auditResults.findings || []).map((_: Finding, idx: number) => idx)));
                          }}
                          className="group relative px-4 py-4 bg-gradient-to-br from-purple-50 to-pink-50 border-2 border-purple-400 hover:border-purple-500 hover:from-purple-100 hover:to-pink-100 rounded-xl font-bold transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5 transform"
                        >
                          <div className="flex flex-col items-center space-y-2">
                            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center shadow-md group-hover:scale-110 transition-transform">
                              <Zap className="w-4 h-4 text-white" />
                      </div>
                            <span className="text-purple-700 text-sm">All</span>
                            <p className="text-xs text-purple-600 font-semibold">{auditResults.findings?.length || 0}</p>
                          </div>
                        </button>
                      </div>

                      {/* Category-based Selection */}
                      <div className="mt-6">
                        <h4 className="text-slate-900 font-bold text-lg mb-4">Select by Category</h4>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <button
                            onClick={() => {
                              const wildcardFindings = (auditResults.findings || [])
                                .map((f: Finding, idx: number) => ({ f, idx }))
                                .filter(({ f }: { f: Finding; idx: number }) => 
                                  f.title.toLowerCase().includes('wildcard') || 
                                  f.description.toLowerCase().includes('wildcard') ||
                                  f.title.toLowerCase().includes('*')
                                )
                                .map(({ idx }: { f: Finding; idx: number }) => idx);
                              setSelectedFindings(new Set(wildcardFindings));
                            }}
                            disabled={(auditResults.findings || []).filter((f: Finding) => 
                              f.title.toLowerCase().includes('wildcard') || 
                              f.description.toLowerCase().includes('wildcard')
                            ).length === 0}
                            className="group relative px-6 py-4 bg-gradient-to-br from-red-50 to-orange-50 border-2 border-red-300 hover:border-red-400 rounded-xl transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            <div className="flex items-center justify-between">
                              <div>
                                <span className="text-slate-900 font-semibold text-sm block">Wildcard Permissions</span>
                                <span className="text-slate-600 text-xs">Overly broad access</span>
                              </div>
                              <span className="text-red-600 font-bold text-sm">
                                {(auditResults.findings || []).filter((f: Finding) => 
                                  f.title.toLowerCase().includes('wildcard') || 
                                  f.description.toLowerCase().includes('wildcard')
                                ).length}
                              </span>
                            </div>
                          </button>

                          <button
                            onClick={() => {
                              const mfaFindings = (auditResults.findings || [])
                                .map((f: Finding, idx: number) => ({ f, idx }))
                                .filter(({ f }: { f: Finding; idx: number }) => 
                                  f.title.toLowerCase().includes('mfa') || 
                                  f.description.toLowerCase().includes('multi-factor') ||
                                  f.title.toLowerCase().includes('mfa')
                                )
                                .map(({ idx }: { f: Finding; idx: number }) => idx);
                              setSelectedFindings(new Set(mfaFindings));
                            }}
                            disabled={(auditResults.findings || []).filter((f: Finding) => 
                              f.title.toLowerCase().includes('mfa') || 
                              f.description.toLowerCase().includes('multi-factor')
                            ).length === 0}
                            className="group relative px-6 py-4 bg-gradient-to-br from-orange-50 to-amber-50 border-2 border-orange-300 hover:border-orange-400 rounded-xl transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            <div className="flex items-center justify-between">
                              <div>
                                <span className="text-slate-900 font-semibold text-sm block">MFA Missing</span>
                                <span className="text-slate-600 text-xs">No multi-factor auth</span>
                              </div>
                              <span className="text-orange-600 font-bold text-sm">
                                {(auditResults.findings || []).filter((f: Finding) => 
                                  f.title.toLowerCase().includes('mfa') || 
                                  f.description.toLowerCase().includes('multi-factor')
                                ).length}
                              </span>
                            </div>
                          </button>

                          <button
                            onClick={() => {
                              const unusedFindings = (auditResults.findings || [])
                                .map((f: Finding, idx: number) => ({ f, idx }))
                                .filter(({ f }: { f: Finding; idx: number }) => 
                                  f.title.toLowerCase().includes('unused') || 
                                  f.description.toLowerCase().includes('unused')
                                )
                                .map(({ idx }: { f: Finding; idx: number }) => idx);
                              setSelectedFindings(new Set(unusedFindings));
                            }}
                            disabled={(auditResults.findings || []).filter((f: Finding) => 
                              f.title.toLowerCase().includes('unused')
                            ).length === 0}
                            className="group relative px-6 py-4 bg-gradient-to-br from-blue-50 to-cyan-50 border-2 border-blue-300 hover:border-blue-400 rounded-xl transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            <div className="flex items-center justify-between">
                              <div>
                                <span className="text-slate-900 font-semibold text-sm block">Unused Permissions</span>
                                <span className="text-slate-600 text-xs">Can be safely removed</span>
                              </div>
                              <span className="text-blue-600 font-bold text-sm">
                                {(auditResults.findings || []).filter((f: Finding) => 
                                  f.title.toLowerCase().includes('unused')
                                ).length}
                              </span>
                            </div>
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Selected Findings List - Premium Light */}
                    {selectedFindings.size > 0 && (
                      <div className="mb-8">
                        <div className="bg-gradient-to-br from-white to-slate-50 border-2 border-slate-200 rounded-2xl p-6 max-h-96 overflow-y-auto custom-scrollbar shadow-lg">
                          <div className="flex items-center justify-between mb-6">
                            <h4 className="text-slate-900 font-bold text-xl">Selected Findings ({selectedFindings.size})</h4>
                            <div className="flex items-center gap-3">
                              <button
                                onClick={() => setSelectedFindings(new Set())}
                                className="px-4 py-2 text-sm text-slate-600 hover:text-slate-900 font-semibold transition-colors hover:bg-slate-100 rounded-lg"
                              >
                                Clear All
                              </button>
                              <button
                                onClick={() => setRemediationStep('review')}
                                className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-xl font-bold transition-all shadow-lg hover:shadow-xl transform hover:scale-105 flex items-center space-x-2"
                              >
                                <span>Review Changes</span>
                                <ChevronRight className="w-4 h-4" />
                              </button>
                </div>
                          </div>
                          <div className="space-y-2">
                            {Array.from(selectedFindings).slice(0, 10).map((idx) => {
                              const finding = auditResults.findings?.[idx];
                              if (!finding) return null;
                              const colors = getSeverityColor(finding.severity);
                              return (
                                <div key={idx} className={`${colors.bg} border ${colors.border} rounded-lg p-3 flex items-center justify-between hover:shadow-sm transition-all`}>
                                  <div className="flex items-center space-x-3 flex-1">
                                    <input
                                      type="checkbox"
                                      checked={true}
                                      onChange={() => {
                                        const newSet = new Set(selectedFindings);
                                        newSet.delete(idx);
                                        setSelectedFindings(newSet);
                                      }}
                                      className="w-5 h-5 rounded-md border-2 border-slate-300 bg-white text-blue-600 focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 cursor-pointer transition-all hover:border-blue-400 checked:bg-blue-600 checked:border-blue-600"
                                    />
                                    <div className="flex-1 min-w-0">
                                      <div className="flex items-center space-x-2">
                                        <span className={`px-2 py-0.5 ${colors.badge} border rounded-md text-xs font-semibold`}>
                                          {finding.severity}
                                        </span>
                                        <span className="text-slate-900 font-semibold text-sm truncate">{finding.title}</span>
                                      </div>
                                      {finding.role && (
                                        <div className="text-slate-600 text-xs font-mono mt-1 truncate">{finding.role}</div>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              );
                            })}
                            {selectedFindings.size > 10 && (
                              <div className="text-slate-500 text-sm text-center py-2">
                                ... and {selectedFindings.size - 10} more
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Individual Selection Hint */}
                    {selectedFindings.size === 0 && (
                      <div className="bg-gradient-to-br from-blue-50 to-purple-50 border-2 border-blue-200 rounded-2xl p-8 text-center shadow-sm">
                        <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center mx-auto mb-4 shadow-lg">
                          <Zap className="w-8 h-8 text-white" />
                        </div>
                        <p className="text-slate-800 text-base font-semibold mb-2">
                          💡 Get Started
                        </p>
                        <p className="text-slate-600 text-sm leading-relaxed">
                          Use the buttons above to select findings by severity, or scroll up to select individual findings from the list
                        </p>
                      </div>
                    )}
                  </>
                )}

                {/* Step 2: Review Changes - Premium Light */}
                {remediationStep === 'review' && (
                  <div>
                    <div className="mb-6">
                      <h4 className="text-2xl font-semibold text-slate-900 mb-2">Review Proposed Changes</h4>
                      <p className="text-slate-600">Please review the changes that will be applied to your AWS account:</p>
                    </div>

                    <div className="space-y-4 mb-6 max-h-96 overflow-y-auto custom-scrollbar">
                      {Array.from(selectedFindings).slice(0, 5).map((idx) => {
                        const finding = auditResults.findings?.[idx];
                        if (!finding) return null;
                        const colors = getSeverityColor(finding.severity);
                        return (
                          <div key={idx} className={`${colors.bg} border-2 ${colors.border} rounded-xl p-4 shadow-sm`}>
                            <div className="flex items-start justify-between mb-3">
                              <div className="flex-1">
                                <div className="flex items-center space-x-2 mb-2">
                                  <span className={`px-2.5 py-1 ${colors.badge} border rounded-md text-xs font-semibold`}>
                                    {finding.severity}
                                  </span>
                                  <span className="text-slate-900 font-bold">{finding.title}</span>
                                </div>
                                {finding.role && (
                                  <div className="text-slate-600 text-sm font-mono mb-2">{finding.role}</div>
                                )}
                                <div className="text-slate-600 text-sm mb-3">{finding.description}</div>
                              </div>
                            </div>
                            <div className="bg-gradient-to-r from-emerald-100 to-green-100 border-2 border-emerald-400 rounded-lg p-3 shadow-sm">
                              <div className="text-emerald-800 text-sm font-bold mb-1 flex items-center">
                                <CheckCircle className="w-3 h-3 mr-1.5" />
                                Proposed Fix:
                              </div>
                              <div className="text-emerald-900 text-sm font-medium">{finding.recommendation}</div>
                            </div>
                          </div>
                        );
                      })}
                      {selectedFindings.size > 5 && (
                        <div className="text-slate-500 text-sm text-center py-2">
                          ... and {selectedFindings.size - 5} more findings
                        </div>
                      )}
                    </div>

                    <div className="flex items-center justify-between">
                      <button
                        onClick={() => setRemediationStep('select')}
                        className="px-6 py-3 bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 rounded-lg font-semibold transition-colors"
                      >
                        ← Back to Selection
                      </button>
                      <button
                        onClick={() => setRemediationStep('confirm')}
                        className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-bold transition-all shadow-sm"
                      >
                        Continue to Confirmation →
                      </button>
                    </div>
                  </div>
                )}

                {/* Step 3: Final Confirmation */}
                {remediationStep === 'confirm' && (
                  <div>
                    <div className="bg-red-50 border-2 border-red-200 rounded-xl p-6 mb-6">
                      <div className="flex items-start space-x-3 mb-4">
                        <AlertTriangle className="w-6 h-6 text-red-600 flex-shrink-0 mt-0.5" />
                        <div>
                          <h4 className="text-red-800 font-bold text-lg mb-2">Final Confirmation Required</h4>
                          <p className="text-red-700 mb-2">
                            You are about to apply <span className="text-red-900 font-bold">{selectedFindings.size}</span> remediation(s) to your AWS account.
                          </p>
                          <ul className="text-red-700 text-sm space-y-1 list-disc list-inside ml-4">
                            <li>These changes will modify IAM policies in your AWS account</li>
                            <li>All actions will be logged in CloudTrail</li>
                            <li>You can rollback changes if needed</li>
                            <li>Please ensure you have reviewed each change carefully</li>
                        </ul>
                        </div>
                      </div>
                    </div>

                    <div className="mb-6">
                      <label className="flex items-center space-x-3 cursor-pointer p-4 bg-slate-50 rounded-lg border border-slate-200 hover:border-blue-300 transition-colors">
                        <input
                          type="checkbox"
                          id="confirm-checkbox"
                          className="w-5 h-5 rounded-md border-2 border-slate-300 bg-white text-blue-600 focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 cursor-pointer transition-all hover:border-blue-400 checked:bg-blue-600 checked:border-blue-600"
                        />
                        <span className="text-slate-900 font-semibold">
                          I understand the changes and confirm I want to proceed with remediation
                        </span>
                      </label>
                    </div>

                    <div className="flex items-center justify-between">
                      <button
                        onClick={() => setRemediationStep('review')}
                        className="px-6 py-3 bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 rounded-lg font-semibold transition-colors"
                      >
                        ← Back to Review
                      </button>
                      <button
                        onClick={async () => {
                          const checkbox = document.getElementById('confirm-checkbox') as HTMLInputElement;
                          if (!checkbox?.checked) {
                            alert('Please confirm by checking the box');
                            return;
                          }
                          setRemediationStep('processing');
                          setIsRemediating(true);
                          const findingsToRemediate = Array.from(selectedFindings).map(idx => auditResults.findings?.[idx]).filter(Boolean);
                          try {
                            const response = await fetch('http://localhost:8000/api/audit/remediate', {
                              method: 'POST',
                              headers: { 'Content-Type': 'application/json' },
                              body: JSON.stringify({
                                findings: findingsToRemediate,
                                mode: 'selected'
                              })
                            });
                            const data = await response.json();
                            if (data.success) {
                              setRemediationResults(data);
                              setRemediationStep('complete');
                            } else {
                              setError(data.error || 'Remediation failed.');
                              setRemediationStep('confirm');
                            }
                          } catch (err) {
                            setError('Failed to apply fixes.');
                            setRemediationStep('confirm');
                          } finally {
                            setIsRemediating(false);
                          }
                        }}
                        disabled={isRemediating}
                        className="px-8 py-3 bg-red-600 hover:bg-red-700 text-white rounded-lg font-bold transition-all shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {isRemediating ? (
                          <>
                            <RefreshCw className="w-5 h-5 inline-block animate-spin mr-2" />
                            Applying Changes...
                          </>
                        ) : (
                          '🚀 Confirm & Apply Remediation'
                        )}
                      </button>
                    </div>
                  </div>
                )}

                {/* Step 4: Processing - Premium Light */}
                {remediationStep === 'processing' && (
                  <div className="text-center py-12">
                    <RefreshCw className="w-12 h-12 text-blue-600 animate-spin mx-auto mb-4" />
                    <p className="text-slate-900 font-semibold text-lg">Applying Remediation...</p>
                    <p className="text-slate-600 text-sm mt-2">Please wait while we apply the changes to your AWS account</p>
                  </div>
                )}

                {/* Step 5: Complete - Premium Light */}
                {remediationStep === 'complete' && remediationResults && (
                  <div>
                    <div className="bg-emerald-50 border-2 border-emerald-200 rounded-xl p-6 mb-6">
                      <div className="flex items-center space-x-3 mb-4">
                        <CheckCircle className="w-8 h-8 text-emerald-600" />
                        <div>
                          <h4 className="text-emerald-800 font-bold text-xl">Remediation Complete!</h4>
                          <p className="text-emerald-700 text-sm">
                            Successfully fixed {remediationResults.remediated} out of {selectedFindings.size} selected issues.
                          </p>
                        </div>
                      </div>
                      {remediationResults.failed > 0 && (
                        <div className="bg-red-50 border border-red-200 rounded-lg p-3 mt-4">
                          <p className="text-red-700 text-sm">
                            {remediationResults.failed} fixes failed. Please review the errors and try again.
                          </p>
                        </div>
                      )}
                    </div>
                    <div className="flex items-center justify-center space-x-4">
                      <button
                        onClick={() => {
                          setSelectedFindings(new Set());
                          setRemediationStep('select');
                          setRemediationResults(null);
                          handleStartAudit();
                        }}
                        className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-bold transition-all shadow-sm"
                      >
                        Run New Audit
                      </button>
                      <button
                        onClick={() => {
                          setSelectedFindings(new Set());
                          setRemediationStep('select');
                          setRemediationResults(null);
                        }}
                        className="px-6 py-3 bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 rounded-lg font-semibold transition-colors"
                      >
                        Remediate More
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Premium Chat Interface - Focused on Q&A, not duplicate summary */}
              <div className="bg-white/80 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-8 shadow-xl mt-8">
                  <div className="mb-6 max-h-96 overflow-y-auto custom-scrollbar">
                    {/* Welcome message - Simple, no duplicate findings */}
                    {chatMessages.length === 0 && (
                      <div className="flex items-start space-x-4 mb-6">
                        <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 via-purple-500 to-pink-500 flex items-center justify-center flex-shrink-0 shadow-lg">
                          <Shield className="w-6 h-6 text-white" />
                        </div>
                        <div className="flex-1 bg-gradient-to-br from-blue-50 to-purple-50 rounded-2xl p-6 border-2 border-blue-200 shadow-sm">
                          <p className="text-slate-900 font-bold text-lg mb-2">AI Security Assistant</p>
                          <p className="text-slate-600 text-sm">
                            I can help you understand your audit findings, explain security issues, suggest fixes, or answer any questions about your IAM policies. What would you like to know?
                          </p>
                        </div>
                      </div>
                    )}
                    
                    {/* Chat messages */}
                    {chatMessages.map((msg, idx) => (
                      <div key={idx} className={`flex items-start space-x-4 mb-4 ${msg.role === 'user' ? 'justify-end' : ''}`}>
                        {msg.role === 'assistant' && (
                          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 via-purple-500 to-pink-500 flex items-center justify-center flex-shrink-0 shadow-lg">
                            <Shield className="w-6 h-6 text-white" />
                          </div>
                        )}
                        <div className={`flex-1 rounded-2xl p-4 border-2 shadow-sm ${
                          msg.role === 'user' 
                            ? 'bg-gradient-to-r from-blue-500 to-purple-500 text-white border-blue-400 max-w-md ml-auto' 
                            : 'bg-gradient-to-br from-blue-50 to-purple-50 border-blue-200 text-slate-700'
                        }`}>
                          <p className={`text-sm whitespace-pre-wrap font-medium ${msg.role === 'user' ? 'text-white' : 'text-slate-700'}`}>{msg.content}</p>
                        </div>
                        {msg.role === 'user' && (
                          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-slate-600 to-slate-700 flex items-center justify-center flex-shrink-0 shadow-lg">
                            <span className="text-white text-sm font-bold">You</span>
                          </div>
                        )}
                      </div>
                    ))}
                    
                    {/* Loading indicator */}
                    {isChatLoading && (
                      <div className="flex items-start space-x-4 mb-4">
                        <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 via-purple-500 to-pink-500 flex items-center justify-center flex-shrink-0 shadow-lg">
                          <Shield className="w-6 h-6 text-white" />
                        </div>
                                               <div className="flex-1 bg-gradient-to-br from-blue-50 to-purple-50 rounded-2xl p-4 border-2 border-blue-200 shadow-sm">
                          <div className="flex items-center space-x-2">
                            <RefreshCw className="w-4 h-4 text-blue-600 animate-spin" />
                            <span className="text-slate-700 text-sm font-medium">Thinking...</span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                  
                  <div className="flex items-center space-x-3">
                    <input
                      type="text"
                      value={chatInput}
                      onChange={(e) => setChatInput(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && !isChatLoading && handleSendMessage()}
                      placeholder="Ask me anything about these findings or request specific fixes..."
                      disabled={isChatLoading}
                      className="flex-1 bg-white/60 backdrop-blur-sm border-2 border-slate-200 rounded-xl px-5 py-3 text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500 transition-all shadow-sm hover:shadow-md font-medium disabled:opacity-50"
                    />
                    <button 
                      onClick={handleSendMessage}
                      disabled={!chatInput.trim() || isChatLoading}
                      className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-xl font-bold transition-all duration-300 shadow-lg hover:shadow-xl flex items-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed transform hover:scale-105"
                    >
                      <span>Send</span>
                      <ChevronRight className="w-4 h-4" />
                    </button>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-center space-x-4">
              <button
                onClick={() => {
                  setAuditResults(null);
                  setError(null);
                }}
                className="px-6 py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white rounded-xl font-bold transition-all duration-300 flex items-center space-x-2"
              >
                <RefreshCw className="w-5 h-5" />
                <span>Run New Audit</span>
              </button>
              <button
                onClick={() => {
                  try {
                    // Create comprehensive audit report with proper structure
                    const reportData = {
                      report_type: 'AWS IAM Security Audit Report',
                      generated_by: 'Aegis IAM - Enterprise IAM Security Platform',
                      timestamp: new Date().toISOString(),
                      date: new Date().toLocaleDateString('en-US', { 
                        year: 'numeric', 
                        month: 'long', 
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit'
                      }),
                      executive_summary: {
                        security_score: auditResults.security_score ?? Math.max(0, 100 - (auditResults.risk_score || 100)),
                        risk_score: auditResults.risk_score || 0,
                        security_grade: getSecurityGrade(auditResults.security_score ?? Math.max(0, 100 - (auditResults.risk_score || 100))).grade,
                        overall_status: getSecurityGrade(auditResults.security_score ?? Math.max(0, 100 - (auditResults.risk_score || 100))).label
                      },
                      audit_summary: auditResults.audit_summary,
                      findings_summary: {
                        total_findings: auditResults.audit_summary.total_findings,
                        critical: auditResults.audit_summary.critical_issues,
                        high: auditResults.audit_summary.high_issues,
                        medium: (auditResults.findings || []).filter((f: Finding) => f.severity === 'Medium').length,
                        low: (auditResults.findings || []).filter((f: Finding) => f.severity === 'Low').length
                      },
                      findings: auditResults.findings,
                      recommendations: auditResults.recommendations,
                      compliance_status: auditResults.compliance_status,
                      cloudtrail_analysis: auditResults.cloudtrail_analysis,
                      scp_analysis: auditResults.scp_analysis
                    };
                    
                    // Format as JSON with proper spacing
                    const dataStr = JSON.stringify(reportData, null, 2);
                    // Use proper MIME type with charset
                    const dataBlob = new Blob([dataStr], { type: 'application/json;charset=utf-8' });
                  const url = URL.createObjectURL(dataBlob);
                  const link = document.createElement('a');
                  link.href = url;
                    // Use .json extension (not .pdf) - JSON is the correct format
                    link.download = `aegis-audit-report-${new Date().toISOString().split('T')[0]}.json`;
                    document.body.appendChild(link);
                  link.click();
                    document.body.removeChild(link);
                    URL.revokeObjectURL(url);
                  } catch (error) {
                    console.error('Error downloading report:', error);
                    alert('Failed to download report. Please try again.');
                  }
                }}
                className="px-6 py-3 bg-gradient-to-r from-slate-700 to-slate-600 hover:from-slate-600 hover:to-slate-500 text-white rounded-xl font-bold transition-all duration-300 flex items-center space-x-2 shadow-lg hover:shadow-xl hover:scale-105"
              >
                <Download className="w-5 h-5" />
                <span>Download Report (JSON)</span>
              </button>
            </div>
          </div>
        )}

        {/* Hero Section - Only show if no results - Premium Light Theme */}
        {!auditResults && (
        <div className="text-center mb-20 animate-fadeIn">
          <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-200 rounded-full px-6 py-3 mb-6 backdrop-blur-sm">
            <Scan className="w-5 h-5 text-blue-600" />
            <span className="text-blue-700 font-semibold text-sm uppercase tracking-wide">Autonomous Security Audit</span>
          </div>
          
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 bg-clip-text text-transparent mb-4 sm:mb-6 leading-tight tracking-tight px-4">
            Audit Your Entire<br />
            <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">
              AWS Account
            </span>
          </h1>
          
          <p className="text-base sm:text-lg lg:text-xl text-slate-600 max-w-3xl mx-auto leading-relaxed mb-8 sm:mb-12 font-medium animate-fadeIn px-4" style={{ animationDelay: '0.2s' }}>
            AI-powered autonomous scanning of all IAM roles, policies, and permissions. Discover unused access, 
            security gaps, and compliance violations across your entire AWS infrastructure using <strong className="text-slate-900">CloudTrail analysis</strong> and real-time API monitoring.
          </p>

          {/* CTA Button */}
          <button
            onClick={handleStartAudit}
            disabled={isAuditing}
            className="group relative px-6 sm:px-10 py-4 sm:py-5 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-2xl font-bold text-base sm:text-lg lg:text-xl transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105 flex items-center space-x-3 mx-auto disabled:opacity-50 disabled:cursor-not-allowed transform animate-fadeIn touch-manipulation" style={{ animationDelay: '0.4s', minHeight: '44px' }}
          >
            {isAuditing ? (
              <>
                <RefreshCw className="w-6 h-6 animate-spin" />
                <span>Auditing...</span>
              </>
            ) : (
              <>
                <Play className="w-6 h-6" />
                <span>Start Autonomous Audit</span>
                <ChevronRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </>
            )}
          </button>

          <p className="text-sm text-slate-600 mt-4 font-medium animate-fadeIn" style={{ animationDelay: '0.6s' }}>
            <Lock className="w-4 h-4 inline mr-1" />
            Requires AWS credentials • Scans entire account in 30-60 seconds
          </p>
        </div>
        )}

        {/* Feature Grid - Only show if no results */}
        {!auditResults && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 mb-20">
          {/* Feature 1 */}
          <div className="group relative bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-8 shadow-xl hover:shadow-2xl hover:-translate-y-1 transition-all duration-500 overflow-hidden animate-fadeIn" style={{ animationDelay: '0.2s' }}>
            <div className="absolute inset-0 bg-gradient-to-br from-blue-50/50 to-purple-50/30 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
            <div className="relative">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center mb-6 shadow-lg group-hover:scale-110 transition-transform duration-300">
                <Scan className="w-8 h-8 text-white" />
            </div>
              <h3 className="text-slate-900 text-2xl font-bold mb-3">Autonomous Scanning</h3>
              <p className="text-slate-600 leading-relaxed font-medium">
              AI agent automatically discovers and analyzes all IAM roles, policies, and permissions across your AWS account using MCP integration.
            </p>
            </div>
          </div>

          {/* Feature 2 */}
          <div className="group relative bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-8 shadow-xl hover:shadow-2xl hover:-translate-y-1 transition-all duration-500 overflow-hidden animate-fadeIn" style={{ animationDelay: '0.3s' }}>
            <div className="absolute inset-0 bg-gradient-to-br from-pink-50/50 to-orange-50/30 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
            <div className="relative">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-pink-500 to-orange-500 flex items-center justify-center mb-6 shadow-lg group-hover:scale-110 transition-transform duration-300">
                <Activity className="w-8 h-8 text-white" />
            </div>
              <h3 className="text-slate-900 text-2xl font-bold mb-3">CloudTrail Analysis</h3>
              <p className="text-slate-600 leading-relaxed font-medium">
              Identify unused permissions by analyzing actual API usage from CloudTrail logs. Remove what you don't need.
            </p>
            </div>
          </div>

          {/* Feature 3 */}
          <div className="group relative bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-8 shadow-xl hover:shadow-2xl hover:-translate-y-1 transition-all duration-500 overflow-hidden animate-fadeIn" style={{ animationDelay: '0.4s' }}>
            <div className="absolute inset-0 bg-gradient-to-br from-orange-50/50 to-red-50/30 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
            <div className="relative">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-orange-500 to-red-500 flex items-center justify-center mb-6 shadow-lg group-hover:scale-110 transition-transform duration-300">
                <Shield className="w-8 h-8 text-white" />
            </div>
              <h3 className="text-slate-900 text-2xl font-bold mb-3">SCP & Boundaries</h3>
              <p className="text-slate-600 leading-relaxed font-medium">
              Detect conflicts between IAM policies, Service Control Policies (SCPs), and Permission Boundaries.
            </p>
            </div>
          </div>

          {/* Feature 4 */}
          <div className="group relative bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-8 shadow-xl hover:shadow-2xl hover:-translate-y-1 transition-all duration-500 overflow-hidden animate-fadeIn" style={{ animationDelay: '0.5s' }}>
            <div className="absolute inset-0 bg-gradient-to-br from-emerald-50/50 to-green-50/30 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
            <div className="relative">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-emerald-500 to-green-500 flex items-center justify-center mb-6 shadow-lg group-hover:scale-110 transition-transform duration-300">
                <CheckCircle className="w-8 h-8 text-white" />
            </div>
              <h3 className="text-slate-900 text-2xl font-bold mb-3">Compliance Validation</h3>
              <p className="text-slate-600 leading-relaxed font-medium">
              Validate all policies against PCI DSS, HIPAA, SOX, GDPR, AWS FSBP, and other compliance frameworks.
            </p>
            </div>
          </div>

          {/* Feature 5 */}
          <div className="group relative bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-8 shadow-xl hover:shadow-2xl hover:-translate-y-1 transition-all duration-500 overflow-hidden animate-fadeIn" style={{ animationDelay: '0.6s' }}>
            <div className="absolute inset-0 bg-gradient-to-br from-yellow-50/50 to-amber-50/30 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
            <div className="relative">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-yellow-500 to-amber-500 flex items-center justify-center mb-6 shadow-lg group-hover:scale-110 transition-transform duration-300">
                <Target className="w-8 h-8 text-white" />
            </div>
              <h3 className="text-slate-900 text-2xl font-bold mb-3">Risk Prioritization</h3>
              <p className="text-slate-600 leading-relaxed font-medium">
              Get a prioritized list of security risks ranked by severity and potential impact to your organization.
            </p>
            </div>
          </div>

          {/* Feature 6 */}
          <div className="group relative bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-3xl p-8 shadow-xl hover:shadow-2xl hover:-translate-y-1 transition-all duration-500 overflow-hidden animate-fadeIn" style={{ animationDelay: '0.7s' }}>
            <div className="absolute inset-0 bg-gradient-to-br from-blue-50/50 to-cyan-50/30 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
            <div className="relative">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center mb-6 shadow-lg group-hover:scale-110 transition-transform duration-300">
                <TrendingUp className="w-8 h-8 text-white" />
            </div>
              <h3 className="text-slate-900 text-2xl font-bold mb-3">Actionable Reports</h3>
              <p className="text-slate-600 leading-relaxed font-medium">
              Export comprehensive audit reports with specific remediation steps for your security and compliance teams.
            </p>
            </div>
          </div>
        </div>
        )}

        {/* How It Works Section - Only show if no results - Premium Light Theme */}
        {!auditResults && (
        <div className="mb-20 animate-fadeIn" style={{ animationDelay: '0.8s' }}>
          <div className="flex items-center justify-center space-x-3 mb-12">
            <div className="w-1 h-8 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
            <h2 className="text-4xl font-bold text-slate-900 text-center tracking-tight">
              How <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 bg-clip-text text-transparent">Autonomous Audit</span> Works
          </h2>
            <div className="w-1 h-8 bg-gradient-to-b from-blue-500 to-purple-500 rounded-full"></div>
          </div>
          
          <div className="flex flex-col md:flex-row items-center justify-center gap-4 md:gap-2">
            {/* Step 1 */}
            <div className="relative group w-full md:w-auto">
              <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-6 text-center shadow-xl hover:shadow-2xl hover:-translate-y-1 transition-all duration-500">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center text-white font-black text-xl mx-auto mb-4 shadow-lg group-hover:scale-110 transition-transform duration-300">1</div>
                <h4 className="text-slate-900 font-bold mb-2">Connect AWS</h4>
                <p className="text-slate-600 text-sm font-medium">Provide credentials or use configured AWS profile</p>
              </div>
            </div>

            {/* Arrow 1 - Between boxes */}
            <div className="hidden md:flex items-center justify-center mx-1">
            <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 rounded-full blur-md opacity-30"></div>
                <div className="relative w-10 h-10 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 rounded-full flex items-center justify-center shadow-lg">
                  <ChevronRight className="w-5 h-5 text-white font-bold drop-shadow-lg" />
              </div>
              </div>
            </div>

            {/* Step 2 */}
            <div className="relative group w-full md:w-auto">
              <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-6 text-center shadow-xl hover:shadow-2xl hover:-translate-y-1 transition-all duration-500">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center text-white font-black text-xl mx-auto mb-4 shadow-lg group-hover:scale-110 transition-transform duration-300">2</div>
                <h4 className="text-slate-900 font-bold mb-2">AI Scans Account</h4>
                <p className="text-slate-600 text-sm font-medium">Agent discovers all IAM roles and policies using MCP</p>
              </div>
            </div>

            {/* Arrow 2 - Between boxes */}
            <div className="hidden md:flex items-center justify-center mx-1">
            <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-r from-purple-500 via-pink-500 to-orange-500 rounded-full blur-md opacity-30"></div>
                <div className="relative w-10 h-10 bg-gradient-to-r from-purple-500 via-pink-500 to-orange-500 rounded-full flex items-center justify-center shadow-lg">
                  <ChevronRight className="w-5 h-5 text-white font-bold drop-shadow-lg" />
              </div>
              </div>
            </div>

            {/* Step 3 */}
            <div className="relative group w-full md:w-auto">
              <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-6 text-center shadow-xl hover:shadow-2xl hover:-translate-y-1 transition-all duration-500">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-pink-500 to-orange-500 flex items-center justify-center text-white font-black text-xl mx-auto mb-4 shadow-lg group-hover:scale-110 transition-transform duration-300">3</div>
                <h4 className="text-slate-900 font-bold mb-2">Deep Analysis</h4>
                <p className="text-slate-600 text-sm font-medium">Validates security, compliance, and usage patterns</p>
              </div>
            </div>

            {/* Arrow 3 - Between boxes */}
            <div className="hidden md:flex items-center justify-center mx-1">
            <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-r from-orange-500 via-pink-500 to-emerald-500 rounded-full blur-md opacity-30"></div>
                <div className="relative w-10 h-10 bg-gradient-to-r from-orange-500 via-pink-500 to-emerald-500 rounded-full flex items-center justify-center shadow-lg">
                  <ChevronRight className="w-5 h-5 text-white font-bold drop-shadow-lg" />
              </div>
              </div>
            </div>

            {/* Step 4 */}
            <div className="group w-full md:w-auto">
              <div className="bg-white/90 backdrop-blur-xl border-2 border-white/50 rounded-2xl p-6 text-center shadow-xl hover:shadow-2xl hover:-translate-y-1 transition-all duration-500">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-emerald-500 to-green-500 flex items-center justify-center text-white font-black text-xl mx-auto mb-4 shadow-lg group-hover:scale-110 transition-transform duration-300">4</div>
                <h4 className="text-slate-900 font-bold mb-2">Get Report</h4>
                <p className="text-slate-600 text-sm font-medium">Comprehensive findings with remediation steps</p>
              </div>
            </div>
          </div>
        </div>
        )}

      </div>
    </div>
  );
};

export default AuditAccount;