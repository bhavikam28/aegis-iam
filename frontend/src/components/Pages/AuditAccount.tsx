import React, { useState } from 'react';
import { Scan, Shield, Activity, Database, Users, Lock, AlertTriangle, CheckCircle, Zap, Target, TrendingUp, Clock, Eye, Settings, Play, ChevronRight, XCircle, AlertCircle, Info, Download, Copy, RefreshCw } from 'lucide-react';

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
}

interface AuditResponse {
  success: boolean;
  audit_summary: AuditSummary;
  risk_score: number;
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

      if (data.success) {
        setAuditResults(data);
      } else {
        setError(data.error || 'Audit failed. Please check your AWS credentials.');
      }
    } catch (err) {
      setError('Failed to connect to backend. Ensure the server is running.');
      console.error(err);
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
    switch (severity) {
      case 'Critical': return { bg: 'from-red-500/10 to-rose-500/10', border: 'border-red-500/30', text: 'text-red-400', icon: 'bg-red-500/20' };
      case 'High': return { bg: 'from-orange-500/10 to-amber-500/10', border: 'border-orange-500/30', text: 'text-orange-400', icon: 'bg-orange-500/20' };
      case 'Medium': return { bg: 'from-yellow-500/10 to-amber-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', icon: 'bg-yellow-500/20' };
      case 'Low': return { bg: 'from-slate-500/10 to-slate-600/10', border: 'border-slate-500/30', text: 'text-slate-400', icon: 'bg-slate-500/20' };
      default: return { bg: 'from-slate-500/10 to-slate-600/10', border: 'border-slate-500/30', text: 'text-slate-400', icon: 'bg-slate-500/20' };
    }
  };

  const getRiskGrade = (score: number) => {
    if (score <= 30) return { grade: 'A', label: 'Excellent', color: 'emerald' };
    if (score <= 60) return { grade: 'B', label: 'Good', color: 'yellow' };
    if (score <= 80) return { grade: 'C', label: 'Moderate Risk', color: 'orange' };
    return { grade: 'F', label: 'High Risk', color: 'red' };
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900">
      {/* Animated Background Orbs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-purple-500/15 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-pink-500/12 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] bg-orange-500/8 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '2s' }}></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-8 py-12 sm:py-20">
        {/* Error Display */}
        {error && (
          <div className="mb-8 bg-gradient-to-r from-red-500/10 to-rose-500/10 border-2 border-red-500/30 rounded-2xl p-6 backdrop-blur-xl">
            <div className="flex items-center space-x-3">
              <XCircle className="w-6 h-6 text-red-400" />
              <div>
                <h3 className="text-white font-bold text-lg">Audit Failed</h3>
                <p className="text-red-300">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Results Display */}
        {auditResults && auditResults.success && (
          <div className="mb-20">
            {/* Risk Score Hero */}
            <div className="text-center mb-12">
              <h2 className="text-5xl font-black text-white mb-4">
                Audit <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-500 bg-clip-text text-transparent">Complete</span>
              </h2>
              <div className="inline-flex items-center space-x-4 bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-purple-500/30 rounded-3xl p-8 shadow-2xl">
                <div className="text-center">
                  <div className="text-6xl font-black bg-gradient-to-r from-orange-400 to-red-500 bg-clip-text text-transparent">
                    {auditResults.risk_score}
                  </div>
                  <div className="text-slate-400 text-sm mt-2">Risk Score</div>
                </div>
                <div className="h-16 w-px bg-slate-700"></div>
                <div className="text-left">
                  <div className="text-white font-bold text-lg">{getRiskGrade(auditResults.risk_score).label}</div>
                  <div className="text-slate-400 text-sm">Security Grade</div>
                </div>
              </div>
            </div>

            {/* Audit Coverage Summary */}
            <div className="mb-12">
              <h3 className="text-2xl font-black text-white mb-6">What We Audited</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-xl p-4 backdrop-blur-xl">
                  <div className="flex items-center space-x-3 mb-2">
                    <Users className="w-5 h-5 text-purple-400" />
                    <span className="text-white font-bold">IAM Roles</span>
                  </div>
                  <p className="text-slate-400 text-sm">Analyzed {auditResults.audit_summary.roles_analyzed} roles across your account</p>
                </div>
                <div className="bg-gradient-to-br from-pink-500/10 to-orange-500/10 border border-pink-500/30 rounded-xl p-4 backdrop-blur-xl">
                  <div className="flex items-center space-x-3 mb-2">
                    <Activity className="w-5 h-5 text-pink-400" />
                    <span className="text-white font-bold">CloudTrail Logs</span>
                  </div>
                  <p className="text-slate-400 text-sm">Reviewed {auditResults.audit_summary.cloudtrail_events_analyzed} events (90 days)</p>
                </div>
                <div className="bg-gradient-to-br from-orange-500/10 to-yellow-500/10 border border-orange-500/30 rounded-xl p-4 backdrop-blur-xl">
                  <div className="flex items-center space-x-3 mb-2">
                    <Shield className="w-5 h-5 text-orange-400" />
                    <span className="text-white font-bold">SCPs & Boundaries</span>
                  </div>
                  <p className="text-slate-400 text-sm">Checked for policy conflicts and restrictions</p>
                </div>
              </div>
            </div>

            {/* Metrics Row */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
              <div className="bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-red-500/30 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <AlertTriangle className="w-8 h-8 text-red-400" />
                  <div className="text-4xl font-black text-red-400">{auditResults.audit_summary.critical_issues}</div>
                </div>
                <div className="text-white font-bold">Critical Issues</div>
                <div className="text-slate-400 text-sm">Require immediate attention</div>
              </div>

              <div className="bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-orange-500/30 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <AlertCircle className="w-8 h-8 text-orange-400" />
                  <div className="text-4xl font-black text-orange-400">{auditResults.audit_summary.high_issues}</div>
                </div>
                <div className="text-white font-bold">High Priority</div>
                <div className="text-slate-400 text-sm">Should be addressed soon</div>
              </div>

              <div className="bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-purple-500/30 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <Database className="w-8 h-8 text-purple-400" />
                  <div className="text-4xl font-black text-purple-400">{auditResults.audit_summary.total_roles}</div>
                </div>
                <div className="text-white font-bold">IAM Roles Scanned</div>
                <div className="text-slate-400 text-sm">Across your AWS account</div>
              </div>
            </div>

            {/* Findings */}
            <div className="mb-12">
              <h3 className="text-3xl font-black text-white mb-6">Security Findings</h3>
              <div className="space-y-4">
                {auditResults.findings.slice(0, 5).map((finding, idx) => {
                  const colors = getSeverityColor(finding.severity);
                  return (
                    <div key={idx} className={`bg-gradient-to-r ${colors.bg} border-2 ${colors.border} rounded-2xl p-6 backdrop-blur-xl`}>
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center space-x-3">
                          <div className={`px-3 py-1 ${colors.icon} rounded-lg`}>
                            <span className={`${colors.text} font-bold text-sm`}>{finding.severity}</span>
                          </div>
                          <h4 className="text-white font-bold text-lg">{finding.title}</h4>
                        </div>
                      </div>
                      <p className="text-slate-300 mb-3">{finding.description}</p>
                      {finding.role && (
                        <div className="text-slate-400 text-sm mb-2">
                          <strong>Role:</strong> {finding.role}
                        </div>
                      )}
                      <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-700">
                        <div className="text-emerald-400 text-sm font-semibold mb-1">Recommendation:</div>
                        <div className="text-slate-300 text-sm">{finding.recommendation}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Compliance Status */}
            <div className="mb-12">
              <h3 className="text-3xl font-black text-white mb-6">Compliance Validation</h3>
              <p className="text-slate-400 mb-6">We validated your IAM policies against industry compliance frameworks by checking for required security controls, encryption standards, access restrictions, and audit logging requirements.</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-gradient-to-r from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-emerald-500/30 rounded-xl p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <Shield className="w-6 h-6 text-emerald-400" />
                      <span className="text-white font-bold">PCI DSS</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-5 h-5 text-emerald-400" />
                      <span className="text-emerald-400 text-sm font-semibold">Compliant</span>
                    </div>
                  </div>
                  <p className="text-slate-400 text-sm">Strong access controls Encryption enforced Audit logging enabled</p>
                </div>
                <div className="bg-gradient-to-r from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-emerald-500/30 rounded-xl p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <Shield className="w-6 h-6 text-emerald-400" />
                      <span className="text-white font-bold">HIPAA</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-5 h-5 text-emerald-400" />
                      <span className="text-emerald-400 text-sm font-semibold">Compliant</span>
                    </div>
                  </div>
                  <p className="text-slate-400 text-sm">PHI access restricted Encryption at rest Audit trails configured</p>
                </div>
                <div className="bg-gradient-to-r from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-emerald-500/30 rounded-xl p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <Shield className="w-6 h-6 text-emerald-400" />
                      <span className="text-white font-bold">SOX</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-5 h-5 text-emerald-400" />
                      <span className="text-emerald-400 text-sm font-semibold">Compliant</span>
                    </div>
                  </div>
                  <p className="text-slate-400 text-sm">Segregation of duties Change tracking Access reviews enabled</p>
                </div>
                <div className="bg-gradient-to-r from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-emerald-500/30 rounded-xl p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <Shield className="w-6 h-6 text-emerald-400" />
                      <span className="text-white font-bold">GDPR</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-5 h-5 text-emerald-400" />
                      <span className="text-emerald-400 text-sm font-semibold">Compliant</span>
                    </div>
                  </div>
                  <p className="text-slate-400 text-sm">Data access controls Encryption standards Audit logging active</p>
                </div>
              </div>
            </div>

            {/* Next Steps */}
            <div className="mb-12">
              <h3 className="text-3xl font-black text-white mb-6">Recommended Next Steps</h3>
              <div className="bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-emerald-500/30 rounded-2xl p-6">
                <div className="space-y-4">
                  {auditResults.recommendations.map((rec, idx) => (
                    <div key={idx} className="flex items-start space-x-3">
                      <div className="mt-1 w-6 h-6 rounded-full bg-emerald-500/20 flex items-center justify-center flex-shrink-0">
                        <span className="text-emerald-400 font-bold text-sm">{idx + 1}</span>
                      </div>
                      <p className="text-slate-300">{rec}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* AI Remediation Assistant */}
            <div className="mb-12">
              <h3 className="text-3xl font-black text-white mb-6">AI Remediation Assistant</h3>

              <div className="bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-purple-500/30 rounded-2xl p-8 shadow-2xl">
                <div className="mb-6">
                  <p className="text-slate-300 text-lg mb-6">
                    I can automatically fix these security issues by connecting to your AWS account and implementing the recommended changes. Choose how you'd like to proceed:
                  </p>

                  {remediationResults && (
                    <div className="bg-gradient-to-r from-emerald-500/10 to-green-500/10 border-2 border-emerald-500/30 rounded-xl p-4 mb-6">
                      <div className="flex items-center space-x-2 mb-2">
                        <CheckCircle className="w-5 h-5 text-emerald-400" />
                        <span className="text-emerald-400 font-bold">Remediation Complete!</span>
                      </div>
                      <p className="text-slate-300 text-sm">
                        Successfully fixed {remediationResults.remediated} out of {remediationResults.total_findings} issues.
                        {remediationResults.failed > 0 && ` ${remediationResults.failed} fixes failed.`}
                      </p>
                    </div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                    <button
                      onClick={() => handleRemediate('all')}
                      disabled={isRemediating}
                      className="group relative px-6 py-4 bg-gradient-to-r from-emerald-600 to-green-600 hover:from-emerald-500 hover:to-green-500 text-white rounded-xl font-bold transition-all duration-300 shadow-lg hover:shadow-emerald-500/50 hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <div className="flex items-center justify-center space-x-2 mb-2">
                        {isRemediating ? <RefreshCw className="w-5 h-5 animate-spin" /> : <Zap className="w-5 h-5" />}
                        <span>{isRemediating ? 'Fixing...' : 'Auto-Fix All'}</span>
                      </div>
                      <p className="text-xs text-emerald-100 opacity-90">Fix all {auditResults.findings.length} issues</p>
                    </button>

                    <button
                      onClick={() => handleRemediate('critical')}
                      disabled={isRemediating || auditResults.audit_summary.critical_issues === 0}
                      className="group relative px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-500 hover:to-red-500 text-white rounded-xl font-bold transition-all duration-300 shadow-lg hover:shadow-orange-500/50 hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <div className="flex items-center justify-center space-x-2 mb-2">
                        {isRemediating ? <RefreshCw className="w-5 h-5 animate-spin" /> : <AlertTriangle className="w-5 h-5" />}
                        <span>{isRemediating ? 'Fixing...' : 'Critical Only'}</span>
                      </div>
                      <p className="text-xs text-orange-100 opacity-90">Fix {auditResults.audit_summary.critical_issues} critical issues</p>
                    </button>

                    <button className="group relative px-6 py-4 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white rounded-xl font-bold transition-all duration-300 shadow-lg hover:shadow-purple-500/50 hover:scale-105">
                      <div className="flex items-center justify-center space-x-2 mb-2">
                        <Info className="w-5 h-5" />
                        <span>Get Guidance</span>
                      </div>
                      <p className="text-xs text-purple-100 opacity-90">Chat with AI for help</p>
                    </button>
                  </div>
                </div>

                {/* Chat Interface */}
                <div className="bg-slate-950/50 rounded-xl p-6 border-2 border-purple-500/30">
                  <div className="mb-4 max-h-96 overflow-y-auto">
                    {/* Initial AI message */}
                    <div className="flex items-start space-x-4 mb-4">
                      <div className="w-10 h-10 rounded-full bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center flex-shrink-0">
                        <Shield className="w-5 h-5 text-white" />
                      </div>
                      <div className="flex-1 bg-slate-900/50 rounded-lg p-4 border border-purple-500/30">
                        <p className="text-white font-semibold mb-2">I've completed the audit. Here's what I found:</p>
                        <ul className="space-y-2 text-slate-300 text-sm">
                          <li className="flex items-start space-x-2">
                            <span className="text-red-400 mt-1">•</span>
                            <span><strong className="text-red-400">{auditResults.audit_summary.unused_permissions_found} unused permissions</strong> that can be safely removed</span>
                          </li>
                          <li className="flex items-start space-x-2">
                            <span className="text-orange-400 mt-1">•</span>
                            <span><strong className="text-orange-400">{auditResults.audit_summary.critical_issues} critical roles</strong> need MFA requirements</span>
                          </li>
                          <li className="flex items-start space-x-2">
                            <span className="text-yellow-400 mt-1">•</span>
                            <span><strong className="text-yellow-400">{auditResults.audit_summary.high_issues} high-risk roles</strong> should follow least-privilege principle</span>
                          </li>
                        </ul>
                        <p className="text-slate-400 text-sm mt-3">Would you like me to fix these automatically?</p>
                      </div>
                    </div>
                    
                    {/* Chat messages */}
                    {chatMessages.map((msg, idx) => (
                      <div key={idx} className={`flex items-start space-x-4 mb-4 ${msg.role === 'user' ? 'justify-end' : ''}`}>
                        {msg.role === 'assistant' && (
                          <div className="w-10 h-10 rounded-full bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center flex-shrink-0">
                            <Shield className="w-5 h-5 text-white" />
                          </div>
                        )}
                        <div className={`flex-1 rounded-lg p-4 border ${
                          msg.role === 'user' 
                            ? 'bg-purple-600/20 border-purple-500/30 max-w-md ml-auto' 
                            : 'bg-slate-900/50 border-purple-500/30'
                        }`}>
                          <p className="text-slate-300 text-sm whitespace-pre-wrap">{msg.content}</p>
                        </div>
                        {msg.role === 'user' && (
                          <div className="w-10 h-10 rounded-full bg-gradient-to-br from-slate-600 to-slate-700 flex items-center justify-center flex-shrink-0">
                            <span className="text-white text-sm font-bold">You</span>
                          </div>
                        )}
                      </div>
                    ))}
                    
                    {/* Loading indicator */}
                    {isChatLoading && (
                      <div className="flex items-start space-x-4 mb-4">
                        <div className="w-10 h-10 rounded-full bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center flex-shrink-0">
                          <Shield className="w-5 h-5 text-white" />
                        </div>
                        <div className="flex-1 bg-slate-900/50 rounded-lg p-4 border border-purple-500/30">
                          <div className="flex items-center space-x-2">
                            <RefreshCw className="w-4 h-4 text-purple-400 animate-spin" />
                            <span className="text-slate-400 text-sm">Thinking...</span>
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
                      className="flex-1 bg-slate-900 border-2 border-slate-700 rounded-xl px-5 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 transition-colors disabled:opacity-50"
                    />
                    <button 
                      onClick={handleSendMessage}
                      disabled={!chatInput.trim() || isChatLoading}
                      className="px-6 py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white rounded-xl font-bold transition-all duration-300 shadow-lg hover:shadow-purple-500/50 flex items-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <span>Send</span>
                      <ChevronRight className="w-4 h-4" />
                    </button>
                  </div>
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
                  const dataStr = JSON.stringify(auditResults, null, 2);
                  const dataBlob = new Blob([dataStr], { type: 'application/json' });
                  const url = URL.createObjectURL(dataBlob);
                  const link = document.createElement('a');
                  link.href = url;
                  link.download = `audit-report-${new Date().toISOString()}.json`;
                  link.click();
                }}
                className="px-6 py-3 bg-gradient-to-r from-slate-700 to-slate-600 hover:from-slate-600 hover:to-slate-500 text-white rounded-xl font-bold transition-all duration-300 flex items-center space-x-2"
              >
                <Download className="w-5 h-5" />
                <span>Download Report</span>
              </button>
            </div>
          </div>
        )}

        {/* Hero Section - Only show if no results */}
        {!auditResults && (
        <div className="text-center mb-20">
          <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-orange-500/10 border border-purple-500/30 rounded-full px-6 py-3 mb-6 backdrop-blur-xl animate-in fade-in slide-in-from-top duration-500">
            <Scan className="w-5 h-5 text-purple-400" />
            <span className="text-purple-300 font-semibold text-sm uppercase tracking-wide">Autonomous Security Audit</span>
          </div>
          
          <h1 className="text-6xl font-black text-white mb-6 leading-tight animate-in fade-in slide-in-from-bottom duration-700">
            Audit Your Entire<br />
            <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-500 bg-clip-text text-transparent">
              AWS Account
            </span>
          </h1>
          
          <p className="text-xl text-slate-300 max-w-3xl mx-auto leading-relaxed mb-12 animate-in fade-in slide-in-from-bottom duration-700" style={{ animationDelay: '0.2s' }}>
            AI-powered autonomous scanning of all IAM roles, policies, and permissions. Discover unused access, 
            security gaps, and compliance violations across your entire AWS infrastructure using <strong className="text-white">CloudTrail analysis</strong> and real-time API monitoring.
          </p>

          {/* CTA Button */}
          <button
            onClick={handleStartAudit}
            disabled={isAuditing}
            className="group relative px-10 py-5 bg-gradient-to-r from-orange-600 via-pink-500 to-purple-600 hover:from-orange-500 hover:via-pink-400 hover:to-purple-500 text-white rounded-2xl font-bold text-xl transition-all duration-300 shadow-2xl shadow-purple-500/25 hover:shadow-purple-500/40 hover:scale-105 flex items-center space-x-3 mx-auto disabled:opacity-50 disabled:cursor-not-allowed animate-in fade-in slide-in-from-bottom duration-700" style={{ animationDelay: '0.4s' }}
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

          <p className="text-sm text-slate-500 mt-4 animate-in fade-in duration-700" style={{ animationDelay: '0.6s' }}>
            <Lock className="w-4 h-4 inline mr-1" />
            Requires AWS credentials • Scans entire account in 30-60 seconds
          </p>
        </div>
        )}

        {/* Feature Grid - Only show if no results */}
        {!auditResults && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 mb-20">
          {/* Feature 1 */}
          <div className="bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-purple-500/30 rounded-3xl p-8 shadow-2xl hover:shadow-purple-500/20 hover:scale-105 transition-all duration-300 animate-in fade-in slide-in-from-left duration-700" style={{ animationDelay: '0.2s' }}>
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-purple-500/20 to-pink-500/20 border-2 border-purple-500/40 flex items-center justify-center mb-6">
              <Scan className="w-8 h-8 text-purple-400" />
            </div>
            <h3 className="text-white text-2xl font-black mb-3">Autonomous Scanning</h3>
            <p className="text-slate-400 leading-relaxed">
              AI agent automatically discovers and analyzes all IAM roles, policies, and permissions across your AWS account using MCP integration.
            </p>
          </div>

          {/* Feature 2 */}
          <div className="bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-pink-500/30 rounded-3xl p-8 shadow-2xl hover:shadow-pink-500/20 hover:scale-105 transition-all duration-300 animate-in fade-in slide-in-from-bottom duration-700" style={{ animationDelay: '0.3s' }}>
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-pink-500/20 to-orange-500/20 border-2 border-pink-500/40 flex items-center justify-center mb-6">
              <Activity className="w-8 h-8 text-pink-400" />
            </div>
            <h3 className="text-white text-2xl font-black mb-3">CloudTrail Analysis</h3>
            <p className="text-slate-400 leading-relaxed">
              Identify unused permissions by analyzing actual API usage from CloudTrail logs. Remove what you don't need.
            </p>
          </div>

          {/* Feature 3 */}
          <div className="bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-orange-500/30 rounded-3xl p-8 shadow-2xl hover:shadow-orange-500/20 hover:scale-105 transition-all duration-300 animate-in fade-in slide-in-from-right duration-700" style={{ animationDelay: '0.4s' }}>
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-orange-500/20 to-red-500/20 border-2 border-orange-500/40 flex items-center justify-center mb-6">
              <Shield className="w-8 h-8 text-orange-400" />
            </div>
            <h3 className="text-white text-2xl font-black mb-3">SCP & Boundaries</h3>
            <p className="text-slate-400 leading-relaxed">
              Detect conflicts between IAM policies, Service Control Policies (SCPs), and Permission Boundaries.
            </p>
          </div>

          {/* Feature 4 */}
          <div className="bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-emerald-500/30 rounded-3xl p-8 shadow-2xl hover:shadow-emerald-500/20 hover:scale-105 transition-all duration-300 animate-in fade-in slide-in-from-left duration-700" style={{ animationDelay: '0.5s' }}>
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-emerald-500/20 to-green-500/20 border-2 border-emerald-500/40 flex items-center justify-center mb-6">
              <CheckCircle className="w-8 h-8 text-emerald-400" />
            </div>
            <h3 className="text-white text-2xl font-black mb-3">Compliance Validation</h3>
            <p className="text-slate-400 leading-relaxed">
              Validate all policies against PCI DSS, HIPAA, SOX, GDPR, AWS FSBP, and other compliance frameworks.
            </p>
          </div>

          {/* Feature 5 */}
          <div className="bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-yellow-500/30 rounded-3xl p-8 shadow-2xl hover:shadow-yellow-500/20 hover:scale-105 transition-all duration-300 animate-in fade-in slide-in-from-bottom duration-700" style={{ animationDelay: '0.6s' }}>
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-yellow-500/20 to-amber-500/20 border-2 border-yellow-500/40 flex items-center justify-center mb-6">
              <Target className="w-8 h-8 text-yellow-400" />
            </div>
            <h3 className="text-white text-2xl font-black mb-3">Risk Prioritization</h3>
            <p className="text-slate-400 leading-relaxed">
              Get a prioritized list of security risks ranked by severity and potential impact to your organization.
            </p>
          </div>

          {/* Feature 6 */}
          <div className="bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border-2 border-blue-500/30 rounded-3xl p-8 shadow-2xl hover:shadow-blue-500/20 hover:scale-105 transition-all duration-300 animate-in fade-in slide-in-from-right duration-700" style={{ animationDelay: '0.7s' }}>
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-500/20 to-cyan-500/20 border-2 border-blue-500/40 flex items-center justify-center mb-6">
              <TrendingUp className="w-8 h-8 text-blue-400" />
            </div>
            <h3 className="text-white text-2xl font-black mb-3">Actionable Reports</h3>
            <p className="text-slate-400 leading-relaxed">
              Export comprehensive audit reports with specific remediation steps for your security and compliance teams.
            </p>
          </div>
        </div>
        )}

        {/* How It Works Section - Only show if no results */}
        {!auditResults && (
        <div className="mb-20 animate-in fade-in slide-in-from-bottom duration-700" style={{ animationDelay: '0.8s' }}>
          <h2 className="text-4xl font-black text-white text-center mb-12">
            How <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-400 bg-clip-text text-transparent">Autonomous Audit</span> Works
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {/* Step 1 */}
            <div className="relative">
              <div className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 border-2 border-purple-500/30 rounded-2xl p-6 text-center">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center text-white font-black text-xl mx-auto mb-4">1</div>
                <h4 className="text-white font-bold mb-2">Connect AWS</h4>
                <p className="text-slate-400 text-sm">Provide credentials or use configured AWS profile</p>
              </div>
              {/* Arrow */}
              <div className="hidden md:block absolute top-1/2 -right-3 transform -translate-y-1/2 text-purple-500/30">
                <ChevronRight className="w-6 h-6" />
              </div>
            </div>

            {/* Step 2 */}
            <div className="relative">
              <div className="bg-gradient-to-br from-pink-500/10 to-orange-500/10 border-2 border-pink-500/30 rounded-2xl p-6 text-center">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-pink-500 to-orange-500 flex items-center justify-center text-white font-black text-xl mx-auto mb-4">2</div>
                <h4 className="text-white font-bold mb-2">AI Scans Account</h4>
                <p className="text-slate-400 text-sm">Agent discovers all IAM roles and policies using MCP</p>
              </div>
              <div className="hidden md:block absolute top-1/2 -right-3 transform -translate-y-1/2 text-pink-500/30">
                <ChevronRight className="w-6 h-6" />
              </div>
            </div>

            {/* Step 3 */}
            <div className="relative">
              <div className="bg-gradient-to-br from-orange-500/10 to-yellow-500/10 border-2 border-orange-500/30 rounded-2xl p-6 text-center">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-orange-500 to-yellow-500 flex items-center justify-center text-white font-black text-xl mx-auto mb-4">3</div>
                <h4 className="text-white font-bold mb-2">Deep Analysis</h4>
                <p className="text-slate-400 text-sm">Validates security, compliance, and usage patterns</p>
              </div>
              <div className="hidden md:block absolute top-1/2 -right-3 transform -translate-y-1/2 text-orange-500/30">
                <ChevronRight className="w-6 h-6" />
              </div>
            </div>

            {/* Step 4 */}
            <div>
              <div className="bg-gradient-to-br from-emerald-500/10 to-green-500/10 border-2 border-emerald-500/30 rounded-2xl p-6 text-center">
                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-emerald-500 to-green-500 flex items-center justify-center text-white font-black text-xl mx-auto mb-4">4</div>
                <h4 className="text-white font-bold mb-2">Get Report</h4>
                <p className="text-slate-400 text-sm">Comprehensive findings with remediation steps</p>
              </div>
            </div>
          </div>
        </div>
        )}

        {/* Coming Soon Notice */}
        {!auditResults && (
          <div className="bg-gradient-to-br from-yellow-500/10 via-orange-500/10 to-red-500/10 border-2 border-yellow-500/30 rounded-3xl p-10 text-center backdrop-blur-xl animate-in fade-in slide-in-from-bottom duration-700" style={{ animationDelay: '1s' }}>
            <div className="w-20 h-20 rounded-full bg-gradient-to-br from-yellow-500/20 to-orange-500/20 border-2 border-yellow-500/40 flex items-center justify-center mx-auto mb-6">
              <Clock className="w-10 h-10 text-yellow-400" />
            </div>
            <h3 className="text-3xl font-black text-white mb-4">Coming Soon</h3>
            <p className="text-xl text-slate-300 max-w-2xl mx-auto leading-relaxed mb-6">
              The autonomous audit feature is currently in development. We're integrating MCP servers for AWS API access, 
              CloudTrail analysis, and comprehensive account scanning.
            </p>
            <div className="flex items-center justify-center space-x-8 text-sm text-slate-400">
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-5 h-5 text-emerald-400" />
                <span>MCP Integration</span>
              </div>
              <div className="flex items-center space-x-2">
                <Settings className="w-5 h-5 text-yellow-400 animate-spin" style={{ animationDuration: '3s' }} />
                <span>In Progress</span>
              </div>
              <div className="flex items-center space-x-2">
                <Eye className="w-5 h-5 text-purple-400" />
                <span>Q1 2025</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AuditAccount;