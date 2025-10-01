import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, Info, Lightbulb, Send, RefreshCw } from 'lucide-react';
import LoadingSpinner from '../UI/LoadingSpinner';
import SecurityScore from '../UI/SecurityScore';
import CodeBlock from '../UI/CodeBlock';
import { GeneratePolicyRequest, GeneratePolicyResponse } from '../../types';
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

  const awsServices = [
    'S3', 'Lambda', 'EC2', 'DynamoDB', 'RDS', 'SQS', 'SNS', 
    'CloudWatch', 'IAM', 'KMS', 'Secrets Manager', 'API Gateway', 
    'ECS', 'EKS', 'CloudFormation'
  ];

  const complianceFrameworks = [
    { value: 'general', label: 'General Security' },
    { value: 'pci-dss', label: 'PCI DSS' },
    { value: 'hipaa', label: 'HIPAA' },
    { value: 'sox', label: 'SOX' },
    { value: 'gdpr', label: 'GDPR' },
    { value: 'cis', label: 'CIS Benchmarks' }
  ];

  const formatExplanation = (explanation: string) => {
    const paragraphs = explanation.split('\n').filter(para => para.trim() !== '');
    
    return paragraphs.map((paragraph, index) => {
      const trimmed = paragraph.trim();
      
      const numberedMatch = trimmed.match(/^(\d+)\.\s*`?([^`]*)`?\s*-?\s*(.*)$/);
      if (numberedMatch) {
        const [, number, action, description] = numberedMatch;
        return (
          <div key={index} className="flex items-start space-x-3 mb-3">
            <div className="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-medium flex-shrink-0 mt-0.5">
              {number}
            </div>
            <div>
              {action && (
                <code className="bg-slate-800 text-orange-400 px-2 py-1 rounded text-sm font-mono">
                  {action}
                </code>
              )}
              {description && (
                <span className="text-slate-300 ml-2">{description}</span>
              )}
            </div>
          </div>
        );
      }
      
      const bulletMatch = trimmed.match(/^-\s*`?([^`]*)`?\s*-?\s*(.*)$/);
      if (bulletMatch) {
        const [, action, description] = bulletMatch;
        return (
          <div key={index} className="flex items-start space-x-3 mb-2">
            <div className="w-2 h-2 bg-slate-400 rounded-full flex-shrink-0 mt-2"></div>
            <div>
              {action && (
                <code className="bg-slate-800 text-orange-400 px-2 py-1 rounded text-sm font-mono">
                  {action}
                </code>
              )}
              {description && (
                <span className="text-slate-300 ml-2">{description}</span>
              )}
            </div>
          </div>
        );
      }
      
      const awsActionRegex = /(`[^`]+`|[a-z0-9]+:[A-Za-z0-9*]+)/g;
      const parts = trimmed.split(awsActionRegex);
      
      return (
        <p key={index} className="text-slate-300 leading-relaxed mb-3">
          {parts.map((part, partIndex) => {
            if (part.match(/^`[^`]+`$/)) {
              return (
                <code key={partIndex} className="bg-slate-800 text-orange-400 px-1.5 py-0.5 rounded text-sm font-mono">
                  {part.slice(1, -1)}
                </code>
              );
            } else if (part.match(/^[a-z0-9]+:[A-Za-z0-9*]+$/)) {
              return (
                <code key={partIndex} className="bg-slate-800 text-orange-400 px-1.5 py-0.5 rounded text-sm font-mono">
                  {part}
                </code>
              );
            }
            return <span key={partIndex}>{part}</span>;
          })}
        </p>
      );
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResponse(null);
    setConversationId(null);
    setIsRefining(false);

    try {
      const result = await generatePolicy({
        description: request.description,
        service: request.service,
        restrictive: request.restrictive,
        compliance: request.compliance
      });

      setResponse(result);
      if (result.conversation_id) {
        setConversationId(result.conversation_id);
        setIsRefining(true);
      }

    } catch (err) {
      console.error("An error occurred while generating the policy:", err);
      setError("Failed to generate policy. Open the developer console (F12) for details.");

    } finally {
      setLoading(false);
    }
  };

  const handleFollowUp = async () => {
    if (!followUpMessage.trim() || !conversationId) return;

    setLoading(true);
    setError(null);

    try {
      const result = await sendFollowUp(followUpMessage, conversationId, request.service);
      setResponse(result);
      setFollowUpMessage('');

    } catch (err) {
      console.error("An error occurred while sending follow-up:", err);
      setError("Failed to process follow-up message.");

    } finally {
      setLoading(false);
    }
  };

  const handleRefinementClick = (suggestion: string) => {
    setFollowUpMessage(suggestion);
  };

  const handleNewConversation = () => {
    setResponse(null);
    setConversationId(null);
    setIsRefining(false);
    setFollowUpMessage('');
    setRequest({
      description: '',
      service: '',
      restrictive: true,
      compliance: 'general'
    });
  };

  return (
    <div className="p-8 max-w-7xl mx-auto">
      <div className="mb-8">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <div className="w-12 h-12 bg-gradient-to-br from-orange-500 to-orange-600 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">Generate Secure Policy</h1>
              <p className="text-slate-400">AI-powered IAM policy generation with security best practices</p>
            </div>
          </div>
          {isRefining && (
            <button
              onClick={handleNewConversation}
              className="flex items-center space-x-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              <span>New Policy</span>
            </button>
          )}
        </div>
        
        <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
          <div className="flex items-start space-x-3">
            <Info className="w-5 h-5 text-blue-400 mt-0.5" />
            <div>
              <h3 className="text-blue-400 font-medium">Conversational Policy Builder</h3>
              <p className="text-slate-300 text-sm mt-1">
                Describe your needs, then refine the policy through conversation. Ask to add conditions, restrict access, or modify permissions.
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        <div className="space-y-6">
          {!isRefining ? (
            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Permission Requirements
                </label>
                <textarea
                  value={request.description}
                  onChange={(e) => setRequest({ ...request, description: e.target.value })}
                  placeholder="E.g., 'IAM policy for read-only access to S3 bucket named company-documents'"
                  className="w-full h-32 px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:border-orange-500 focus:ring-1 focus:ring-orange-500 resize-none"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Primary AWS Service
                </label>
                <select
                  value={request.service}
                  onChange={(e) => setRequest({ ...request, service: e.target.value })}
                  className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-white focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
                  required
                >
                  <option value="">Select a service...</option>
                  {awsServices.map(service => (
                    <option key={service} value={service}>{service}</option>
                  ))}
                </select>
              </div>

              <div className="space-y-4">
                <div className="flex items-center space-x-3">
                  <input
                    id="restrictive"
                    type="checkbox"
                    checked={request.restrictive}
                    onChange={(e) => setRequest({ ...request, restrictive: e.target.checked })}
                    className="w-4 h-4 bg-slate-900 border-slate-600 rounded text-orange-500 focus:ring-orange-500 focus:ring-2"
                  />
                  <label htmlFor="restrictive" className="text-sm text-slate-300 flex items-center space-x-2">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    <span>Generate restrictive, least-privilege policy (recommended)</span>
                  </label>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Compliance Framework
                  </label>
                  <select
                    value={request.compliance}
                    onChange={(e) => setRequest({ ...request, compliance: e.target.value })}
                    className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-white focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
                  >
                    {complianceFrameworks.map(framework => (
                      <option key={framework.value} value={framework.value}>{framework.label}</option>
                    ))}
                  </select>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading || !request.description.trim()}
                className="w-full bg-gradient-to-r from-orange-500 to-orange-600 text-white py-3 px-6 rounded-lg font-medium hover:from-orange-600 hover:to-orange-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center justify-center space-x-2"
              >
                <Shield className="w-5 h-5" />
                <span>{loading ? 'Generating...' : 'Generate Secure Policy'}</span>
              </button>
            </form>
          ) : (
            <div className="space-y-4">
              <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4">
                <h3 className="text-green-400 font-medium mb-2">Policy Generated Successfully!</h3>
                <p className="text-slate-300 text-sm">
                  You can now refine this policy by asking follow-up questions or use the suggestions below.
                </p>
              </div>

              {response?.refinement_suggestions && response.refinement_suggestions.length > 0 && (
                <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
                  <h4 className="text-white font-medium mb-3">Suggested Refinements:</h4>
                  <div className="space-y-2">
                    {response.refinement_suggestions.map((suggestion, index) => (
                      <button
                        key={index}
                        onClick={() => handleRefinementClick(suggestion)}
                        className="w-full text-left px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-sm transition-colors"
                      >
                        {suggestion}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Refine Your Policy
                </label>
                <div className="flex space-x-2">
                  <input
                    type="text"
                    value={followUpMessage}
                    onChange={(e) => setFollowUpMessage(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleFollowUp()}
                    placeholder="E.g., 'Restrict to red-team/* prefix' or 'Add organization ID condition'"
                    className="flex-1 px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
                    disabled={loading}
                  />
                  <button
                    onClick={handleFollowUp}
                    disabled={loading || !followUpMessage.trim()}
                    className="px-4 py-3 bg-orange-500 hover:bg-orange-600 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    <Send className="w-5 h-5" />
                  </button>
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                <span className="text-red-400 font-medium">Error</span>
              </div>
              <p className="text-red-300 text-sm mt-1">{error}</p>
            </div>
          )}
        </div>

        <div className="space-y-6">
          {loading ? (
            <div className="bg-slate-900 border border-slate-700 rounded-lg h-96 flex items-center justify-center">
              <LoadingSpinner message="Analyzing requirements..." />
            </div>
          ) : response ? (
            <>
              <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
                <SecurityScore score={response.security_score} className="mb-4" />
                <div className="flex items-center space-x-4 text-sm">
                  <div className="flex items-center space-x-1">
                    <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                    <span className="text-slate-400">Least Privilege</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                    <span className="text-slate-400">Compliant</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
                    <span className="text-slate-400">AI Optimized</span>
                  </div>
                </div>
              </div>

              <div>
                <h3 className="text-lg font-semibold text-white mb-3 flex items-center space-x-2">
                  <Shield className="w-5 h-5 text-orange-500" />
                  <span>Generated IAM Policy</span>
                </h3>
                <CodeBlock 
                  code={JSON.stringify(response.policy, null, 2)}
                  filename="secure-iam-policy.json"
                />
              </div>

              <div className="space-y-4">
                <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
                  <h4 className="text-lg font-medium text-white mb-4 flex items-center space-x-2">
                    <Lightbulb className="w-5 h-5 text-yellow-400" />
                    <span>Policy Explanation</span>
                  </h4>
                  <div className="space-y-2">
                    {formatExplanation(response.explanation)}
                  </div>
                </div>

                {response.reasoning && (
                  <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
                    <h4 className="text-lg font-medium text-white mb-4 flex items-center space-x-2">
                      <Shield className="w-5 h-5 text-blue-400" />
                      <span>AI Agent Reasoning</span>
                    </h4>
                    <div className="space-y-4">
                      <div>
                        <h5 className="text-sm font-medium text-blue-400 mb-2">Planning Phase</h5>
                        <p className="text-slate-300 text-sm">{response.reasoning.plan}</p>
                      </div>
                      <div>
                        <h5 className="text-sm font-medium text-green-400 mb-2">Actions Taken</h5>
                        <ul className="space-y-1">
                          {response.reasoning.actions.map((action, index) => (
                            <li key={index} className="text-slate-300 text-sm flex items-start space-x-2">
                              <CheckCircle className="w-3 h-3 text-green-400 mt-0.5 flex-shrink-0" />
                              <span>{action}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <h5 className="text-sm font-medium text-purple-400 mb-2">Security Reflection</h5>
                        <p className="text-slate-300 text-sm">{response.reasoning.reflection}</p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="bg-slate-900 border border-slate-700 rounded-lg h-96 flex items-center justify-center">
              <div className="text-center">
                <Shield className="w-16 h-16 text-slate-600 mx-auto mb-4" />
                <h3 className="text-xl font-medium text-slate-400 mb-2">Ready for Security Analysis</h3>
                <p className="text-slate-500">Enter your permission requirements to generate a secure IAM policy</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default GeneratePolicy;