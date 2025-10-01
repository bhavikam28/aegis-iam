import React, { useState } from 'react';
import { BarChart3, Clock, CheckCircle, TrendingDown, ArrowRight, Play, Pause } from 'lucide-react';
import LoadingSpinner from '../UI/LoadingSpinner';
import CodeBlock from '../UI/CodeBlock';
import { AnalyzeHistoryRequest, AnalyzeHistoryResponse, JobStatus } from '../../types';
import { analyzeHistory, getJobStatus } from '../../services/api';

const AnalyzeHistory: React.FC = () => {
  const [request, setRequest] = useState<AnalyzeHistoryRequest>({
    role_arn: '',
    date_range: '90'
  });
  const [response, setResponse] = useState<AnalyzeHistoryResponse | null>(null);
  const [jobStatus, setJobStatus] = useState<JobStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const dateRanges = [
    { value: '30', label: '30 days' },
    { value: '60', label: '60 days' },
    { value: '90', label: '90 days' }
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!request.role_arn.trim()) return;

    setLoading(true);
    setError(null);
    setJobStatus(null);

    try {
      // Start the analysis job
      const result = await analyzeHistory(request);
      
      if (result.job_id) {
        // If it's a long-running job, poll for status
        const job: JobStatus = {
          id: result.job_id,
          status: 'running',
          progress: 0,
          estimated_completion: '5-10 minutes',
          message: 'Analyzing CloudTrail logs and usage patterns...'
        };
        setJobStatus(job);
        pollJobStatus(result.job_id);
      } else {
        // If result is immediate
        setResponse(result);
        setLoading(false);
      }
    } catch (err) {
      setError('Failed to start usage analysis. Please verify the role ARN and try again.');
      setLoading(false);
    }
  };

  const pollJobStatus = async (jobId: string) => {
    const poll = async () => {
      try {
        const status = await getJobStatus(jobId);
        setJobStatus(status);

        if (status.status === 'completed') {
          // Simulate getting the final result
          const result = await analyzeHistory(request);
          setResponse(result);
          setLoading(false);
        } else if (status.status === 'failed') {
          setError('Analysis failed. Please try again.');
          setLoading(false);
        } else {
          setTimeout(poll, 2000); // Poll every 2 seconds
        }
      } catch (err) {
        setError('Failed to check job status.');
        setLoading(false);
      }
    };
    poll();
  };

  return (
    <div className="p-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center space-x-3 mb-4">
          <div className="w-12 h-12 bg-gradient-to-br from-purple-500 to-purple-600 rounded-lg flex items-center justify-center">
            <BarChart3 className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white">Analyze Historical Usage</h1>
            <p className="text-slate-400">Right-size permissions based on actual CloudTrail usage data</p>
          </div>
        </div>
        
        <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4">
          <div className="flex items-start space-x-3">
            <BarChart3 className="w-5 h-5 text-green-400 mt-0.5" />
            <div>
              <h3 className="text-green-400 font-medium">Historical Usage Optimizer</h3>
              <p className="text-slate-300 text-sm mt-1">
                Analyze CloudTrail logs to identify unused permissions and generate right-sized policies 
                with dramatic permission reductions while maintaining functionality.
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        {/* Input Form */}
        <div className="space-y-6">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Role ARN Input */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                IAM Role ARN
              </label>
              <input
                type="text"
                value={request.role_arn}
                onChange={(e) => setRequest({ ...request, role_arn: e.target.value })}
                placeholder="arn:aws:iam::123456789012:role/MyRole"
                className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:border-orange-500 focus:ring-1 focus:ring-orange-500 font-mono"
                required
              />
              <p className="text-xs text-slate-500 mt-1">
                The role must have CloudTrail logging enabled for accurate analysis
              </p>
            </div>

            {/* Date Range Selection */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Analysis Period
              </label>
              <select
                value={request.date_range}
                onChange={(e) => setRequest({ ...request, date_range: e.target.value })}
                className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-white focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
              >
                {dateRanges.map(range => (
                  <option key={range.value} value={range.value}>Last {range.label}</option>
                ))}
              </select>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading || !request.role_arn.trim()}
              className="w-full bg-gradient-to-r from-purple-500 to-purple-600 text-white py-3 px-6 rounded-lg font-medium hover:from-purple-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center justify-center space-x-2"
            >
              <BarChart3 className="w-5 h-5" />
              <span>{loading ? 'Starting Analysis...' : 'Start Security Analysis'}</span>
            </button>
          </form>

          {/* Error Display */}
          {error && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
              <div className="flex items-center space-x-2">
                <Clock className="w-5 h-5 text-red-400" />
                <span className="text-red-400 font-medium">Analysis Failed</span>
              </div>
              <p className="text-red-300 text-sm mt-1">{error}</p>
            </div>
          )}

          {/* Job Status */}
          {jobStatus && (
            <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-2">
                  <div className="flex items-center space-x-2">
                    {jobStatus.status === 'running' ? (
                      <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                    ) : (
                      <CheckCircle className="w-4 h-4 text-green-400" />
                    )}
                    <span className="text-blue-400 font-medium">
                      {jobStatus.status === 'running' ? 'Analysis Running' : 'Analysis Complete'}
                    </span>
                  </div>
                </div>
                <span className="text-xs text-slate-400">
                  ETA: {jobStatus.estimated_completion}
                </span>
              </div>
              
              <div className="w-full bg-slate-800 rounded-full h-2 mb-3">
                <div
                  className="bg-blue-500 h-2 rounded-full transition-all duration-1000"
                  style={{ width: `${jobStatus.progress}%` }}
                ></div>
              </div>
              
              <p className="text-blue-200 text-sm">{jobStatus.message}</p>
              
              {jobStatus.status === 'running' && (
                <div className="flex items-center space-x-2 mt-3 text-xs text-slate-400">
                  <Clock className="w-3 h-3" />
                  <span>Deep analysis in progress - examining CloudTrail logs and usage patterns</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Results */}
        <div className="space-y-6">
          {loading && !response ? (
            <div className="bg-slate-900 border border-slate-700 rounded-lg h-96 flex items-center justify-center">
              <LoadingSpinner message="Analyzing historical usage patterns and optimizing permissions..." />
            </div>
          ) : response ? (
            <>
              {/* Usage Summary */}
              <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center space-x-2">
                  <TrendingDown className="w-5 h-5 text-green-500" />
                  <span>Permission Optimization Results</span>
                </h3>
                
                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div className="bg-slate-800 rounded-lg p-4">
                    <div className="text-2xl font-bold text-white mb-1">
                      {response.usage_summary.total_permissions}
                    </div>
                    <div className="text-sm text-slate-400">Total Permissions</div>
                  </div>
                  <div className="bg-slate-800 rounded-lg p-4">
                    <div className="text-2xl font-bold text-green-400 mb-1">
                      {response.usage_summary.used_permissions}
                    </div>
                    <div className="text-sm text-slate-400">Actually Used</div>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">Usage Efficiency</span>
                    <span className="text-lg font-semibold text-green-400">
                      {response.usage_summary.usage_percentage}%
                    </span>
                  </div>
                  
                  <div className="w-full bg-slate-800 rounded-full h-3">
                    <div
                      className="bg-gradient-to-r from-green-500 to-green-400 h-3 rounded-full"
                      style={{ width: `${response.usage_summary.usage_percentage}%` }}
                    ></div>
                  </div>
                  
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-red-400">
                      {response.usage_summary.unused_permissions} unused permissions
                    </span>
                    <span className="text-green-400">
                      {response.risk_reduction}% risk reduction
                    </span>
                  </div>
                </div>
              </div>

              {/* Before/After Comparison */}
              <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Permission Reduction Impact</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="text-center p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                    <div className="text-3xl font-bold text-red-400 mb-2">
                      {response.usage_summary.total_permissions}
                    </div>
                    <div className="text-sm text-red-300">Original Permissions</div>
                  </div>
                  
                  <div className="flex items-center justify-center">
                    <ArrowRight className="w-8 h-8 text-slate-400" />
                  </div>
                  
                  <div className="text-center p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
                    <div className="text-3xl font-bold text-green-400 mb-2">
                      {response.usage_summary.used_permissions}
                    </div>
                    <div className="text-sm text-green-300">Optimized Permissions</div>
                  </div>
                </div>
              </div>

              {/* Optimized Policy */}
              <div>
                <h3 className="text-lg font-semibold text-white mb-3 flex items-center space-x-2">
                  <CheckCircle className="w-5 h-5 text-green-500" />
                  <span>Right-Sized IAM Policy</span>
                </h3>
                <CodeBlock 
                  code={JSON.stringify(response.optimized_policy, null, 2)}
                  filename="optimized-iam-policy.json"
                />
              </div>

              {/* Security Improvements */}
              {response.security_improvements.length > 0 && (
                <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-6">
                  <h3 className="text-lg font-medium text-green-400 mb-4 flex items-center space-x-2">
                    <CheckCircle className="w-5 h-5" />
                    <span>Security Improvements</span>
                  </h3>
                  <ul className="space-y-3">
                    {response.security_improvements.map((improvement, index) => (
                      <li key={index} className="text-green-200 text-sm flex items-start space-x-2">
                        <div className="w-1.5 h-1.5 bg-green-400 rounded-full mt-2 flex-shrink-0"></div>
                        <span>{improvement}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Implementation Steps */}
              {response.implementation_steps.length > 0 && (
                <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-6">
                  <h3 className="text-lg font-medium text-blue-400 mb-4 flex items-center space-x-2">
                    <Play className="w-5 h-5" />
                    <span>Implementation Guide</span>
                  </h3>
                  <div className="space-y-3">
                    {response.implementation_steps.map((step, index) => (
                      <div key={index} className="flex items-start space-x-3">
                        <div className="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-xs font-medium flex-shrink-0">
                          {index + 1}
                        </div>
                        <p className="text-blue-200 text-sm">{step}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="bg-slate-900 border border-slate-700 rounded-lg h-96 flex items-center justify-center">
              <div className="text-center">
                <BarChart3 className="w-16 h-16 text-slate-600 mx-auto mb-4" />
                <h3 className="text-xl font-medium text-slate-400 mb-2">Ready for Usage Analysis</h3>
                <p className="text-slate-500">Enter a role ARN to analyze historical usage and optimize permissions</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AnalyzeHistory;