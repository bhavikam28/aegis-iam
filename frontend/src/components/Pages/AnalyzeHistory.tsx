import React, { useState } from 'react';
import { BarChart3, ArrowRight, CheckCircle, Sparkles, Shield } from 'lucide-react';

// Mock types for demo
interface AnalyzeHistoryResponse {
  risk_reduction: number;
  usage_summary: {
    total_permissions: number;
    used_permissions: number;
    unused_permissions: number;
    usage_percentage: number;
  };
  optimized_policy: object;
  implementation_steps: string[];
  security_improvements: string[];
}

const AnalyzeHistory: React.FC = () => {
  const [roleArn, setRoleArn] = useState('');
  const [dateRange, setDateRange] = useState('90');
  const [response, setResponse] = useState<AnalyzeHistoryResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const dateRanges = [
    { value: '30', label: '30 days' },
    { value: '60', label: '60 days' },
    { value: '90', label: '90 days' }
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!roleArn.trim()) return;

    setLoading(true);
    setError(null);

    // MOCK API CALL
    setTimeout(() => {
        setResponse({
            risk_reduction: 78,
            usage_summary: {
                total_permissions: 120,
                used_permissions: 26,
                unused_permissions: 94,
                usage_percentage: 22,
            },
            optimized_policy: {
                Version: "2012-10-17",
                Statement: [ { Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::specific-bucket/*" } ]
            },
            implementation_steps: [
                "Review the optimized policy to ensure it meets business needs.",
                "Create a new IAM policy version with the optimized JSON.",
                "Set the new policy version as the default for the role.",
                "Monitor application functionality after deployment."
            ],
            security_improvements: [
                "Reduced attack surface by removing 94 unused permissions.",
                "Enforced least privilege based on actual usage.",
                "Eliminated potential privilege escalation paths."
            ]
        });
        setLoading(false);
    }, 1500);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-purple-950/20 to-slate-950">
      {/* Background Elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-20 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-20 left-20 w-96 h-96 bg-pink-500/10 rounded-full blur-3xl"></div>
      </div>

      <div className="relative max-w-7xl mx-auto px-8 py-16">
        {/* Header */}
        <div className="mb-12">
          <div className="inline-flex items-center space-x-2 bg-purple-500/10 border border-purple-500/30 rounded-full px-6 py-2 mb-6">
            <Sparkles className="w-4 h-4 text-purple-400" />
            <span className="text-purple-300 text-sm font-medium">Usage Optimizer</span>
          </div>
          
          <h1 className="text-6xl font-bold mb-6">
            <span className="text-white">Analyze Historical</span>
            <br />
            <span className="bg-gradient-to-r from-orange-400 via-pink-400 to-purple-400 bg-clip-text text-transparent">
              Usage Patterns
            </span>
          </h1>
          
          <p className="text-xl text-slate-300 max-w-3xl leading-relaxed">
            Right-size IAM permissions based on actual CloudTrail usage data. Identify unused permissions 
            and generate optimized policies with dramatic risk reduction.
          </p>
        </div>

        {!response ? (
          /* Input Form */
          <div className="max-w-4xl mx-auto">
            <form onSubmit={handleSubmit}>
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-3xl p-10">
                {/* Role ARN Input */}
                <div className="mb-8">
                  <label className="block text-white text-lg font-semibold mb-4">IAM Role ARN</label>
                  <input
                    type="text"
                    value={roleArn}
                    onChange={(e) => setRoleArn(e.target.value)}
                    placeholder="arn:aws:iam::123456789012:role/MyRole"
                    className="w-full px-6 py-5 bg-slate-800/50 border border-slate-600/50 rounded-2xl text-white text-lg placeholder-slate-500 focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 focus:outline-none font-mono"
                    required
                  />
                  <p className="text-sm text-slate-500 mt-3">
                    Role must have CloudTrail logging enabled for accurate analysis
                  </p>
                </div>

                {/* Date Range Selection */}
                <div className="mb-8">
                  <label className="block text-white text-lg font-semibold mb-4">Analysis Period</label>
                  <div className="grid grid-cols-3 gap-4">
                    {dateRanges.map(range => (
                      <button
                        key={range.value}
                        type="button"
                        onClick={() => setDateRange(range.value)}
                        className={`px-6 py-4 rounded-2xl font-medium transition-all ${
                          dateRange === range.value
                            ? 'bg-gradient-to-r from-orange-500 via-pink-500 to-purple-600 text-white shadow-lg shadow-purple-500/25'
                            : 'bg-slate-800/50 text-slate-400 hover:text-white border border-slate-700/50'
                        }`}
                      >
                        Last {range.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled={loading || !roleArn.trim()}
                  className="w-full bg-gradient-to-r from-orange-500 via-pink-500 to-purple-600 text-white py-5 px-8 rounded-2xl font-semibold text-lg hover:from-orange-600 hover:via-pink-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-purple-500/25 hover:shadow-xl hover:shadow-purple-500/40 flex items-center justify-center space-x-3"
                >
                  {loading ? (
                    <>
                      <div className="w-6 h-6 border-3 border-white border-t-transparent rounded-full animate-spin"></div>
                      <span>Analyzing...</span>
                    </>
                  ) : (
                    <>
                      <BarChart3 className="w-6 h-6" />
                      <span>Start Security Analysis</span>
                      <Shield className="w-5 h-5" />
                    </>
                  )}
                </button>
              </div>
            </form>

            {error && (
              <div className="mt-6 bg-red-500/10 border border-red-500/30 rounded-2xl p-6">
                <p className="text-red-400">{error}</p>
              </div>
            )}
          </div>
        ) : (
          /* Results */
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Usage Summary - Large Card */}
            <div className="lg:col-span-3">
              <div className="bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8">
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <h3 className="text-white text-2xl font-bold mb-2">Permission Optimization Results</h3>
                    <p className="text-slate-400">Based on {dateRange} days of CloudTrail analysis</p>
                  </div>
                  <div className="text-center">
                    <div className="text-5xl font-bold text-green-400 mb-2">
                      {response.risk_reduction}%
                    </div>
                    <div className="text-slate-400 text-sm">Risk Reduction</div>
                  </div>
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-3 gap-6">
                  <div className="bg-slate-800/50 rounded-2xl p-6 text-center border border-slate-700/50">
                    <div className="text-4xl font-bold text-pink-400 mb-2">
                      {response.usage_summary.total_permissions}
                    </div>
                    <div className="text-slate-400 text-sm">Original Permissions</div>
                  </div>
                  
                  <div className="flex items-center justify-center">
                    <ArrowRight className="w-12 h-12 text-slate-400" />
                  </div>
                  
                  <div className="bg-gradient-to-br from-green-500/20 to-purple-500/20 rounded-2xl p-6 text-center border border-green-500/30">
                    <div className="text-4xl font-bold text-green-400 mb-2">
                      {response.usage_summary.used_permissions}
                    </div>
                    <div className="text-green-300 text-sm">Optimized Permissions</div>
                  </div>
                </div>

                {/* Progress Bar */}
                <div className="mt-6">
                  <div className="flex items-center justify-between text-sm mb-2">
                    <span className="text-slate-400">Usage Efficiency</span>
                    <span className="text-green-400 font-semibold">
                      {response.usage_summary.usage_percentage}%
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-4">
                    <div
                      className="bg-gradient-to-r from-green-500 to-purple-500 h-4 rounded-full transition-all duration-1000"
                      style={{ width: `${response.usage_summary.usage_percentage}%` }}
                    ></div>
                  </div>
                  <div className="flex justify-between text-sm mt-2">
                    <span className="text-pink-400">
                      {response.usage_summary.unused_permissions} unused
                    </span>
                    <span className="text-green-400">
                      {response.usage_summary.used_permissions} actively used
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Optimized Policy */}
            <div className="lg:col-span-2 bg-slate-900/50 backdrop-blur-xl border border-purple-500/20 rounded-2xl p-8">
               <h3 className="text-white text-2xl font-bold mb-4">Optimized IAM Policy</h3>
               <div className="bg-slate-900 border border-purple-500/20 rounded-2xl overflow-hidden">
                <div className="flex items-center justify-between px-6 py-4 border-b border-purple-500/20 bg-slate-800/50">
                    <span className="text-sm text-slate-400">optimized-iam-policy.json</span>
                    <button className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg text-sm text-white transition-all">
                        Copy
                    </button>
                </div>
                <div className="p-6 overflow-x-auto">
                    <pre className="text-sm text-slate-300 font-mono">
                        {JSON.stringify(response.optimized_policy, null, 2)}
                    </pre>
                </div>
               </div>
            </div>

            {/* Security Improvements & Actions */}
            <div className="space-y-6">
              {/* Security Improvements */}
              <div className="bg-gradient-to-br from-green-500/10 to-purple-500/10 backdrop-blur-xl border border-green-500/30 rounded-2xl p-8">
                <h4 className="text-green-400 text-xl font-bold mb-4">Security Improvements</h4>
                <ul className="space-y-3">
                  {response.security_improvements.map((improvement, index) => (
                    <li key={index} className="text-slate-300 text-sm flex items-start space-x-3">
                      <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                      <span>{improvement}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Implementation Steps */}
              <div className="bg-orange-500/10 backdrop-blur-xl border border-orange-500/30 rounded-2xl p-8">
                <h4 className="text-orange-400 text-xl font-bold mb-4">Implementation Guide</h4>
                <div className="space-y-4">
                  {response.implementation_steps.map((step, index) => (
                    <div key={index} className="flex items-start space-x-4">
                      <div className="w-8 h-8 bg-orange-500/20 text-orange-400 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0">
                        {index + 1}
                      </div>
                      <p className="text-slate-300 text-sm">{step}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* New Analysis Button */}
              <button
                onClick={() => setResponse(null)}
                className="w-full bg-slate-800 hover:bg-slate-700 text-white py-4 rounded-xl transition-all border border-slate-700"
              >
                Analyze Another Role
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AnalyzeHistory;
