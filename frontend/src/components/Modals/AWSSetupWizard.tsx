import React, { useState, useEffect } from 'react';
import { X, CheckCircle, Copy, ChevronRight, ChevronLeft, AlertCircle, RefreshCw, Terminal } from 'lucide-react';
import { checkCLICredentials } from '../../services/api';

interface AWSSetupWizardProps {
  isOpen: boolean;
  onClose: () => void;
  onComplete: (credentials: { access_key_id?: string; secret_access_key?: string; region: string }) => void;
}

const LEAST_PRIVILEGE_POLICY = JSON.stringify({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "iam:GetRole",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListRoles",
        "iam:ListAttachedRolePolicies",
        "iam:GetRolePolicy",
        "cloudtrail:LookupEvents",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}, null, 2);

const AWSSetupWizard: React.FC<AWSSetupWizardProps> = ({ isOpen, onClose, onComplete }) => {
  // AWS CLI-based authentication only (as recommended by mentor)
  const [currentStep, setCurrentStep] = useState(1);
  const [region, setRegion] = useState('us-east-1');
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [connectionError, setConnectionError] = useState('');
  const [cliCredentialsAvailable, setCliCredentialsAvailable] = useState<boolean | null>(null);
  const [checkingCliCredentials, setCheckingCliCredentials] = useState(false);
  const [cliCredentialInfo, setCliCredentialInfo] = useState<any>(null);

  const totalSteps = 3; // Simplified: Check credentials, Setup policy, Complete

  // Check CLI credentials when modal opens
  useEffect(() => {
    if (isOpen) {
      checkCLIAuth();
    }
  }, [isOpen, region]);

  const checkCLIAuth = async () => {
    setCheckingCliCredentials(true);
    try {
      const result = await checkCLICredentials(region);
      setCliCredentialsAvailable(result.available || false);
      setCliCredentialInfo(result);
      if (result.available && result.bedrock_available) {
        setConnectionStatus('success');
      } else if (result.available && !result.bedrock_available) {
        setConnectionStatus('error');
        setConnectionError(result.bedrock_error || 'Bedrock not available');
      }
    } catch (error: any) {
      setCliCredentialsAvailable(false);
      setConnectionStatus('error');
      setConnectionError(error.message || 'Failed to check CLI credentials');
    } finally {
      setCheckingCliCredentials(false);
    }
  };

  if (!isOpen) return null;

  const handleCopyPolicy = () => {
    navigator.clipboard.writeText(LEAST_PRIVILEGE_POLICY);
  };


  const handleComplete = () => {
    // For CLI auth, credentials are None - backend will use default chain
    if (cliCredentialsAvailable && connectionStatus === 'success') {
      onComplete({
        region
        // No access_key_id or secret_access_key for CLI auth
      });
      onClose();
    }
  };

  const handleNext = () => {
    if (currentStep < totalSteps) {
      setCurrentStep(currentStep + 1);
    }
  };

  const handlePrevious = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-md p-4">
      <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-white/95 backdrop-blur-xl rounded-3xl shadow-2xl border border-slate-200/50">
        {/* Header with gradient accent */}
        <div className="sticky top-0 z-10 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 px-8 py-5 rounded-t-3xl flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-white/20 rounded-xl flex items-center justify-center backdrop-blur-sm">
              <Terminal className="w-5 h-5 text-white" />
            </div>
            <h2 className="text-xl font-bold text-white">AWS Authentication</h2>
          </div>
          <button
            onClick={onClose}
            className="text-white hover:bg-white/20 rounded-lg p-2 transition-colors"
            aria-label="Close wizard"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Progress Bar */}
        <div className="px-8 py-4 bg-gradient-to-br from-slate-50 to-blue-50/30 border-b border-slate-200/50">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-semibold text-slate-700">
              Step {currentStep} of {totalSteps}
            </span>
            <span className="text-sm text-slate-500 font-medium">
              {Math.round((currentStep / totalSteps) * 100)}%
            </span>
          </div>
          <div className="w-full bg-slate-200/50 rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 h-full rounded-full transition-all duration-500"
              style={{ width: `${(currentStep / totalSteps) * 100}%` }}
            ></div>
          </div>
        </div>

        {/* Content */}
        <div className="px-8 py-8">
          {/* Step 1: CLI Credentials Check */}
          {currentStep === 1 && (
            <div className="space-y-6">
              {/* Credentials Status Card */}
              {checkingCliCredentials ? (
                <div className="relative bg-gradient-to-br from-slate-50 to-blue-50/30 border border-slate-200/50 rounded-2xl p-8 text-center">
                  <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-purple-500/5 to-pink-500/5 rounded-2xl"></div>
                  <div className="relative">
                    <div className="animate-spin rounded-full h-16 w-16 border-4 border-blue-200 border-t-blue-600 mx-auto mb-4"></div>
                    <p className="text-slate-700 font-semibold">Verifying credentials...</p>
                  </div>
                </div>
              ) : cliCredentialsAvailable === null ? (
                <div className="relative bg-gradient-to-br from-amber-50/50 to-orange-50/30 border border-amber-200/50 rounded-2xl p-8 text-center">
                  <div className="absolute inset-0 bg-gradient-to-br from-amber-500/5 via-orange-500/5 to-red-500/5 rounded-2xl"></div>
                  <div className="relative">
                    <div className="w-16 h-16 bg-amber-100 rounded-full flex items-center justify-center mx-auto mb-4">
                      <AlertCircle className="w-8 h-8 text-amber-600" />
                    </div>
                    <p className="text-slate-700 font-semibold mb-6">Verify AWS CLI configuration</p>
                    <button
                      onClick={checkCLIAuth}
                      className="px-8 py-3 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 text-white rounded-xl font-semibold hover:shadow-xl transition-all transform hover:scale-105"
                    >
                      <RefreshCw className="w-5 h-5 inline-block mr-2" />
                      Check Credentials
                    </button>
                  </div>
                </div>
              ) : cliCredentialsAvailable ? (
                <div className="relative bg-gradient-to-br from-emerald-50/50 to-green-50/30 border border-emerald-200/50 rounded-2xl p-6 overflow-hidden">
                  <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-200/20 rounded-full -mr-16 -mt-16 blur-2xl"></div>
                  <div className="relative">
                    <div className="flex items-start gap-4 mb-6">
                      <div className="w-12 h-12 bg-emerald-100 rounded-xl flex items-center justify-center flex-shrink-0">
                        <CheckCircle className="w-7 h-7 text-emerald-600" />
                      </div>
                      <div className="flex-1">
                        <h4 className="font-bold text-slate-900 mb-3 text-lg">Credentials Verified</h4>
                        {cliCredentialInfo && (
                          <div className="space-y-3">
                            <div className="flex items-center gap-2 text-sm text-slate-700">
                              <span className="font-medium text-slate-500">Account:</span>
                              <span className="font-mono">
                                {cliCredentialInfo.account_id 
                                  ? `${cliCredentialInfo.account_id.substring(0, 4)}****${cliCredentialInfo.account_id.substring(8)}`
                                  : 'N/A'}
                              </span>
                            </div>
                            <div className="flex items-center gap-2 text-sm text-slate-700">
                              <span className="font-medium text-slate-500">Method:</span>
                              <span>{cliCredentialInfo.method === 'aws_cli_or_env' ? 'AWS CLI' : cliCredentialInfo.method === 'iam_instance_profile' ? 'IAM Profile' : 'Default'}</span>
                            </div>
                            {cliCredentialInfo.bedrock_available ? (
                              <div className="flex items-center gap-2 text-sm text-emerald-700 font-medium">
                                <CheckCircle className="w-4 h-4" />
                                <span>Bedrock access confirmed</span>
                              </div>
                            ) : (
                              <div className="flex items-center gap-2 text-sm text-amber-700">
                                <AlertCircle className="w-4 h-4" />
                                <span>{cliCredentialInfo.bedrock_error || 'Bedrock access required'}</span>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                    <button
                      onClick={checkCLIAuth}
                      className="w-full px-4 py-2.5 bg-white/80 backdrop-blur-sm border border-emerald-300/50 text-emerald-700 rounded-xl font-medium hover:bg-emerald-50 transition-colors"
                    >
                      <RefreshCw className="w-4 h-4 inline-block mr-2" />
                      Refresh
                    </button>
                  </div>
                </div>
              ) : (
                <div className="relative bg-gradient-to-br from-red-50/50 to-rose-50/30 border border-red-200/50 rounded-2xl p-6">
                  <div className="absolute inset-0 bg-gradient-to-br from-red-500/5 via-rose-500/5 to-pink-500/5 rounded-2xl"></div>
                  <div className="relative">
                    <div className="flex items-start gap-4 mb-4">
                      <div className="w-12 h-12 bg-red-100 rounded-xl flex items-center justify-center flex-shrink-0">
                        <AlertCircle className="w-7 h-7 text-red-600" />
                      </div>
                      <div className="flex-1">
                        <h4 className="font-bold text-slate-900 mb-2">No Credentials Found</h4>
                        <p className="text-sm text-slate-600 mb-4">{connectionError || 'Configure AWS CLI first'}</p>
                        <div className="bg-white/80 backdrop-blur-sm border border-red-200/50 rounded-xl p-4 text-sm text-slate-700 space-y-2">
                          <p className="font-semibold text-slate-900 mb-2">Setup AWS CLI:</p>
                          <div className="space-y-1.5 font-mono text-xs bg-slate-50 rounded-lg p-3 border border-slate-200">
                            <div>$ pip install awscli</div>
                            <div>$ aws configure</div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Region Selection */}
              <div className="bg-gradient-to-br from-slate-50 to-blue-50/20 border border-slate-200/50 rounded-2xl p-6">
                <label className="block text-sm font-bold text-slate-900 mb-3 uppercase tracking-wide">AWS Region</label>
                <select
                  value={region}
                  onChange={(e) => {
                    setRegion(e.target.value);
                    if (cliCredentialsAvailable) {
                      checkCLIAuth();
                    }
                  }}
                  className="w-full px-4 py-3 bg-white border border-slate-300/50 rounded-xl text-slate-900 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all font-medium shadow-sm"
                >
                  <option value="us-east-1">us-east-1 (N. Virginia)</option>
                  <option value="us-west-2">us-west-2 (Oregon)</option>
                  <option value="eu-west-1">eu-west-1 (Ireland)</option>
                  <option value="ap-southeast-1">ap-southeast-1 (Singapore)</option>
                </select>
              </div>
            </div>
          )}

          {/* Step 2: IAM Policy Setup */}
          {currentStep === 2 && (
            <div className="space-y-6">
              <div className="text-center mb-6">
                <h3 className="text-2xl font-bold text-slate-900 mb-2">IAM Policy Configuration</h3>
                <p className="text-slate-600">Attach the required permissions to your IAM user</p>
              </div>

              <div className="relative bg-gradient-to-br from-slate-50 to-blue-50/20 border border-slate-200/50 rounded-2xl p-6 overflow-hidden">
                <div className="absolute top-0 right-0 w-40 h-40 bg-blue-200/10 rounded-full -mr-20 -mt-20 blur-3xl"></div>
                <div className="relative">
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="font-bold text-slate-900 text-lg">Required IAM Policy</h4>
                    <button
                      onClick={handleCopyPolicy}
                      className="px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg hover:shadow-lg transition-all flex items-center gap-2 text-sm font-medium"
                    >
                      <Copy className="w-4 h-4" />
                      Copy
                    </button>
                  </div>
                  <div className="bg-slate-900 rounded-xl p-5 mb-4 border border-slate-700 overflow-hidden">
                    <pre className="text-xs text-slate-200 overflow-x-auto font-mono leading-relaxed">{LEAST_PRIVILEGE_POLICY}</pre>
                  </div>
                  <div className="bg-white/80 backdrop-blur-sm border border-slate-200/50 rounded-xl p-4">
                    <p className="text-sm font-semibold text-slate-900 mb-3">Quick Steps:</p>
                    <ol className="space-y-2 text-sm text-slate-700">
                      <li className="flex items-start gap-2">
                        <span className="text-blue-600 font-bold">1.</span>
                        <span>Go to <a href="https://console.aws.amazon.com/iam/home#/users" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline font-medium">IAM → Users</a></span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-blue-600 font-bold">2.</span>
                        <span>Select your user → Add permissions</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-blue-600 font-bold">3.</span>
                        <span>Create policy → Paste the JSON above</span>
                      </li>
                    </ol>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Complete */}
          {currentStep === 3 && (
            <div className="space-y-6">
              <div className="text-center">
                <div className="relative w-24 h-24 mx-auto mb-6">
                  <div className="absolute inset-0 bg-gradient-to-br from-emerald-400 to-green-500 rounded-full blur-xl opacity-50"></div>
                  <div className="relative w-24 h-24 bg-gradient-to-br from-emerald-100 to-green-100 rounded-full flex items-center justify-center border-4 border-emerald-200">
                    <CheckCircle className="w-14 h-14 text-emerald-600" />
                  </div>
                </div>
                <h3 className="text-3xl font-bold text-slate-900 mb-3">Ready to Use</h3>
                <p className="text-slate-600 text-lg">
                  Your AWS credentials are configured
                </p>
              </div>

              {cliCredentialInfo && (
                <div className="relative bg-gradient-to-br from-slate-50 to-blue-50/20 border border-slate-200/50 rounded-2xl p-6 overflow-hidden">
                  <div className="absolute top-0 left-0 w-32 h-32 bg-blue-200/10 rounded-full -ml-16 -mt-16 blur-2xl"></div>
                  <div className="relative">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-slate-500 font-medium">Account</span>
                        <p className="text-slate-900 font-mono font-semibold mt-1">
                          {cliCredentialInfo.account_id 
                            ? `${cliCredentialInfo.account_id.substring(0, 4)}****${cliCredentialInfo.account_id.substring(8)}`
                            : 'N/A'}
                        </p>
                      </div>
                      <div>
                        <span className="text-slate-500 font-medium">Region</span>
                        <p className="text-slate-900 font-semibold mt-1">{region}</p>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}


        </div>

        {/* Footer Navigation */}
        <div className="sticky bottom-0 bg-gradient-to-b from-white to-slate-50/50 border-t border-slate-200/50 px-8 py-5 rounded-b-3xl flex items-center justify-between backdrop-blur-sm">
          <button
            onClick={handlePrevious}
            disabled={currentStep === 1}
            className="px-5 py-2.5 bg-slate-100 hover:bg-slate-200 disabled:opacity-30 disabled:cursor-not-allowed text-slate-700 rounded-xl font-semibold transition-all flex items-center gap-2 disabled:hover:bg-slate-100"
          >
            <ChevronLeft className="w-4 h-4" />
            Previous
          </button>

          <div className="flex gap-3">
            {currentStep < totalSteps ? (
              <button
                onClick={handleNext}
                disabled={(currentStep === 1 && !cliCredentialsAvailable) || (currentStep === 2 && connectionStatus !== 'success')}
                className="px-8 py-2.5 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 hover:from-blue-700 hover:via-purple-700 hover:to-pink-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl font-semibold transition-all shadow-lg hover:shadow-xl disabled:hover:shadow-lg flex items-center gap-2 transform hover:scale-105 disabled:hover:scale-100"
              >
                {currentStep === 1 ? 'Continue' : currentStep === 2 ? 'Complete' : 'Next'}
                <ChevronRight className="w-4 h-4" />
              </button>
            ) : (
              <button
                onClick={handleComplete}
                disabled={connectionStatus !== 'success'}
                className="px-8 py-2.5 bg-gradient-to-r from-emerald-600 via-green-600 to-teal-600 hover:from-emerald-700 hover:via-green-700 hover:to-teal-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl font-semibold transition-all shadow-lg hover:shadow-xl disabled:hover:shadow-lg flex items-center gap-2 transform hover:scale-105 disabled:hover:scale-100"
              >
                Get Started
                <CheckCircle className="w-5 h-5" />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AWSSetupWizard;



