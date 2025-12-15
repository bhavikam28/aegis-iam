import React, { useState } from 'react';
import { X, CheckCircle, Copy, ChevronRight, ChevronLeft, AlertCircle, Key, ExternalLink, RefreshCw, Shield, ArrowRight } from 'lucide-react';
import { testAWSCredentials } from '../../services/api';

interface AWSSetupWizardProps {
  isOpen: boolean;
  onClose: () => void;
  onComplete: (credentials: { access_key_id: string; secret_access_key: string; region: string }) => void;
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
  const [currentStep, setCurrentStep] = useState(1);
  const [accessKeyId, setAccessKeyId] = useState('');
  const [secretAccessKey, setSecretAccessKey] = useState('');
  const [region, setRegion] = useState('us-east-1');
  const [showSecret, setShowSecret] = useState(false);
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [connectionError, setConnectionError] = useState('');

  const totalSteps = 5;

  if (!isOpen) return null;

  const handleCopyPolicy = () => {
    navigator.clipboard.writeText(LEAST_PRIVILEGE_POLICY);
  };

  const handleTestConnection = async () => {
    setTestingConnection(true);
    setConnectionStatus('testing');
    setConnectionError('');

    // Basic format validation
    if (accessKeyId.length < 16 || secretAccessKey.length < 20) {
      setConnectionStatus('error');
      setConnectionError('Invalid credential format. Access Key ID should be ~20 characters and Secret Key should be ~40 characters.');
      setTestingConnection(false);
      return;
    }

    try {
      const result = await testAWSCredentials({
        access_key_id: accessKeyId,
        secret_access_key: secretAccessKey,
        region: region
      });

      if (result.success) {
        if (result.bedrock_available) {
          setConnectionStatus('success');
        } else {
          // Credentials work but Bedrock is not available
          setConnectionStatus('error');
          setConnectionError(
            result.bedrock_error || 
            `Bedrock is not available in ${region} or you don't have permissions. Please ensure you attached the policy from Step 2.`
          );
        }
      } else {
        setConnectionStatus('error');
        setConnectionError(result.error || 'Failed to validate credentials.');
      }
    } catch (error: any) {
      setConnectionStatus('error');
      setConnectionError(error.message || 'Failed to validate credentials. Please check your network connection and try again.');
    } finally {
      setTestingConnection(false);
    }
  };

  const handleComplete = () => {
    if (accessKeyId && secretAccessKey && region) {
      onComplete({
        access_key_id: accessKeyId,
        secret_access_key: secretAccessKey,
        region
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto bg-white rounded-2xl shadow-2xl border-2 border-slate-200">
        {/* Header */}
        <div className="sticky top-0 z-10 bg-gradient-to-r from-blue-600 to-purple-600 px-6 py-4 rounded-t-2xl flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Key className="w-6 h-6 text-white" />
            <h2 className="text-xl font-bold text-white">AWS Setup Wizard</h2>
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
        <div className="px-6 py-4 bg-slate-50 border-b border-slate-200">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-semibold text-slate-700">
              Step {currentStep} of {totalSteps}
            </span>
            <span className="text-sm text-slate-500">
              {Math.round((currentStep / totalSteps) * 100)}% Complete
            </span>
          </div>
          <div className="w-full bg-slate-200 rounded-full h-2">
            <div
              className="bg-gradient-to-r from-blue-600 to-purple-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${(currentStep / totalSteps) * 100}%` }}
            ></div>
          </div>
        </div>

        {/* Content */}
        <div className="px-6 py-8">
          {/* Step 1: Overview */}
          {currentStep === 1 && (
            <div className="space-y-6">
              <div className="text-center">
                <h3 className="text-2xl font-bold text-slate-900 mb-4">One-Time Setup Overview</h3>
                <p className="text-slate-600 text-lg mb-6">
                  You'll need about 5 minutes to set up AWS access. Don't worry—we'll guide you through each step.
                </p>
              </div>

              <div className="bg-blue-50 border-2 border-blue-200 rounded-xl p-6 space-y-4">
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-6 h-6 text-blue-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <h4 className="font-semibold text-blue-900 mb-1">You'll use YOUR AWS account</h4>
                    <p className="text-sm text-blue-700">We never see your data. All AWS calls go directly from your browser to AWS.</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-6 h-6 text-blue-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <h4 className="font-semibold text-blue-900 mb-1">You pay only for what you use</h4>
                    <p className="text-sm text-blue-700">AWS charges ~$0.01-0.10 per policy generation (Bedrock usage). No subscription fees.</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-6 h-6 text-blue-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <h4 className="font-semibold text-blue-900 mb-1">Your credentials stay in your browser</h4>
                    <p className="text-sm text-blue-700">Credentials are never stored on our servers. They're cleared when you close the tab.</p>
                  </div>
                </div>
              </div>

              <div className="bg-slate-50 border-2 border-slate-200 rounded-xl p-6">
                <h4 className="font-semibold text-slate-900 mb-3">What you'll do:</h4>
                <ol className="space-y-3 text-slate-700">
                  <li className="flex items-start gap-3">
                    <span className="font-bold text-blue-600">1.</span>
                    <span>Create an IAM user in AWS Console (we'll show you exactly how)</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <span className="font-bold text-blue-600">2.</span>
                    <span>Attach a minimal security policy (we'll give you the exact policy to use)</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <span className="font-bold text-blue-600">3.</span>
                    <span>Create an access key and paste it here</span>
                  </li>
                </ol>
              </div>
            </div>
          )}

          {/* Step 2: Create IAM User */}
          {currentStep === 2 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-2xl font-bold text-slate-900 mb-2">Step 1 of 3: Create an IAM User</h3>
                <p className="text-slate-600 mb-6">
                  Open AWS Console in a new tab, then follow these steps:
                </p>
              </div>

              <div className="bg-slate-50 border-2 border-slate-200 rounded-xl p-6 space-y-4">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold flex-shrink-0">1</div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-slate-900 mb-1">Go to IAM → Users → Create User</h4>
                    <a
                      href="https://console.aws.amazon.com/iam/home#/users"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-sm text-blue-600 hover:text-blue-700 font-medium mt-1"
                    >
                      Open AWS IAM Console <ExternalLink className="w-4 h-4" />
                    </a>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold flex-shrink-0">2</div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-slate-900 mb-1">Name your user</h4>
                    <p className="text-sm text-slate-600">We suggest: <code className="bg-white px-2 py-1 rounded border border-slate-300 font-mono text-sm">aegis-iam-user</code></p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold flex-shrink-0">3</div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-slate-900 mb-1">Enable "Access key - Programmatic access"</h4>
                    <p className="text-sm text-slate-600">This is required for API access. Don't enable console access.</p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold flex-shrink-0">4</div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-slate-900 mb-1">Attach this policy</h4>
                    <p className="text-sm text-slate-600 mb-2">Click "Create policy" → JSON tab → Paste this:</p>
                    <div className="relative">
                      <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg text-xs overflow-x-auto border-2 border-slate-700">
                        {LEAST_PRIVILEGE_POLICY}
                      </pre>
                      <button
                        onClick={handleCopyPolicy}
                        className="absolute top-2 right-2 bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1 transition-colors"
                      >
                        <Copy className="w-3 h-3" />
                        Copy Policy
                      </button>
                    </div>
                    <p className="text-xs text-slate-500 mt-2">
                      ⚠️ This is a least-privilege policy (only what Aegis needs). Much safer than admin access!
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold flex-shrink-0">5</div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-slate-900 mb-1">Create and save your access keys</h4>
                    <p className="text-sm text-slate-600">Download the CSV or copy both keys immediately. The secret key won't be shown again!</p>
                  </div>
                </div>
              </div>

              <div className="bg-amber-50 border-2 border-amber-200 rounded-xl p-4">
                <div className="flex items-start gap-3">
                  <AlertCircle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <h4 className="font-semibold text-amber-900 mb-1">Pro Tip</h4>
                    <p className="text-sm text-amber-700">
                      We're using a least-privilege policy (only the permissions Aegis needs). This is much safer than giving admin access. 
                      If you see guides suggesting <code className="bg-white px-1.5 py-0.5 rounded border border-amber-300 font-mono text-xs">IAMFullAccess</code>, 
                      ignore them—you don't need that much permission.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Enter Credentials */}
          {currentStep === 3 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-2xl font-bold text-slate-900 mb-2">Step 2 of 3: Enter Your Credentials</h3>
                <p className="text-slate-600 mb-6">
                  Paste the Access Key ID and Secret Access Key you just created:
                </p>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-semibold text-slate-900 mb-2">
                    AWS Region <span className="text-red-500">*</span>
                  </label>
                  <select
                    value={region}
                    onChange={(e) => setRegion(e.target.value)}
                    className="w-full px-4 py-3 bg-white border-2 border-slate-300 rounded-xl text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all font-medium"
                  >
                    <optgroup label="Recommended (Bedrock Available)">
                      <option value="us-east-1">us-east-1 - US East (N. Virginia)</option>
                      <option value="us-west-2">us-west-2 - US West (Oregon)</option>
                      <option value="eu-west-1">eu-west-1 - Europe (Ireland)</option>
                    </optgroup>
                    <optgroup label="Other Bedrock Regions">
                      <option value="ap-southeast-1">ap-southeast-1 - Asia Pacific (Singapore)</option>
                      <option value="ap-northeast-1">ap-northeast-1 - Asia Pacific (Tokyo)</option>
                    </optgroup>
                  </select>
                  <p className="text-xs text-slate-500 mt-1.5">Select a region where Bedrock is available</p>
                </div>

                <div>
                  <label className="block text-sm font-semibold text-slate-900 mb-2">
                    Access Key ID <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={accessKeyId}
                    onChange={(e) => setAccessKeyId(e.target.value)}
                    placeholder="AKIAIOSFODNN7EXAMPLE"
                    className="w-full px-4 py-3 bg-white border-2 border-slate-300 rounded-xl text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all font-mono text-sm"
                  />
                  <p className="text-xs text-slate-500 mt-1.5">Format: 20 characters starting with AKIA</p>
                </div>

                <div>
                  <label className="block text-sm font-semibold text-slate-900 mb-2">
                    Secret Access Key <span className="text-red-500">*</span>
                  </label>
                  <div className="relative">
                    <input
                      type={showSecret ? 'text' : 'password'}
                      value={secretAccessKey}
                      onChange={(e) => setSecretAccessKey(e.target.value)}
                      placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                      className="w-full px-4 py-3 pr-20 bg-white border-2 border-slate-300 rounded-xl text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all font-mono text-sm"
                    />
                    <button
                      type="button"
                      onClick={() => setShowSecret(!showSecret)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-xs font-medium text-blue-600 hover:text-blue-700 transition-colors"
                    >
                      {showSecret ? 'Hide' : 'Show'}
                    </button>
                  </div>
                  <p className="text-xs text-slate-500 mt-1.5">Format: 40 characters (alphanumeric + symbols)</p>
                </div>

                <div className="bg-blue-50 border-2 border-blue-200 rounded-xl p-4">
                  <div className="flex items-start gap-3">
                    <Shield className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
                    <div>
                      <h4 className="font-semibold text-blue-900 mb-1">Your Credentials Are Secure</h4>
                      <ul className="text-xs text-blue-700 space-y-1">
                        <li>✓ Encrypted in transit (HTTPS)</li>
                        <li>✓ Stored only in browser memory</li>
                        <li>✓ Cleared when you close the tab</li>
                        <li>✓ Never logged or persisted</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Step 4: Test Connection */}
          {currentStep === 4 && (
            <div className="space-y-6">
              <div>
                <h3 className="text-2xl font-bold text-slate-900 mb-2">Step 3 of 3: Test Connection</h3>
                <p className="text-slate-600 mb-6">
                  Let's verify your credentials work correctly:
                </p>
              </div>

              <div className="bg-slate-50 border-2 border-slate-200 rounded-xl p-8">
                {connectionStatus === 'idle' && (
                  <div className="text-center">
                    <Key className="w-16 h-16 text-slate-400 mx-auto mb-4" />
                    <p className="text-slate-600 mb-6">Click the button below to test your AWS connection</p>
                    <button
                      onClick={handleTestConnection}
                      className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-xl font-semibold transition-all shadow-lg hover:shadow-xl"
                    >
                      Test Connection
                    </button>
                  </div>
                )}

                {connectionStatus === 'testing' && (
                  <div className="text-center">
                    <RefreshCw className="w-16 h-16 text-blue-600 mx-auto mb-4 animate-spin" />
                    <p className="text-slate-700 font-medium">Testing your credentials...</p>
                    <p className="text-sm text-slate-500 mt-2">This may take a few seconds</p>
                  </div>
                )}

                {connectionStatus === 'success' && (
                  <div className="text-center">
                    <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                      <CheckCircle className="w-10 h-10 text-green-600" />
                    </div>
                    <h4 className="text-xl font-bold text-green-700 mb-2">Connection Successful!</h4>
                    <div className="space-y-2 text-sm text-slate-600">
                      <p>✓ AWS credentials valid</p>
                      <p>✓ Region {region} configured</p>
                      <p>✓ Ready to use Aegis IAM</p>
                    </div>
                  </div>
                )}

                {connectionStatus === 'error' && (
                  <div className="text-center">
                    <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                      <AlertCircle className="w-10 h-10 text-red-600" />
                    </div>
                    <h4 className="text-xl font-bold text-red-700 mb-2">Connection Failed</h4>
                    <p className="text-red-600 mb-4">{connectionError || 'Failed to validate credentials'}</p>
                    <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-left text-sm text-red-700 space-y-2">
                      <p className="font-semibold">Common issues:</p>
                      <ul className="list-disc list-inside space-y-1 ml-2">
                        <li>Wrong region? (Bedrock is only in us-east-1, us-west-2, eu-west-1)</li>
                        <li>Missing Bedrock permissions? Make sure you attached the policy from Step 2</li>
                        <li>Invalid credentials? Generate new access keys in AWS Console</li>
                      </ul>
                    </div>
                    <button
                      onClick={handleTestConnection}
                      className="mt-4 px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-xl font-semibold transition-all shadow-lg hover:shadow-xl"
                    >
                      Retry Test
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Step 5: Complete */}
          {currentStep === 5 && (
            <div className="space-y-6 text-center">
              <div className="w-20 h-20 bg-gradient-to-br from-green-400 to-blue-500 rounded-full flex items-center justify-center mx-auto mb-6">
                <CheckCircle className="w-12 h-12 text-white" />
              </div>
              <h3 className="text-3xl font-bold text-slate-900 mb-4">You're All Set!</h3>
              <p className="text-lg text-slate-600 mb-8">
                Your AWS account is connected. You can now generate, validate, and audit IAM policies using your real AWS infrastructure.
              </p>

              <div className="bg-gradient-to-r from-blue-50 to-purple-50 border-2 border-blue-200 rounded-xl p-6">
                <h4 className="font-semibold text-slate-900 mb-3">Try this sample prompt:</h4>
                <div className="bg-white rounded-lg p-4 border-2 border-slate-200 mb-4">
                  <p className="text-slate-700 italic">
                    "Create a Lambda execution role with S3 read access and CloudWatch Logs write permissions"
                  </p>
                </div>
                <p className="text-sm text-slate-600">
                  This will generate a complete IAM policy with security analysis—all powered by Claude AI.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Footer Navigation */}
        <div className="sticky bottom-0 bg-white border-t border-slate-200 px-6 py-4 rounded-b-2xl flex items-center justify-between">
          <button
            onClick={handlePrevious}
            disabled={currentStep === 1}
            className="px-4 py-2 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 disabled:cursor-not-allowed text-slate-700 rounded-lg font-semibold transition-colors flex items-center gap-2"
          >
            <ChevronLeft className="w-4 h-4" />
            Previous
          </button>

          <div className="flex gap-2">
            {currentStep < totalSteps ? (
              <button
                onClick={handleNext}
                disabled={currentStep === 4 && connectionStatus !== 'success'}
                className="px-6 py-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-semibold transition-all shadow-lg hover:shadow-xl flex items-center gap-2"
              >
                {currentStep === 3 ? 'Test Connection' : currentStep === 4 ? 'Continue' : 'Next'}
                {currentStep !== 3 && currentStep !== 4 && <ChevronRight className="w-4 h-4" />}
              </button>
            ) : (
              <button
                onClick={handleComplete}
                className="px-8 py-2 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white rounded-lg font-semibold transition-all shadow-lg hover:shadow-xl flex items-center gap-2"
              >
                Start Using Aegis IAM
                <ArrowRight className="w-5 h-5" />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AWSSetupWizard;



