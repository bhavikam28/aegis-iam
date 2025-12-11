import React, { useState } from 'react';
import { X, Key, Globe, AlertCircle, CheckCircle, ExternalLink } from 'lucide-react';

interface AWSConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (credentials: { access_key_id: string; secret_access_key: string; region: string }) => void;
  currentCredentials?: { access_key_id: string; secret_access_key: string; region: string } | null;
}

const AWS_REGIONS = [
  { value: 'us-east-1', label: 'US East (N. Virginia)' },
  { value: 'us-east-2', label: 'US East (Ohio)' },
  { value: 'us-west-1', label: 'US West (N. California)' },
  { value: 'us-west-2', label: 'US West (Oregon)' },
  { value: 'eu-west-1', label: 'Europe (Ireland)' },
  { value: 'eu-west-2', label: 'Europe (London)' },
  { value: 'eu-west-3', label: 'Europe (Paris)' },
  { value: 'eu-central-1', label: 'Europe (Frankfurt)' },
  { value: 'eu-north-1', label: 'Europe (Stockholm)' },
  { value: 'ap-northeast-1', label: 'Asia Pacific (Tokyo)' },
  { value: 'ap-northeast-2', label: 'Asia Pacific (Seoul)' },
  { value: 'ap-southeast-1', label: 'Asia Pacific (Singapore)' },
  { value: 'ap-southeast-2', label: 'Asia Pacific (Sydney)' },
  { value: 'ap-south-1', label: 'Asia Pacific (Mumbai)' },
  { value: 'ca-central-1', label: 'Canada (Central)' },
  { value: 'sa-east-1', label: 'South America (São Paulo)' },
];

const AWSConfigModal: React.FC<AWSConfigModalProps> = ({ isOpen, onClose, onSave, currentCredentials }) => {
  const [accessKeyId, setAccessKeyId] = useState(currentCredentials?.access_key_id || '');
  const [secretAccessKey, setSecretAccessKey] = useState(currentCredentials?.secret_access_key || '');
  const [region, setRegion] = useState(currentCredentials?.region || 'us-east-1');
  const [showSecret, setShowSecret] = useState(false);
  const [errors, setErrors] = useState<{ accessKeyId?: string; secretAccessKey?: string }>({});

  if (!isOpen) return null;

  const validate = () => {
    const newErrors: { accessKeyId?: string; secretAccessKey?: string } = {};

    // Validate Access Key ID (20 characters, alphanumeric, starts with AKIA)
    if (!accessKeyId) {
      newErrors.accessKeyId = 'Access Key ID is required';
    } else if (!/^AKIA[A-Z0-9]{16}$/.test(accessKeyId)) {
      newErrors.accessKeyId = 'Invalid format. Should be 20 characters starting with AKIA';
    }

    // Validate Secret Access Key (40 characters, alphanumeric + symbols)
    if (!secretAccessKey) {
      newErrors.secretAccessKey = 'Secret Access Key is required';
    } else if (secretAccessKey.length !== 40) {
      newErrors.secretAccessKey = 'Invalid format. Should be 40 characters';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSave = () => {
    if (validate()) {
      onSave({
        access_key_id: accessKeyId,
        secret_access_key: secretAccessKey,
        region,
      });
      onClose();
    }
  };

  const handleCancel = () => {
    // Reset form
    setAccessKeyId(currentCredentials?.access_key_id || '');
    setSecretAccessKey(currentCredentials?.secret_access_key || '');
    setRegion(currentCredentials?.region || 'us-east-1');
    setErrors({});
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm">
      <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 rounded-2xl shadow-2xl border border-gray-700">
        {/* Header */}
        <div className="sticky top-0 z-10 bg-gradient-to-r from-blue-600 to-purple-600 px-6 py-4 rounded-t-2xl flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Key className="w-6 h-6 text-white" />
            <h2 className="text-2xl font-bold text-white">AWS Credentials Configuration</h2>
          </div>
          <button
            onClick={handleCancel}
            className="text-white hover:bg-white/20 rounded-lg p-2 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="px-6 py-6 space-y-6">
          {/* Security Notice */}
          <div className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="text-sm font-semibold text-blue-300 mb-1">Your Credentials Are Secure</h3>
              <p className="text-xs text-blue-200/80 leading-relaxed">
                Your AWS credentials are <strong>never stored</strong> on our servers. They are used only for the duration 
                of your current session and are transmitted securely over HTTPS directly to AWS. We never log or persist 
                your credentials.
              </p>
            </div>
          </div>

          {/* AWS Setup Guide */}
          <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-gray-300 mb-2 flex items-center gap-2">
              <ExternalLink className="w-4 h-4" />
              Need AWS Credentials?
            </h3>
            <p className="text-xs text-gray-400 mb-3">
              Follow these steps to create an IAM user with programmatic access:
            </p>
            <ol className="text-xs text-gray-400 space-y-1.5 list-decimal list-inside">
              <li>Go to AWS Console → IAM → Users → Create User</li>
              <li>Enable "Programmatic access" (Access Key ID and Secret)</li>
              <li>Attach policies: <code className="text-xs bg-gray-700 px-1 py-0.5 rounded">IAMFullAccess</code>, <code className="text-xs bg-gray-700 px-1 py-0.5 rounded">AmazonBedrockFullAccess</code></li>
              <li>Download the credentials CSV file</li>
            </ol>
            <a
              href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 mt-3 transition-colors"
            >
              Read AWS IAM User Guide <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          {/* Form Fields */}
          <div className="space-y-4">
            {/* Access Key ID */}
            <div>
              <label htmlFor="accessKeyId" className="block text-sm font-medium text-gray-300 mb-2">
                Access Key ID <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                id="accessKeyId"
                value={accessKeyId}
                onChange={(e) => {
                  setAccessKeyId(e.target.value);
                  setErrors((prev) => ({ ...prev, accessKeyId: undefined }));
                }}
                placeholder="AKIAIOSFODNN7EXAMPLE"
                className={`w-full px-4 py-3 bg-gray-800 border ${
                  errors.accessKeyId ? 'border-red-500' : 'border-gray-600'
                } rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all font-mono text-sm`}
              />
              {errors.accessKeyId && (
                <p className="text-xs text-red-400 mt-1 flex items-center gap-1">
                  <AlertCircle className="w-3 h-3" />
                  {errors.accessKeyId}
                </p>
              )}
              <p className="text-xs text-gray-500 mt-1">
                Format: 20 characters starting with AKIA
              </p>
            </div>

            {/* Secret Access Key */}
            <div>
              <label htmlFor="secretAccessKey" className="block text-sm font-medium text-gray-300 mb-2">
                Secret Access Key <span className="text-red-400">*</span>
              </label>
              <div className="relative">
                <input
                  type={showSecret ? 'text' : 'password'}
                  id="secretAccessKey"
                  value={secretAccessKey}
                  onChange={(e) => {
                    setSecretAccessKey(e.target.value);
                    setErrors((prev) => ({ ...prev, secretAccessKey: undefined }));
                  }}
                  placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                  className={`w-full px-4 py-3 bg-gray-800 border ${
                    errors.secretAccessKey ? 'border-red-500' : 'border-gray-600'
                  } rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all font-mono text-sm pr-20`}
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-gray-400 hover:text-gray-300 transition-colors"
                >
                  {showSecret ? 'Hide' : 'Show'}
                </button>
              </div>
              {errors.secretAccessKey && (
                <p className="text-xs text-red-400 mt-1 flex items-center gap-1">
                  <AlertCircle className="w-3 h-3" />
                  {errors.secretAccessKey}
                </p>
              )}
              <p className="text-xs text-gray-500 mt-1">
                Format: 40 characters (alphanumeric + symbols)
              </p>
            </div>

            {/* Region */}
            <div>
              <label htmlFor="region" className="block text-sm font-medium text-gray-300 mb-2">
                <Globe className="w-4 h-4 inline-block mr-1" />
                AWS Region <span className="text-red-400">*</span>
              </label>
              <select
                id="region"
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                className="w-full px-4 py-3 bg-gray-800 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all"
              >
                {AWS_REGIONS.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Cost Warning */}
          <div className="bg-yellow-900/30 border border-yellow-500/50 rounded-lg p-4 flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="text-sm font-semibold text-yellow-300 mb-1">AWS Charges Apply</h3>
              <p className="text-xs text-yellow-200/80 leading-relaxed">
                Using Aegis IAM will invoke AWS Bedrock API calls on <strong>your AWS account</strong>. These calls incur 
                charges based on AWS Bedrock pricing (~$3-15 per 1M tokens). You are responsible for all AWS costs.
              </p>
            </div>
          </div>

          {/* Success Message (if reconfiguring) */}
          {currentCredentials && (
            <div className="bg-green-900/30 border border-green-500/50 rounded-lg p-4 flex items-start gap-3">
              <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <h3 className="text-sm font-semibold text-green-300 mb-1">Credentials Already Configured</h3>
                <p className="text-xs text-green-200/80">
                  You can update your credentials below and save to reconfigure.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 bg-gray-800/95 backdrop-blur-sm px-6 py-4 rounded-b-2xl flex items-center justify-between border-t border-gray-700">
          <button
            onClick={handleCancel}
            className="px-5 py-2.5 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors font-medium"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="px-5 py-2.5 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-lg transition-all font-medium shadow-lg"
          >
            Save & Continue
          </button>
        </div>
      </div>
    </div>
  );
};

export default AWSConfigModal;
