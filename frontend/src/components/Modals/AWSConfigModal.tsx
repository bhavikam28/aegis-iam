import React, { useState } from 'react';
import { X, Key, Globe, AlertCircle, CheckCircle, ExternalLink } from 'lucide-react';

interface AWSConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (credentials: { access_key_id: string; secret_access_key: string; region: string }) => void;
  currentCredentials?: { access_key_id: string; secret_access_key: string; region: string } | null;
}

const AWS_REGIONS = [
  // US Regions
  { value: 'us-east-1', label: 'us-east-1 - US East (N. Virginia)' },
  { value: 'us-east-2', label: 'us-east-2 - US East (Ohio)' },
  { value: 'us-west-1', label: 'us-west-1 - US West (N. California)' },
  { value: 'us-west-2', label: 'us-west-2 - US West (Oregon)' },
  // AWS GovCloud (US) Regions
  { value: 'us-gov-east-1', label: 'us-gov-east-1 - AWS GovCloud (US-East)' },
  { value: 'us-gov-west-1', label: 'us-gov-west-1 - AWS GovCloud (US-West)' },
  // Europe Regions
  { value: 'eu-west-1', label: 'eu-west-1 - Europe (Ireland)' },
  { value: 'eu-west-2', label: 'eu-west-2 - Europe (London)' },
  { value: 'eu-west-3', label: 'eu-west-3 - Europe (Paris)' },
  { value: 'eu-central-1', label: 'eu-central-1 - Europe (Frankfurt)' },
  { value: 'eu-central-2', label: 'eu-central-2 - Europe (Zurich)' },
  { value: 'eu-north-1', label: 'eu-north-1 - Europe (Stockholm)' },
  { value: 'eu-south-1', label: 'eu-south-1 - Europe (Milan)' },
  { value: 'eu-south-2', label: 'eu-south-2 - Europe (Spain)' },
  // Asia Pacific Regions
  { value: 'ap-south-1', label: 'ap-south-1 - Asia Pacific (Mumbai)' },
  { value: 'ap-south-2', label: 'ap-south-2 - Asia Pacific (Hyderabad)' },
  { value: 'ap-southeast-1', label: 'ap-southeast-1 - Asia Pacific (Singapore)' },
  { value: 'ap-southeast-2', label: 'ap-southeast-2 - Asia Pacific (Sydney)' },
  { value: 'ap-southeast-3', label: 'ap-southeast-3 - Asia Pacific (Jakarta)' },
  { value: 'ap-southeast-4', label: 'ap-southeast-4 - Asia Pacific (Melbourne)' },
  { value: 'ap-southeast-5', label: 'ap-southeast-5 - Asia Pacific (Malaysia)' },
  { value: 'ap-southeast-6', label: 'ap-southeast-6 - Asia Pacific (New Zealand)' },
  { value: 'ap-southeast-7', label: 'ap-southeast-7 - Asia Pacific (Thailand)' },
  { value: 'ap-northeast-1', label: 'ap-northeast-1 - Asia Pacific (Tokyo)' },
  { value: 'ap-northeast-2', label: 'ap-northeast-2 - Asia Pacific (Seoul)' },
  { value: 'ap-northeast-3', label: 'ap-northeast-3 - Asia Pacific (Osaka)' },
  { value: 'ap-east-1', label: 'ap-east-1 - Asia Pacific (Hong Kong)' },
  { value: 'ap-east-2', label: 'ap-east-2 - Asia Pacific (Taipei)' },
  // Canada Regions
  { value: 'ca-central-1', label: 'ca-central-1 - Canada (Central)' },
  { value: 'ca-west-1', label: 'ca-west-1 - Canada West (Calgary)' },
  // South America Regions
  { value: 'sa-east-1', label: 'sa-east-1 - South America (São Paulo)' },
  // Africa Regions
  { value: 'af-south-1', label: 'af-south-1 - Africa (Cape Town)' },
  // Middle East Regions
  { value: 'me-south-1', label: 'me-south-1 - Middle East (Bahrain)' },
  { value: 'me-central-1', label: 'me-central-1 - Middle East (UAE)' },
  { value: 'il-central-1', label: 'il-central-1 - Israel (Tel Aviv)' },
  // Mexico Regions
  { value: 'mx-central-1', label: 'mx-central-1 - Mexico (Central)' },
  // China Regions (Special)
  { value: 'cn-north-1', label: 'cn-north-1 - China (Beijing)' },
  { value: 'cn-northwest-1', label: 'cn-northwest-1 - China (Ningxia)' },
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-white rounded-2xl shadow-2xl border-2 border-slate-200">
        {/* Header */}
        <div className="sticky top-0 z-10 bg-gradient-to-r from-blue-600 to-purple-600 px-4 sm:px-6 py-4 rounded-t-2xl flex items-center justify-between">
          <div className="flex items-center gap-2 sm:gap-3 flex-1 min-w-0">
            <Key className="w-5 h-5 sm:w-6 sm:h-6 text-white flex-shrink-0" />
            <h2 className="text-lg sm:text-xl lg:text-2xl font-bold text-white truncate">AWS Credentials Configuration</h2>
          </div>
          <button
            onClick={handleCancel}
            className="text-white hover:bg-white/20 rounded-lg p-2 transition-colors flex-shrink-0 min-w-[44px] min-h-[44px] flex items-center justify-center"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="px-4 sm:px-6 py-6 space-y-6">
          {/* Security Notice */}
          <div className="bg-blue-50 border-2 border-blue-200 rounded-xl p-4 flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="text-sm font-semibold text-blue-900 mb-1">Your Credentials Are Secure</h3>
              <p className="text-xs text-slate-700 leading-relaxed">
                Your AWS credentials are <strong className="text-blue-900">never stored</strong> on our servers. They are used only for the duration 
                of your current session and are transmitted securely over HTTPS directly to AWS. We never log or persist 
                your credentials.
              </p>
            </div>
          </div>

          {/* AWS Setup Guide */}
          <div className="bg-slate-50 border-2 border-slate-200 rounded-xl p-4">
            <h3 className="text-sm font-semibold text-slate-900 mb-2 flex items-center gap-2">
              <ExternalLink className="w-4 h-4 text-slate-700" />
              Need AWS Credentials?
            </h3>
            <p className="text-xs text-slate-600 mb-3">
              Follow these steps to create an IAM user with programmatic access:
            </p>
            <ol className="text-xs text-slate-600 space-y-1.5 list-decimal list-inside">
              <li>Go to AWS Console → IAM → Users → Create User</li>
              <li>Enable "Programmatic access" (Access Key ID and Secret)</li>
              <li>Attach policies: <code className="text-xs bg-white border border-slate-300 px-2 py-0.5 rounded text-slate-900 font-mono">IAMFullAccess</code>, <code className="text-xs bg-white border border-slate-300 px-2 py-0.5 rounded text-slate-900 font-mono">AmazonBedrockFullAccess</code></li>
              <li>Download the credentials CSV file</li>
            </ol>
            <a
              href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-xs text-blue-600 hover:text-blue-700 font-medium mt-3 transition-colors"
            >
              Read AWS IAM User Guide <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          {/* Form Fields */}
          <div className="space-y-4">
            {/* Access Key ID */}
            <div>
              <label htmlFor="accessKeyId" className="block text-sm font-semibold text-slate-900 mb-2">
                Access Key ID <span className="text-red-500">*</span>
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
                className={`w-full px-4 py-3 bg-white border-2 ${
                  errors.accessKeyId ? 'border-red-400' : 'border-slate-300'
                } rounded-xl text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all font-mono text-sm`}
              />
              {errors.accessKeyId && (
                <p className="text-xs text-red-600 mt-1.5 flex items-center gap-1 font-medium">
                  <AlertCircle className="w-3 h-3" />
                  {errors.accessKeyId}
                </p>
              )}
              <p className="text-xs text-slate-500 mt-1.5">
                Format: 20 characters starting with AKIA
              </p>
            </div>

            {/* Secret Access Key */}
            <div>
              <label htmlFor="secretAccessKey" className="block text-sm font-semibold text-slate-900 mb-2">
                Secret Access Key <span className="text-red-500">*</span>
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
                  className={`w-full px-4 py-3 bg-white border-2 ${
                    errors.secretAccessKey ? 'border-red-400' : 'border-slate-300'
                  } rounded-xl text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all font-mono text-sm pr-20`}
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-xs font-medium text-blue-600 hover:text-blue-700 transition-colors"
                >
                  {showSecret ? 'Hide' : 'Show'}
                </button>
              </div>
              {errors.secretAccessKey && (
                <p className="text-xs text-red-600 mt-1.5 flex items-center gap-1 font-medium">
                  <AlertCircle className="w-3 h-3" />
                  {errors.secretAccessKey}
                </p>
              )}
              <p className="text-xs text-slate-500 mt-1.5">
                Format: 40 characters (alphanumeric + symbols)
              </p>
            </div>

            {/* Region */}
            <div>
              <label htmlFor="region" className="block text-sm font-semibold text-slate-900 mb-2">
                <Globe className="w-4 h-4 inline-block mr-1 text-slate-700" />
                AWS Region <span className="text-red-500">*</span>
              </label>
              <select
                id="region"
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                className="w-full px-4 py-3 bg-white border-2 border-slate-300 rounded-xl text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all font-medium"
              >
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
                  <option value="eu-central-2">eu-central-2 - Europe (Zurich)</option>
                  <option value="eu-north-1">eu-north-1 - Europe (Stockholm)</option>
                  <option value="eu-south-1">eu-south-1 - Europe (Milan)</option>
                  <option value="eu-south-2">eu-south-2 - Europe (Spain)</option>
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
            </div>
          </div>

          {/* Cost Warning */}
          <div className="bg-amber-50 border-2 border-amber-300 rounded-xl p-4 flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="text-sm font-semibold text-amber-900 mb-1">AWS Charges Apply</h3>
              <p className="text-xs text-slate-700 leading-relaxed">
                Using Aegis IAM will invoke AWS Bedrock API calls on <strong className="text-amber-900">your AWS account</strong>. These calls incur 
                charges based on AWS Bedrock pricing (~$3-15 per 1M tokens). You are responsible for all AWS costs.
              </p>
            </div>
          </div>

          {/* Success Message (if reconfiguring) */}
          {currentCredentials && (
            <div className="bg-emerald-50 border-2 border-emerald-300 rounded-xl p-4 flex items-start gap-3">
              <CheckCircle className="w-5 h-5 text-emerald-600 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <h3 className="text-sm font-semibold text-emerald-900 mb-1">Credentials Already Configured</h3>
                <p className="text-xs text-slate-700">
                  You can update your credentials below and save to reconfigure.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 bg-slate-50 border-t-2 border-slate-200 px-4 sm:px-6 py-4 rounded-b-2xl flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 sm:gap-0">
          <button
            onClick={handleCancel}
            className="px-6 py-3 sm:py-2.5 bg-white border-2 border-slate-300 hover:border-slate-400 hover:bg-slate-50 text-slate-700 rounded-xl transition-all font-semibold min-h-[44px] touch-manipulation"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="px-6 py-3 sm:py-2.5 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-xl transition-all font-semibold shadow-lg hover:shadow-xl min-h-[44px] touch-manipulation"
          >
            Save & Continue
          </button>
        </div>
      </div>
    </div>
  );
};

export default AWSConfigModal;
