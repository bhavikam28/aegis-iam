import React, { useState } from 'react';
import { X, Shield, Lock, AlertTriangle, CheckCircle, ExternalLink } from 'lucide-react';

interface AWSConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (credentials: AWSCredentials) => void;
}

export interface AWSCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
}

const AWSConfigModal: React.FC<AWSConfigModalProps> = ({ isOpen, onClose, onSubmit }) => {
  const [credentials, setCredentials] = useState<AWSCredentials>({
    accessKeyId: '',
    secretAccessKey: '',
    region: 'us-east-1'
  });
  
  const [showSecret, setShowSecret] = useState(false);
  const [agreed, setAgreed] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!agreed) {
      alert('Please acknowledge the security notice');
      return;
    }
    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      alert('Please enter both Access Key ID and Secret Access Key');
      return;
    }
    onSubmit(credentials);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white rounded-3xl shadow-2xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-600 to-purple-600 text-white p-6 rounded-t-3xl relative">
          <button
            onClick={onClose}
            className="absolute top-4 right-4 text-white/80 hover:text-white transition-colors"
          >
            <X className="w-6 h-6" />
          </button>
          <div className="flex items-center space-x-3">
            <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-2xl font-bold">AWS Configuration</h2>
              <p className="text-blue-100 text-sm">Secure credential management</p>
            </div>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {/* Security Notice */}
          <div className="bg-gradient-to-r from-emerald-50 to-green-50 border-2 border-emerald-200 rounded-xl p-4">
            <div className="flex items-start space-x-3">
              <Lock className="w-5 h-5 text-emerald-600 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <h3 className="font-bold text-emerald-900 mb-2">🔒 Your Security is Our Priority</h3>
                <ul className="space-y-1 text-sm text-emerald-800">
                  <li className="flex items-start">
                    <CheckCircle className="w-4 h-4 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Credentials are <strong>NEVER stored</strong> on our servers</span>
                  </li>
                  <li className="flex items-start">
                    <CheckCircle className="w-4 h-4 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Sent <strong>directly to AWS Bedrock</strong> using HTTPS</span>
                  </li>
                  <li className="flex items-start">
                    <CheckCircle className="w-4 h-4 mr-2 mt-0.5 flex-shrink-0" />
                    <span>Cleared automatically when you <strong>close the browser</strong></span>
                  </li>
                  <li className="flex items-start">
                    <CheckCircle className="w-4 h-4 mr-2 mt-0.5 flex-shrink-0" />
                    <span>All traffic encrypted with <strong>TLS 1.3</strong></span>
                  </li>
                </ul>
              </div>
            </div>
          </div>

          {/* Cost Warning */}
          <div className="bg-gradient-to-r from-amber-50 to-orange-50 border-2 border-amber-200 rounded-xl p-4">
            <div className="flex items-start space-x-3">
              <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <h3 className="font-bold text-amber-900 mb-1">💰 Billing Information</h3>
                <p className="text-sm text-amber-800">
                  Usage will be billed to <strong>YOUR AWS account</strong>. Estimated cost: <strong>~$0.01-0.03 per analysis</strong> (AWS Bedrock Claude 3.7 Sonnet pricing).
                </p>
              </div>
            </div>
          </div>

          {/* Credentials Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Access Key ID */}
            <div>
              <label className="block text-sm font-semibold text-slate-700 mb-2">
                AWS Access Key ID <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={credentials.accessKeyId}
                onChange={(e) => setCredentials({ ...credentials, accessKeyId: e.target.value })}
                placeholder="AKIAIOSFODNN7EXAMPLE"
                className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:border-blue-500 focus:outline-none font-mono text-sm"
                required
                autoComplete="off"
                spellCheck="false"
              />
            </div>

            {/* Secret Access Key */}
            <div>
              <label className="block text-sm font-semibold text-slate-700 mb-2">
                AWS Secret Access Key <span className="text-red-500">*</span>
              </label>
              <div className="relative">
                <input
                  type={showSecret ? "text" : "password"}
                  value={credentials.secretAccessKey}
                  onChange={(e) => setCredentials({ ...credentials, secretAccessKey: e.target.value })}
                  placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                  className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:border-blue-500 focus:outline-none font-mono text-sm pr-20"
                  required
                  autoComplete="off"
                  spellCheck="false"
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-sm text-blue-600 hover:text-blue-700 font-medium"
                >
                  {showSecret ? 'Hide' : 'Show'}
                </button>
              </div>
            </div>

            {/* Region */}
            <div>
              <label className="block text-sm font-semibold text-slate-700 mb-2">
                AWS Region <span className="text-red-500">*</span>
              </label>
              <select
                value={credentials.region}
                onChange={(e) => setCredentials({ ...credentials, region: e.target.value })}
                className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:border-blue-500 focus:outline-none"
                required
              >
                <option value="us-east-1">US East (N. Virginia) - us-east-1</option>
                <option value="us-east-2">US East (Ohio) - us-east-2</option>
                <option value="us-west-1">US West (N. California) - us-west-1</option>
                <option value="us-west-2">US West (Oregon) - us-west-2</option>
                <option value="eu-west-1">EU (Ireland) - eu-west-1</option>
                <option value="eu-central-1">EU (Frankfurt) - eu-central-1</option>
                <option value="ap-southeast-1">Asia Pacific (Singapore) - ap-southeast-1</option>
                <option value="ap-northeast-1">Asia Pacific (Tokyo) - ap-northeast-1</option>
              </select>
            </div>

            {/* Agreement Checkbox */}
            <div className="bg-slate-50 rounded-xl p-4 border-2 border-slate-200">
              <label className="flex items-start space-x-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={agreed}
                  onChange={(e) => setAgreed(e.target.checked)}
                  className="mt-1 w-5 h-5 text-blue-600 border-2 border-slate-300 rounded focus:ring-2 focus:ring-blue-500"
                />
                <span className="text-sm text-slate-700">
                  I understand that my AWS credentials will be used to make API calls to AWS Bedrock,
                  and I will be charged according to AWS pricing. Credentials are never stored and are
                  used only for the duration of this session.
                </span>
              </label>
            </div>

            {/* Help Link */}
            <div className="bg-blue-50 rounded-xl p-4 border-2 border-blue-200">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2 text-sm text-blue-700">
                  <span>Don't have AWS credentials?</span>
                </div>
                <a
                  href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center space-x-1 text-sm font-medium text-blue-600 hover:text-blue-700"
                >
                  <span>How to Get AWS Keys</span>
                  <ExternalLink className="w-4 h-4" />
                </a>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex space-x-3 pt-4">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 px-6 py-3 border-2 border-slate-300 text-slate-700 rounded-xl font-semibold hover:bg-slate-50 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={!agreed}
                className="flex-1 px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-xl font-semibold hover:from-blue-700 hover:to-purple-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
              >
                Continue Securely
              </button>
            </div>
          </form>

          {/* Alternative Options */}
          <div className="pt-4 border-t-2 border-slate-100">
            <p className="text-sm text-slate-600 text-center mb-3">
              Prefer not to enter credentials here?
            </p>
            <div className="grid grid-cols-2 gap-3">
              <a
                href="/github-action-guide"
                className="text-center px-4 py-2 bg-slate-100 hover:bg-slate-200 rounded-lg text-sm font-medium text-slate-700 transition-colors"
              >
                Use GitHub Action
              </a>
              <a
                href="/self-host-guide"
                className="text-center px-4 py-2 bg-slate-100 hover:bg-slate-200 rounded-lg text-sm font-medium text-slate-700 transition-colors"
              >
                Self-Host Instead
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AWSConfigModal;

