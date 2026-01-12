import React, { useState } from 'react';
import { X, CheckCircle, Copy, Terminal, Download, ExternalLink, ChevronRight } from 'lucide-react';

interface LocalSetupModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const LocalSetupModal: React.FC<LocalSetupModalProps> = ({ isOpen, onClose }) => {
  const [copiedStep, setCopiedStep] = useState<number | null>(null);

  if (!isOpen) return null;

  const steps = [
    {
      title: 'Clone the Repository',
      command: 'git clone https://github.com/bhavikam28/aegis-iam.git\ncd aegis-iam',
      description: 'Get the latest code from GitHub'
    },
    {
      title: 'Configure AWS CLI',
      command: 'aws configure',
      description: 'Enter your AWS Access Key ID, Secret Key, and region'
    },
    {
      title: 'Start Backend',
      command: 'cd agent\npython -m venv venv\nsource venv/bin/activate  # Windows: venv\\Scripts\\activate\npip install -r requirements.txt\nuvicorn main:app --reload --port 8000',
      description: 'Run the FastAPI backend server'
    },
    {
      title: 'Start Frontend',
      command: 'cd frontend\nnpm install\necho "VITE_API_URL=http://localhost:8000" > .env\nnpm run dev',
      description: 'Run the React frontend (in a new terminal)'
    },
    {
      title: 'Open the App',
      command: 'Visit http://localhost:5173',
      description: 'Your credentials stay on your machine!'
    }
  ];

  const handleCopy = (text: string, stepIndex: number) => {
    navigator.clipboard.writeText(text);
    setCopiedStep(stepIndex);
    setTimeout(() => setCopiedStep(null), 2000);
  };

  const iamPolicy = JSON.stringify({
    "Version": "2012-10-17",
    "Statement": [{
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
    }]
  }, null, 2);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-md p-4">
      <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto bg-white rounded-3xl shadow-2xl border border-slate-200/50">
        {/* Header */}
        <div className="sticky top-0 z-10 bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 px-8 py-5 rounded-t-3xl flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-white/20 rounded-xl flex items-center justify-center backdrop-blur-sm">
              <Terminal className="w-5 h-5 text-white" />
            </div>
            <h2 className="text-xl font-bold text-white">Local Setup Guide</h2>
          </div>
          <button
            onClick={onClose}
            className="text-white hover:bg-white/20 rounded-lg p-2 transition-colors"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="px-8 py-8">
          {/* Intro */}
          <div className="mb-8">
            <p className="text-slate-700 text-lg mb-4">
              Run Aegis IAM locally for <strong>full functionality</strong> with <strong>maximum security</strong>. 
              Your AWS credentials stay on your machine.
            </p>
            <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
              <p className="text-sm text-blue-900">
                <strong>⏱️ Setup time:</strong> ~5 minutes | 
                <strong> 🔒 Security:</strong> Credentials never leave your machine | 
                <strong> 💰 Cost:</strong> Only your AWS Bedrock usage
              </p>
            </div>
          </div>

          {/* Prerequisites */}
          <div className="mb-8 bg-slate-50 rounded-2xl p-6 border border-slate-200">
            <h3 className="text-lg font-bold text-slate-900 mb-4">Prerequisites</h3>
            <ul className="space-y-2 text-slate-700">
              <li className="flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-emerald-500" />
                <span>Node.js 18+ and npm</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-emerald-500" />
                <span>Python 3.11+</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-emerald-500" />
                <span>AWS Account with Bedrock access</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-emerald-500" />
                <span>AWS CLI installed</span>
              </li>
            </ul>
          </div>

          {/* Setup Steps */}
          <div className="space-y-6 mb-8">
            <h3 className="text-xl font-bold text-slate-900 mb-4">Setup Steps</h3>
            {steps.map((step, index) => (
              <div key={index} className="bg-white border-2 border-slate-200 rounded-2xl p-6">
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-xl flex items-center justify-center flex-shrink-0 text-white font-bold">
                    {index + 1}
                  </div>
                  <div className="flex-1">
                    <h4 className="text-lg font-bold text-slate-900 mb-2">{step.title}</h4>
                    <p className="text-sm text-slate-600 mb-3">{step.description}</p>
                    <div className="relative bg-slate-900 rounded-xl p-4">
                      <pre className="text-xs text-slate-200 font-mono whitespace-pre-wrap overflow-x-auto">
                        {step.command}
                      </pre>
                      <button
                        onClick={() => handleCopy(step.command, index)}
                        className="absolute top-4 right-4 p-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                        title="Copy command"
                      >
                        {copiedStep === index ? (
                          <CheckCircle className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <Copy className="w-4 h-4 text-slate-300" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* IAM Policy */}
          <div className="mb-8 bg-amber-50 border-2 border-amber-200 rounded-2xl p-6">
            <h3 className="text-lg font-bold text-slate-900 mb-3">Required IAM Policy</h3>
            <p className="text-sm text-slate-700 mb-4">
              Attach this policy to your IAM user in AWS Console:
            </p>
            <div className="relative bg-slate-900 rounded-xl p-4 mb-4">
              <pre className="text-xs text-slate-200 font-mono overflow-x-auto">
                {iamPolicy}
              </pre>
              <button
                onClick={() => handleCopy(iamPolicy, -1)}
                className="absolute top-4 right-4 p-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                title="Copy policy"
              >
                {copiedStep === -1 ? (
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                ) : (
                  <Copy className="w-4 h-4 text-slate-300" />
                )}
              </button>
            </div>
            <a
              href="https://console.aws.amazon.com/iam/home#/users"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 font-medium"
            >
              Open AWS IAM Console
              <ExternalLink className="w-4 h-4" />
            </a>
          </div>

          {/* Help Links */}
          <div className="flex flex-col sm:flex-row gap-4">
            <a
              href="https://github.com/bhavikam28/aegis-iam/blob/main/LOCAL_SETUP.md"
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-xl font-semibold hover:shadow-lg transition-all flex items-center justify-center gap-2"
            >
              <Download className="w-5 h-5" />
              Detailed Guide
            </a>
            <a
              href="https://github.com/bhavikam28/aegis-iam"
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 px-6 py-3 bg-white border-2 border-slate-300 text-slate-700 rounded-xl font-semibold hover:bg-slate-50 transition-all flex items-center justify-center gap-2"
            >
              View on GitHub
              <ChevronRight className="w-5 h-5" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LocalSetupModal;

