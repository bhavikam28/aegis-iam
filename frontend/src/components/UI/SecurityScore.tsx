import React from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';

interface SecurityScoreProps {
  score: number;
  className?: string;
}

const SecurityScore: React.FC<SecurityScoreProps> = ({ score, className = '' }) => {
  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-400';
    if (score >= 70) return 'text-yellow-400';
    if (score >= 50) return 'text-orange-400';
    return 'text-red-400';
  };

  const getScoreIcon = (score: number) => {
    if (score >= 90) return CheckCircle;
    if (score >= 70) return Shield;
    if (score >= 50) return AlertTriangle;
    return XCircle;
  };

  const getScoreLabel = (score: number) => {
    if (score >= 90) return 'Excellent Security';
    if (score >= 70) return 'Good Security';
    if (score >= 50) return 'Moderate Risk';
    return 'High Risk';
  };

  const ScoreIcon = getScoreIcon(score);

  return (
    <div className={`flex items-center space-x-2 ${className}`}>
      <div className="flex items-center space-x-1">
        <ScoreIcon className={`w-5 h-5 ${getScoreColor(score)}`} />
        <span className={`text-2xl font-bold ${getScoreColor(score)}`}>
          {score}
        </span>
        <span className="text-slate-400 text-sm">/100</span>
      </div>
      <div className="flex flex-col">
        <span className={`text-sm font-medium ${getScoreColor(score)}`}>
          {getScoreLabel(score)}
        </span>
        <span className="text-xs text-slate-500">Security Score</span>
      </div>
    </div>
  );
};

export default SecurityScore;