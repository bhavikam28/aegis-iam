import React, { useState, useEffect } from 'react';
import { Lightbulb, Shield, Key, Lock, AlertTriangle, CheckCircle, Clock, Users, Database, Globe } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

interface SecurityTip {
  icon: LucideIcon;
  tip: string;
  category: 'best-practice' | 'fact' | 'tip' | 'warning';
}

const securityTips: SecurityTip[] = [
  // Best Practices
  { icon: Shield, tip: "Least privilege: Grant only the permissions needed for the task", category: 'best-practice' },
  { icon: Key, tip: "Rotate access keys regularly — AWS recommends every 90 days", category: 'best-practice' },
  { icon: Lock, tip: "Enable MFA for all IAM users, especially those with console access", category: 'best-practice' },
  { icon: Users, tip: "Use IAM roles instead of long-term access keys when possible", category: 'best-practice' },
  { icon: Database, tip: "Use resource-level ARNs instead of wildcards (*) in policies", category: 'best-practice' },
  
  // Facts & Statistics
  { icon: AlertTriangle, tip: "85% of data breaches involve weak or stolen credentials", category: 'fact' },
  { icon: Clock, tip: "AWS recommends reviewing IAM policies every 90 days", category: 'fact' },
  { icon: Globe, tip: "Over 90% of cloud security failures are due to misconfiguration", category: 'fact' },
  { icon: Shield, tip: "The average cost of a data breach in 2024 is $4.88 million", category: 'fact' },
  
  // Pro Tips
  { icon: Lightbulb, tip: "Use IAM Access Analyzer to identify unused permissions", category: 'tip' },
  { icon: Lightbulb, tip: "Tag your IAM roles for better organization and cost tracking", category: 'tip' },
  { icon: Lightbulb, tip: "Use service control policies (SCPs) for organization-wide guardrails", category: 'tip' },
  { icon: CheckCircle, tip: "Condition keys add extra security layers to your policies", category: 'tip' },
  { icon: Lightbulb, tip: "Use aws:SourceIP condition to restrict API calls by IP address", category: 'tip' },
  
  // Warnings
  { icon: AlertTriangle, tip: "Never commit AWS credentials to source code repositories", category: 'warning' },
  { icon: AlertTriangle, tip: "Avoid using the root account for everyday tasks", category: 'warning' },
  { icon: Lock, tip: "\"Action\": \"*\" grants ALL permissions — use with extreme caution", category: 'warning' },
];

interface SecurityTipsProps {
  rotationInterval?: number; // in milliseconds, default 4000 (4 seconds)
  className?: string;
}

const SecurityTips: React.FC<SecurityTipsProps> = ({ 
  rotationInterval = 4000,
  className = ''
}) => {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isVisible, setIsVisible] = useState(true);
  const [shuffledTips, setShuffledTips] = useState<SecurityTip[]>([]);

  // Shuffle tips on mount so they appear in random order
  useEffect(() => {
    const shuffled = [...securityTips].sort(() => Math.random() - 0.5);
    setShuffledTips(shuffled);
  }, []);

  useEffect(() => {
    if (shuffledTips.length === 0) return;

    const interval = setInterval(() => {
      // Fade out
      setIsVisible(false);
      
      // After fade out, change tip and fade in
      setTimeout(() => {
        setCurrentIndex((prev) => (prev + 1) % shuffledTips.length);
        setIsVisible(true);
      }, 300);
    }, rotationInterval);

    return () => clearInterval(interval);
  }, [rotationInterval, shuffledTips]);

  // Don't render until tips are shuffled
  if (shuffledTips.length === 0) {
    return <div className={`w-full max-w-lg mx-auto ${className} h-32`}></div>;
  }

  const currentTip = shuffledTips[currentIndex];
  const Icon = currentTip.icon;

  const getCategoryStyles = () => {
    switch (currentTip.category) {
      case 'best-practice':
        return {
          bg: 'bg-gradient-to-r from-blue-50 to-indigo-50',
          border: 'border-blue-200',
          iconBg: 'bg-blue-100',
          iconColor: 'text-blue-600',
          textColor: 'text-blue-800',
          label: '💡 Best Practice',
          labelColor: 'text-blue-600'
        };
      case 'fact':
        return {
          bg: 'bg-gradient-to-r from-purple-50 to-pink-50',
          border: 'border-purple-200',
          iconBg: 'bg-purple-100',
          iconColor: 'text-purple-600',
          textColor: 'text-purple-800',
          label: '📊 Did You Know?',
          labelColor: 'text-purple-600'
        };
      case 'tip':
        return {
          bg: 'bg-gradient-to-r from-indigo-50 to-purple-50',
          border: 'border-indigo-200',
          iconBg: 'bg-indigo-100',
          iconColor: 'text-indigo-600',
          textColor: 'text-indigo-800',
          label: '⚡ Pro Tip',
          labelColor: 'text-indigo-600'
        };
      case 'warning':
        return {
          bg: 'bg-gradient-to-r from-pink-50 to-rose-50',
          border: 'border-pink-200',
          iconBg: 'bg-pink-100',
          iconColor: 'text-pink-600',
          textColor: 'text-pink-800',
          label: '⚠️ Security Alert',
          labelColor: 'text-pink-600'
        };
      default:
        return {
          bg: 'bg-slate-50',
          border: 'border-slate-200',
          iconBg: 'bg-slate-100',
          iconColor: 'text-slate-600',
          textColor: 'text-slate-800',
          label: '💡 Tip',
          labelColor: 'text-slate-600'
        };
    }
  };

  const styles = getCategoryStyles();

  return (
    <div className={`w-full max-w-lg mx-auto ${className}`}>
      <div 
        className={`
          ${styles.bg} ${styles.border} 
          border-2 rounded-2xl p-5 
          transition-all duration-300 ease-in-out
          ${isVisible ? 'opacity-100 transform translate-y-0' : 'opacity-0 transform -translate-y-2'}
          shadow-sm hover:shadow-md
        `}
      >
        {/* Category Label */}
        <div className={`text-xs font-bold uppercase tracking-wider ${styles.labelColor} mb-3`}>
          {styles.label}
        </div>
        
        {/* Tip Content */}
        <div className="flex items-start space-x-4">
          <div className={`flex-shrink-0 w-10 h-10 ${styles.iconBg} rounded-xl flex items-center justify-center`}>
            <Icon className={`w-5 h-5 ${styles.iconColor}`} />
          </div>
          <p className={`${styles.textColor} text-sm sm:text-base font-medium leading-relaxed flex-1`}>
            {currentTip.tip}
          </p>
        </div>
      </div>
      
      {/* Progress indicator - simple animation */}
      <div className="flex justify-center mt-4">
        <div className="flex space-x-1.5">
          {[0, 1, 2].map((index) => (
            <div
              key={index}
              className="w-2 h-2 rounded-full bg-gradient-to-r from-blue-500 to-purple-500 animate-pulse"
              style={{ animationDelay: `${index * 0.2}s` }}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

export default SecurityTips;

