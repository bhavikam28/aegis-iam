import React from 'react';
import { Shield } from 'lucide-react';

interface PremiumLogoProps {
  className?: string;
  size?: number;
}

const PremiumLogo: React.FC<PremiumLogoProps> = ({ className = '', size = 64 }) => {
  // Calculate icon size based on container size - bigger shield
  const iconSize = Math.floor(size * 0.68); // ~68% of container size (bigger, more prominent)
  
  return (
    <div className={`relative ${className}`}>
      {/* Glow Effect */}
      <div className="absolute inset-0 bg-gradient-to-br from-blue-500 via-purple-500 to-pink-500 rounded-xl blur-lg opacity-30"></div>
      {/* Logo Container */}
      <div className="relative w-full h-full bg-gradient-to-br from-blue-600 via-purple-600 to-pink-600 rounded-xl flex items-center justify-center shadow-lg border border-purple-200/50">
        <Shield className="text-white" style={{ width: iconSize, height: iconSize }} />
      </div>
    </div>
  );
};

export default PremiumLogo;
