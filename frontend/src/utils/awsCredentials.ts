/**
 * Secure AWS Credentials Management
 * 
 * SECURITY PRINCIPLES:
 * 1. Credentials stored ONLY in memory (React state)
 * 2. NEVER stored in localStorage, sessionStorage, or cookies
 * 3. Cleared on page refresh
 * 4. Never logged to console
 * 5. Passed only to backend API (which forwards to AWS)
 */

export interface AWSCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
}

/**
 * Validate AWS Access Key ID format
 * Format: AKIA followed by 16 alphanumeric characters
 */
export const validateAccessKeyId = (accessKeyId: string): boolean => {
  // AWS Access Key ID format: AKIA[A-Z0-9]{16}
  const regex = /^AKIA[A-Z0-9]{16}$/;
  return regex.test(accessKeyId);
};

/**
 * Validate AWS Secret Access Key format
 * Format: 40 alphanumeric + special characters
 */
export const validateSecretAccessKey = (secretAccessKey: string): boolean => {
  // AWS Secret Access Key is 40 characters, base64-like
  return secretAccessKey.length === 40 && /^[A-Za-z0-9+/]+$/.test(secretAccessKey);
};

/**
 * Validate AWS Region format
 */
export const validateRegion = (region: string): boolean => {
  const validRegions = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-central-1', 'eu-north-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
    'ap-south-1', 'sa-east-1', 'ca-central-1'
  ];
  return validRegions.includes(region);
};

/**
 * Validate complete AWS credentials
 */
export const validateCredentials = (credentials: AWSCredentials): { valid: boolean; error?: string } => {
  if (!credentials.accessKeyId || !credentials.secretAccessKey || !credentials.region) {
    return { valid: false, error: 'All fields are required' };
  }

  if (!validateAccessKeyId(credentials.accessKeyId)) {
    return { valid: false, error: 'Invalid Access Key ID format. Should start with AKIA followed by 16 characters' };
  }

  if (!validateSecretAccessKey(credentials.secretAccessKey)) {
    return { valid: false, error: 'Invalid Secret Access Key format. Should be 40 characters' };
  }

  if (!validateRegion(credentials.region)) {
    return { valid: false, error: 'Invalid AWS region' };
  }

  return { valid: true };
};

/**
 * Sanitize credentials for logging (NEVER log actual credentials!)
 */
export const sanitizeCredentialsForLogging = (credentials: AWSCredentials) => {
  return {
    accessKeyId: credentials.accessKeyId ? `${credentials.accessKeyId.substring(0, 4)}...${credentials.accessKeyId.substring(credentials.accessKeyId.length - 4)}` : 'NOT_SET',
    secretAccessKey: '***REDACTED***',
    region: credentials.region
  };
};

/**
 * Check if credentials are configured (without exposing them)
 */
export const areCredentialsConfigured = (credentials: AWSCredentials | null): boolean => {
  return !!(credentials?.accessKeyId && credentials?.secretAccessKey && credentials?.region);
};

/**
 * Get masked display of credentials for UI
 */
export const getMaskedCredentials = (credentials: AWSCredentials) => {
  return {
    accessKeyId: `${credentials.accessKeyId.substring(0, 10)}...`,
    region: credentials.region
  };
};

/**
 * Clear credentials (call when user logs out or closes session)
 */
export const clearCredentials = (): null => {
  // No localStorage/sessionStorage to clear
  // Just return null to set state
  return null;
};

/**
 * Estimate cost for AWS Bedrock usage
 */
export const estimateCost = (requestType: 'generate' | 'validate' | 'audit'): string => {
  const costs = {
    generate: '$0.02-0.05',
    validate: '$0.01-0.03',
    audit: '$0.05-0.15'
  };
  return costs[requestType];
};

