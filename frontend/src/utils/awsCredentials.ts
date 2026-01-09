/**
 * AWS Credentials Management Utility
 * 
 * SECURITY PRINCIPLES:
 * - Credentials stored in React state (memory) AND sessionStorage (for convenience)
 * - sessionStorage automatically clears when browser tab is closed
 * - Credentials persist across page refreshes within the same session
 * - Passed directly to backend API calls
 * - Backend uses credentials ONLY for the current request
 */

export interface AWSCredentials {
  access_key_id?: string;  // Optional for CLI-based auth
  secret_access_key?: string;  // Optional for CLI-based auth
  region: string;
}

/**
 * Validates AWS Access Key ID format
 * Format: 20 characters starting with AKIA
 */
export const validateAccessKeyId = (accessKeyId: string): boolean => {
  return /^AKIA[A-Z0-9]{16}$/.test(accessKeyId);
};

/**
 * Validates AWS Secret Access Key format
 * Format: 40 characters (alphanumeric + symbols)
 */
export const validateSecretAccessKey = (secretAccessKey: string): boolean => {
  return secretAccessKey.length === 40;
};

/**
 * Validates AWS Region format
 * Format: [area]-[direction]-[number] (e.g., us-east-1)
 */
export const validateRegion = (region: string): boolean => {
  return /^[a-z]{2}-[a-z]+-[0-9]$/.test(region);
};

/**
 * Validates complete AWS credentials object
 */
export const validateCredentials = (credentials: AWSCredentials | null): boolean => {
  if (!credentials) return false;
  
  return (
    validateAccessKeyId(credentials.access_key_id) &&
    validateSecretAccessKey(credentials.secret_access_key) &&
    validateRegion(credentials.region)
  );
};

/**
 * Masks Access Key ID for display
 * Example: AKIAIOSFODNN7EXAMPLE → AKIA************MPLE
 */
export const maskAccessKeyId = (accessKeyId: string): string => {
  if (!accessKeyId || accessKeyId.length < 8) return '****';
  return `${accessKeyId.slice(0, 4)}************${accessKeyId.slice(-4)}`;
};

/**
 * Masks Secret Access Key for display
 * Example: Shows only first 4 and last 4 characters
 */
export const maskSecretAccessKey = (secretAccessKey: string): string => {
  if (!secretAccessKey || secretAccessKey.length < 8) return '********';
  return `${secretAccessKey.slice(0, 4)}********************************${secretAccessKey.slice(-4)}`;
};

/**
 * Get region display name - Complete list of all AWS regions
 */
export const getRegionDisplayName = (region: string): string => {
  const regionNames: Record<string, string> = {
    // US Regions
    'us-east-1': 'US East (N. Virginia)',
    'us-east-2': 'US East (Ohio)',
    'us-west-1': 'US West (N. California)',
    'us-west-2': 'US West (Oregon)',
    
    // Europe
    'eu-west-1': 'Europe (Ireland)',
    'eu-west-2': 'Europe (London)',
    'eu-west-3': 'Europe (Paris)',
    'eu-central-1': 'Europe (Frankfurt)',
    'eu-central-2': 'Europe (Zurich)',
    'eu-north-1': 'Europe (Stockholm)',
    'eu-south-1': 'Europe (Milan)',
    'eu-south-2': 'Europe (Spain)',
    
    // Asia Pacific
    'ap-south-1': 'Asia Pacific (Mumbai)',
    'ap-south-2': 'Asia Pacific (Hyderabad)',
    'ap-southeast-1': 'Asia Pacific (Singapore)',
    'ap-southeast-2': 'Asia Pacific (Sydney)',
    'ap-southeast-3': 'Asia Pacific (Jakarta)',
    'ap-southeast-4': 'Asia Pacific (Melbourne)',
    'ap-southeast-5': 'Asia Pacific (Malaysia)',
    'ap-southeast-6': 'Asia Pacific (New Zealand)',
    'ap-southeast-7': 'Asia Pacific (Thailand)',
    'ap-northeast-1': 'Asia Pacific (Tokyo)',
    'ap-northeast-2': 'Asia Pacific (Seoul)',
    'ap-northeast-3': 'Asia Pacific (Osaka)',
    'ap-east-1': 'Asia Pacific (Hong Kong)',
    'ap-east-2': 'Asia Pacific (Taipei)',
    
    // Middle East
    'me-south-1': 'Middle East (Bahrain)',
    'me-central-1': 'Middle East (UAE)',
    'il-central-1': 'Israel (Tel Aviv)',
    
    // Canada
    'ca-central-1': 'Canada (Central)',
    'ca-west-1': 'Canada West (Calgary)',
    
    // South America
    'sa-east-1': 'South America (São Paulo)',
    
    // Africa
    'af-south-1': 'Africa (Cape Town)',
    
    // Mexico
    'mx-central-1': 'Mexico (Central)',
    
    // AWS GovCloud (US)
    'us-gov-east-1': 'AWS GovCloud (US-East)',
    'us-gov-west-1': 'AWS GovCloud (US-West)',
    
    // China (Special Regions - require separate account)
    'cn-north-1': 'China (Beijing)',
    'cn-northwest-1': 'China (Ningxia)',
  };
  
  return regionNames[region] || region;
};

/**
 * SessionStorage helpers for credentials persistence
 * Uses sessionStorage (cleared when tab closes) - NOT localStorage (persists forever)
 */
const CREDENTIALS_STORAGE_KEY = 'aegis_aws_credentials';

export const saveCredentialsToSession = (credentials: AWSCredentials): void => {
  try {
    sessionStorage.setItem(CREDENTIALS_STORAGE_KEY, JSON.stringify(credentials));
  } catch (error) {
    console.error('Failed to save credentials to sessionStorage:', error);
    // Silently fail - credentials still work in memory
  }
};

export const loadCredentialsFromSession = (): AWSCredentials | null => {
  try {
    const stored = sessionStorage.getItem(CREDENTIALS_STORAGE_KEY);
    if (!stored) return null;
    
    const credentials = JSON.parse(stored) as AWSCredentials;
    
    // Validate loaded credentials before returning
    if (validateCredentials(credentials)) {
      return credentials;
    } else {
      // Invalid credentials - clear them
      clearCredentialsFromSession();
      return null;
    }
  } catch (error) {
    console.error('Failed to load credentials from sessionStorage:', error);
    clearCredentialsFromSession();
    return null;
  }
};

export const clearCredentialsFromSession = (): void => {
  try {
    sessionStorage.removeItem(CREDENTIALS_STORAGE_KEY);
  } catch (error) {
    console.error('Failed to clear credentials from sessionStorage:', error);
  }
};
