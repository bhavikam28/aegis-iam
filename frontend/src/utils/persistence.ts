/**
 * Persistence utility for storing and retrieving component state
 * Uses localStorage with expiration (default: 24 hours)
 */

const STORAGE_PREFIX = 'aegis_iam_';
const DEFAULT_EXPIRY_HOURS = 24;

interface StoredData<T> {
  data: T;
  timestamp: number;
  expiryHours: number;
}

/**
 * Check if stored data is still valid (not expired)
 */
function isDataValid<T>(stored: StoredData<T> | null): boolean {
  if (!stored) return false;
  
  const now = Date.now();
  const expiryTime = stored.timestamp + (stored.expiryHours * 60 * 60 * 1000);
  return now < expiryTime;
}

/**
 * Save data to localStorage with expiration
 */
export function saveToStorage<T>(
  key: string,
  data: T,
  expiryHours: number = DEFAULT_EXPIRY_HOURS
): void {
  try {
    const storageKey = `${STORAGE_PREFIX}${key}`;
    const storedData: StoredData<T> = {
      data,
      timestamp: Date.now(),
      expiryHours
    };
    localStorage.setItem(storageKey, JSON.stringify(storedData));
  } catch (error) {
    console.warn(`Failed to save to localStorage (${key}):`, error);
    // localStorage might be full or disabled - fail silently
  }
}

/**
 * Retrieve data from localStorage if still valid
 */
export function loadFromStorage<T>(key: string): T | null {
  try {
    const storageKey = `${STORAGE_PREFIX}${key}`;
    const stored = localStorage.getItem(storageKey);
    
    if (!stored) return null;
    
    const parsed: StoredData<T> = JSON.parse(stored);
    
    if (!isDataValid(parsed)) {
      // Data expired, remove it
      localStorage.removeItem(storageKey);
      return null;
    }
    
    return parsed.data;
  } catch (error) {
    console.warn(`Failed to load from localStorage (${key}):`, error);
    return null;
  }
}

/**
 * Clear specific storage key
 */
export function clearStorage(key: string): void {
  try {
    const storageKey = `${STORAGE_PREFIX}${key}`;
    localStorage.removeItem(storageKey);
  } catch (error) {
    console.warn(`Failed to clear localStorage (${key}):`, error);
  }
}

/**
 * Clear all Aegis IAM storage
 */
export function clearAllStorage(): void {
  try {
    const keys = Object.keys(localStorage);
    keys.forEach(key => {
      if (key.startsWith(STORAGE_PREFIX)) {
        localStorage.removeItem(key);
      }
    });
  } catch (error) {
    console.warn('Failed to clear all storage:', error);
  }
}

/**
 * Storage keys for different features
 */
export const STORAGE_KEYS = {
  GENERATE_POLICY: 'generate_policy',
  VALIDATE_POLICY: 'validate_policy',
  AUDIT_ACCOUNT: 'audit_account'
} as const;

