// Centralized API configuration
// Uses environment variable on Vercel, 127.0.0.1 for local development
export const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

