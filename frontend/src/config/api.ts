// Centralized API configuration
// Uses environment variable on Vercel, localhost for local development
export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

