/**
 * Compliance Framework Reference Links - FALLBACK ONLY
 * 
 * NOTE: The AI agent should generate compliance links dynamically in its responses.
 * This file is kept only as a minimal fallback for backward compatibility.
 * The agent is the primary source of truth for compliance links.
 * 
 * TODO: Remove this file entirely once agent consistently provides links in all responses.
 */

/**
 * Fallback function - returns null to indicate agent should provide the link
 * The agent generates compliance links dynamically based on the exact requirement
 */
export function getComplianceLink(framework: string, requirement: string): string | null {
  // Agent should provide links in its response
  // This fallback returns null to indicate missing link
  // Frontend components should primarily use links from agent responses
  return null;
}

