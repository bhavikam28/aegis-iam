interface IAMStatement {
  Effect?: string;
  Action?: string | string[];
  Resource?: string | string[];
  Sid?: string;
}

interface IAMPolicy {
  Version?: string;
  Statement: IAMStatement[];
}

// Helper to extract service from policy for UI display
export function extractServiceFromPolicy(policy: IAMPolicy | null): string {
  if (!policy?.Statement) return '';
  
  // Look through actions to identify services
  const services = new Set<string>();
  
  for (const stmt of policy.Statement) {
    const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
    actions.forEach(action => {
      if (action) {
        const service = action.split(':')[0].toLowerCase();
        services.add(service);
      }
    });
  }

  return Array.from(services).join(', ');
}