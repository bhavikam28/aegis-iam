export interface IAMPolicy {
  Version: string;
  Statement: IAMStatement[];
}

export interface IAMStatement {
  Sid?: string;
  Effect: 'Allow' | 'Deny';
  Action: string | string[];
  Resource: string | string[];
  Condition?: Record<string, any>;
  Principal?: string | Record<string, any>;
}

export interface SecurityFinding {
  id: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  type: 'OverPrivileged' | 'Compliance' | 'Security' | 'BestPractice';
  title: string;
  description: string;
  recommendation: string;
  affectedStatement?: number;
}

export interface ComplianceFramework {
  name: string;
  status: 'Compliant' | 'NonCompliant' | 'Partial';
  gaps: string[];
}

export interface GeneratePolicyRequest {
  description: string;
  service: string;
  restrictive: boolean;
  compliance: string;
}

export interface GeneratePolicyResponse {
  policy: any;
  explanation: string;
  security_notes: string[];
  security_score: number;
  reasoning: {
    plan: string;
    actions: string[];
    reflection: string;
  };
  conversation_id?: string;  // ADD THIS
  refinement_suggestions?: string[];  // ADD THIS
}

export interface ValidatePolicyRequest {
  policy_json?: string;
  role_arn?: string;
}

export interface ValidatePolicyResponse {
  findings: SecurityFinding[];
  risk_score: number;
  security_issues: string[];
  recommendations: string[];
  compliance_status: Record<string, ComplianceFramework>;
}

export interface AnalyzeHistoryRequest {
  role_arn: string;
  date_range: string;
}

export interface AnalyzeHistoryResponse {
  optimized_policy: IAMPolicy;
  usage_summary: {
    total_permissions: number;
    used_permissions: number;
    unused_permissions: number;
    usage_percentage: number;
  };
  security_improvements: string[];
  implementation_steps: string[];
  risk_reduction: number;
}

export interface JobStatus {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  estimated_completion: string;
  message: string;
}