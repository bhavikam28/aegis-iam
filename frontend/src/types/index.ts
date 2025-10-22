export interface GeneratePolicyRequest {
  description: string;
  restrictive: boolean;
  compliance: string;
}

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

export interface ScoreBreakdown {
  permissions?: {
    positive: string[];
    improvements: string[];
  };
  trust?: {
    positive: string[];
    improvements: string[];
  };
}

export interface SecurityNotes {
  permissions?: string[];
  trust?: string[];
}

export interface SecurityFeatures {
  permissions?: string[];
  trust?: string[];
}

export interface RefinementSuggestions {
  permissions?: string[];
  trust?: string[];
}

export interface GeneratePolicyResponse {
  conversation_id: string;
  final_answer: string;
  message_count: number;
  policy: any;
  trust_policy?: any;
  explanation?: string;
  trust_explanation?: string;
  permissions_score: number;
  trust_score: number;
  overall_score: number;
  security_notes?: SecurityNotes;
  score_breakdown?: ScoreBreakdown;
  security_features?: SecurityFeatures;
  refinement_suggestions?: RefinementSuggestions;
  conversation_history?: ChatMessage[];
  is_question?: boolean;
  reasoning?: {
    plan: string;
    actions: string[];
    reflection: string;
  };
}

export interface ValidationRequest {
  policy_json?: string;
  role_arn?: string;
  compliance_frameworks?: string[];
  mode?: 'quick' | 'audit';
}

export interface SecurityFinding {
  id: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  type: string;
  title: string;
  description: string;
  recommendation: string;
  affectedStatement?: number;
  code_snippet?: string;
}

export interface ComplianceFramework {
  name: string;
  status: 'Compliant' | 'NonCompliant' | 'Partial';
  gaps?: string[];
  violations?: Array<{
    requirement: string;
    description: string;
    fix: string;
  }>;
}

export interface AuditSummary {
  total_roles: number;
  roles_analyzed: number;
  total_policies: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
}

export interface ValidationResponse {
  findings: SecurityFinding[];
  risk_score: number;
  security_issues: string[];
  recommendations: string[];
  compliance_status: Record<string, ComplianceFramework>;
  quick_wins?: string[];
  audit_summary?: AuditSummary | null;
  top_risks?: string[];
  agent_reasoning?: string;
}

export interface IAMPolicy {
  Version: string;
  Statement: Array<{
    Sid?: string;
    Effect: string;
    Action: string | string[];
    Resource: string | string[];
    Condition?: any;
  }>;
}

export interface AnalyzeHistoryRequest {
  role_arn: string;
  date_range: string;
}

export interface AnalyzeHistoryResponse {
  optimized_policy: any;
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