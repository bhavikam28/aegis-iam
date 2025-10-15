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
  policy: any | null;
  trust_policy: any | null;
  explanation: string;
  trust_explanation?: string;
  permissions_score: number;
  trust_score: number;
  overall_score: number;
  security_notes: SecurityNotes;
  security_features: SecurityFeatures;
  score_breakdown: ScoreBreakdown;
  is_question: boolean;
  conversation_history: ChatMessage[];
  refinement_suggestions: RefinementSuggestions;
}

export interface ValidationRequest {
  policy_json?: string;
  role_arn?: string;
  compliance_frameworks?: string[];
  mode?: 'quick' | 'audit';
}

export interface Finding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  recommendation?: string;
  affected_resource?: string;
}

export interface ComplianceStatus {
  [framework: string]: {
    compliant: boolean;
    score: number;
    findings: string[];
  };
}

export interface AuditSummary {
  total_roles: number;
  roles_scanned: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  scan_duration: string;
}

export interface ValidationResponse {
  success: boolean;
  risk_score: number;
  findings: Finding[];
  compliance_status: ComplianceStatus;
  recommendations: string[];
  quick_wins: string[];
  audit_summary?: AuditSummary;
  top_risks?: Finding[];
  raw_response: string;
  mcp_enabled: boolean;
  error?: string;
}

export interface AuditRequest {
  compliance_frameworks?: string[];
}

export interface AuditResponse extends ValidationResponse {
  audit_summary: AuditSummary;
}