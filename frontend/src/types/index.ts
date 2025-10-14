// frontend/src/types/index.ts

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

export interface ValidationIssue {
  type: string;
  found: string;
  problem: string;
  suggestion: string;
}

export interface GeneratePolicyResponse {
  conversation_id: string;
  final_answer: string;
  message_count: number;
  policy: any;
  trust_policy?: any;  // ← CRITICAL: Trust policy for IAM roles
  explanation: string;
  security_notes: string[];
  security_features?: string[];
  security_score: number;
  score_breakdown?: Record<string, number>;
  score_explanation?: string;
  reasoning: {
    plan: string;
    actions: string[];
    reflection: string;
  };
  refinement_suggestions?: string[];
  conversation_history?: ChatMessage[];
  is_question?: boolean;
  validation_issues?: ValidationIssue[];
}

export interface PolicyGenerationRequest {
  description: string;
  restrictive: boolean;
  compliance: string;
  conversation_id?: string;
}

export interface ValidationResponse {
  success: boolean;
  risk_score: number;
  findings: any[];
  compliance_status: Record<string, any>;
  recommendations: string[];
  quick_wins: string[];
  audit_summary?: any;
  top_risks?: any[];
  raw_response: string;
  mcp_enabled: boolean;
  error?: string;
}