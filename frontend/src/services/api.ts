import { 
  GeneratePolicyResponse,
  PolicyGenerationRequest,
  ValidationResponse,
  ChatMessage
} from '../types';

// Missing types - define them here
export interface ValidatePolicyRequest {
  policy_json?: string;
  role_arn?: string;
  compliance_frameworks?: string[];
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

export interface JobStatus {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  estimated_completion: string;
  message: string;
}

// API URL - uses environment variable on Vercel, localhost for local development
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export interface ConversationalRequest {
  description: string;
  compliance?: string;
  restrictive?: boolean;
  conversation_id?: string;
  is_followup?: boolean;
}

export interface ConversationalResponse {
  final_answer: string;
  conversation_id: string;
  message_count: number;
  refinement_suggestions: string[];
  permissions_score: number;
  trust_score: number;
  overall_score: number;
  security_notes: string[];
  score_breakdown?: Record<string, number>;
  score_explanation?: string;
  security_features?: string[];
  conversation_history: ChatMessage[];
  policy?: any;
  trust_policy?: any;
  explanation?: string;
  trust_explanation?: string;
  is_question?: boolean;
}

// Service detection utility
const detectServiceFromDescription = (description: string): string => {
  if (!description || !description.trim()) {
    return 'lambda'; // Safe default
  }
  
  const descLower = description.toLowerCase();
  
  // Service keyword mappings (match backend patterns)
  const servicePatterns: { [key: string]: string[] } = {
    'lambda': ['lambda', 'function', 'serverless', 'aws lambda', 'lambda function'],
    'ec2': ['ec2', 'instance', 'vm', 'virtual machine', 'ec2 instance'],
    'ecs': ['ecs', 'container', 'task', 'ecs task', 'ecs service', 'docker'],
    'fargate': ['fargate', 'aws fargate', 'ecs fargate'],
    's3': ['s3', 'bucket', 'storage', 's3 bucket', 'object storage'],
    'dynamodb': ['dynamodb', 'dynamo', 'table', 'dynamodb table', 'nosql'],
    'rds': ['rds', 'database', 'mysql', 'postgresql', 'aurora', 'relational'],
    'redshift': ['redshift', 'data warehouse', 'analytics database'],
    'apigateway': ['api gateway', 'apigateway', 'rest api', 'api', 'http api'],
    'sns': ['sns', 'notification', 'topic', 'publish'],
    'sqs': ['sqs', 'queue', 'message queue'],
    'glue': ['glue', 'etl', 'data transformation'],
    'batch': ['batch', 'batch job', 'batch processing'],
    'eks': ['eks', 'kubernetes', 'k8s'],
    'ecr': ['ecr', 'container registry'],
    'kinesis': ['kinesis', 'stream', 'data stream'],
    'stepfunctions': ['step functions', 'stepfunctions', 'state machine'],
    'eventbridge': ['eventbridge', 'event bus'],
    'sagemaker': ['sagemaker', 'ml', 'machine learning'],
    'iot': ['iot', 'internet of things', 'iot core'],
    'cloudfront': ['cloudfront', 'cdn'],
    'route53': ['route53', 'dns', 'domain'],
  };
  
  // Score each service
  const serviceScores: { [key: string]: number } = {};
  
  for (const [service, keywords] of Object.entries(servicePatterns)) {
    let score = 0;
    for (const keyword of keywords) {
      if (descLower.includes(keyword)) {
        score += keyword.length > 3 ? 2 : 1;
      }
      // Word boundary match
      const regex = new RegExp(`\\b${keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
      if (regex.test(descLower)) {
        score += 3;
      }
    }
    if (score > 0) {
      serviceScores[service] = score;
    }
  }
  
  // Return service with highest score, or default to lambda
  if (Object.keys(serviceScores).length === 0) {
    return 'lambda';
  }
  
  const detectedService = Object.entries(serviceScores)
    .sort(([, a], [, b]) => b - a)[0][0];
  
  console.log(`🔍 Detected service: ${detectedService} from description`);
  return detectedService;
};

export const generatePolicy = async (
  request: ConversationalRequest
): Promise<GeneratePolicyResponse> => {
  // Detect service from description if not explicitly provided
  const detectedService = detectServiceFromDescription(request.description);
  
  let response: Response;
  try {
    response = await fetch(`${API_URL}/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        description: request.description,
        service: detectedService, // Use detected service instead of hardcoded 'lambda'
        conversation_id: request.conversation_id || null,
        is_followup: request.is_followup || false,
        restrictive: request.restrictive || false,
        compliance: request.compliance || 'general'
      }),
    });
  } catch (fetchError) {
    console.error('Fetch error:', fetchError);
    throw new Error(`Network error: ${fetchError instanceof Error ? fetchError.message : 'Failed to connect to server'}`);
  }

  // Read response text once (can't read response body twice)
  const responseText = await response.text();
  
  if (!response.ok) {
    console.error(`Backend error (${response.status}):`, responseText);
    throw new Error(`Backend error: ${response.status} - ${responseText.substring(0, 200)}`);
  }

  // Log response for debugging
  console.log('Backend response text (first 500 chars):', responseText.substring(0, 500));
  
  // Check if response is empty or null
  if (!responseText || responseText.trim() === '' || responseText.trim() === 'null') {
    console.error('Backend returned empty or null response body');
    console.error('Response text:', responseText);
    throw new Error('Empty or null response body from server. Please check backend logs.');
  }
  
  let backendResponse: ConversationalResponse | null;
  try {
    backendResponse = JSON.parse(responseText);
  } catch (jsonError) {
    console.error('JSON parse error:', jsonError);
    console.error('Response text that failed to parse:', responseText);
    throw new Error(`Invalid response format from server: ${jsonError instanceof Error ? jsonError.message : 'Unknown error'}`);
  }
  
  // Check if response is null or undefined
  if (!backendResponse || backendResponse === null || (typeof backendResponse === 'object' && Object.keys(backendResponse).length === 0)) {
    console.error('Backend returned null/undefined/empty after parsing');
    console.error('Parsed response:', backendResponse);
    console.error('Response text (first 500 chars):', responseText.substring(0, 500));
    throw new Error("Backend returned null or empty response. The server may have encountered an error. Please check backend logs.");
  }
  
  console.log('Backend response parsed successfully:', {
    hasFinalAnswer: !!backendResponse.final_answer,
    hasPolicy: !!backendResponse.policy,
    hasTrustPolicy: !!backendResponse.trust_policy,
    conversationId: backendResponse.conversation_id
  });
  
  // Check if final_answer exists - handle error responses and normal responses
  if (!backendResponse.final_answer || (typeof backendResponse.final_answer === 'string' && backendResponse.final_answer.trim() === '')) {
    console.error('Backend response missing final_answer:', backendResponse);
    
    // If there's an error field, use it as final_answer
    if ('error' in backendResponse && backendResponse.error) {
      backendResponse.final_answer = backendResponse.error;
    } else {
      // Provide a fallback
      backendResponse.final_answer = backendResponse.explanation || 'Policy generation completed.';
    }
  }
  
  const messageContent = backendResponse.final_answer || backendResponse.error || 'No response received from the agent backend.';

  if (!messageContent || (typeof messageContent === 'string' && messageContent.trim() === '')) {
    throw new Error("No response received from the agent backend.");
  }

  if (backendResponse.is_question || !backendResponse.policy) {
    return {
      conversation_id: backendResponse.conversation_id,
      final_answer: messageContent,
      message_count: backendResponse.message_count || 1,
      policy: null,
      trust_policy: null,
      explanation: messageContent,
      permissions_score: 0,
      trust_score: 0,
      overall_score: 0,
      security_notes: [],
      score_breakdown: {},
      score_explanation: "Agent is requesting more information.",
      security_features: [],
      reasoning: {
        plan: "Gathering required information",
        actions: ["Requesting AWS Account ID, Region, or other details"],
        reflection: "Cannot generate policy without complete information"
      },
      refinement_suggestions: [],
      conversation_history: backendResponse.conversation_history || [],
      is_question: true
    };
  }

  return {
    conversation_id: backendResponse.conversation_id,
    final_answer: messageContent,
    message_count: backendResponse.message_count || 1,
    policy: backendResponse.policy,
    trust_policy: backendResponse.trust_policy,
    explanation: backendResponse.explanation || "Policy generated successfully.",
    trust_explanation: backendResponse.trust_explanation || "",
    permissions_score: backendResponse.permissions_score || 0,
    trust_score: backendResponse.trust_score || 0,
    overall_score: backendResponse.overall_score || 0,
    security_notes: backendResponse.security_notes || { permissions: [], trust: [] },
    score_breakdown: backendResponse.score_breakdown || { permissions: { positive: [], improvements: [] }, trust: { positive: [], improvements: [] } },
    security_features: backendResponse.security_features || { permissions: [], trust: [] },
    refinement_suggestions: backendResponse.refinement_suggestions || { permissions: [], trust: [] },
    conversation_history: backendResponse.conversation_history || []
  };
};

export const sendFollowUp = async (
  message: string,
  conversationId: string
): Promise<GeneratePolicyResponse> => {
  return generatePolicy({
    description: message,
    restrictive: true,
    compliance: 'general',
    conversation_id: conversationId,
    is_followup: true
  });
};

export const getConversationHistory = async (conversationId: string): Promise<{
  conversation_id: string;
  messages: ChatMessage[];
  message_count: number;
}> => {
  const response = await fetch(`${API_URL}/conversation/${conversationId}`);
  if (!response.ok) {
    throw new Error('Failed to fetch conversation history');
  }
  return response.json();
};

export const clearConversation = async (conversationId: string) => {
  const response = await fetch(`${API_URL}/conversation/${conversationId}`, {
    method: 'DELETE'
  });
  if (!response.ok) {
    throw new Error('Failed to clear conversation');
  }
  return response.json();
};

// ============================================
// VALIDATION API (MCP-ENABLED)
// ============================================

export const validatePolicy = async (request: ValidatePolicyRequest): Promise<ValidationResponse> => {
  // Determine mode based on what's provided
  const mode = request.policy_json || request.role_arn ? 'quick' : 'audit';
  
  const response = await fetch(`${API_URL}/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      policy_json: request.policy_json || null,
      role_arn: request.role_arn || null,
      compliance_frameworks: request.compliance_frameworks || ['pci_dss', 'hipaa', 'sox', 'gdpr', 'cis'],
      mode: mode
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Validation failed: ${response.status} - ${errorText}`);
  }

  const backendResponse = await response.json();
  
  if (!backendResponse.success) {
    throw new Error(backendResponse.error || 'Validation failed');
  }

  // Extract agent reasoning from raw response if available
  let agentReasoning = '';
  if (backendResponse.raw_response) {
    // Look for " Agent Reasoning" section in the raw response
    const reasoningMatch = backendResponse.raw_response.match(/ Agent Reasoning[\s\S]*?(?=##|$)/);
    if (reasoningMatch) {
      agentReasoning = reasoningMatch[0].trim();
    }
  }

  return {
    findings: backendResponse.findings || [],
    risk_score: backendResponse.risk_score || 50,
    security_issues: backendResponse.findings?.map((f: any) => f.description) || [],
    recommendations: backendResponse.recommendations || [],
    compliance_status: backendResponse.compliance_status || {},
    quick_wins: backendResponse.quick_wins || [],
    audit_summary: backendResponse.audit_summary || null,
    top_risks: backendResponse.top_risks || [],
    agent_reasoning: agentReasoning
  };
};

// ============================================
// AUTONOMOUS AUDIT API (MCP-ENABLED)
// ============================================

export interface AuditRequest {
  compliance_frameworks?: string[];
}

export interface AuditResponse {
  success: boolean;
  audit_summary: {
    total_roles: number;
    roles_analyzed: number;
    total_policies: number;
    total_findings: number;
    critical_findings: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
  };
  risk_score: number;
  top_risks: Array<{
    role_name: string;
    risk_score: number;
    critical_issues: number;
    findings: any[];
  }>;
  findings: any[];
  compliance_status: Record<string, any>;
  recommendations: string[];
  quick_wins: string[];
  raw_response: string;
  mcp_enabled: boolean;
}

export const performAutonomousAudit = async (
  request: AuditRequest = {}
): Promise<ValidationResponse> => {
  const response = await fetch(`${API_URL}/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      compliance_frameworks: request.compliance_frameworks || ['pci_dss', 'hipaa', 'sox', 'gdpr', 'cis']
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Audit failed: ${response.status} - ${errorText}`);
  }

  const result = await response.json();
  
  if (!result.success) {
    throw new Error(result.error || 'Audit failed');
  }

  // Extract agent reasoning from raw response if available
  let agentReasoning = '';
  if (result.raw_response) {
    // Look for " Agent Reasoning" section in the raw response
    const reasoningMatch = result.raw_response.match(/ Agent Reasoning[\s\S]*?(?=##|$)/);
    if (reasoningMatch) {
      agentReasoning = reasoningMatch[0].trim();
    }
  }

  // Convert audit response to ValidatePolicyResponse format
  return {
    findings: result.findings || [],
    risk_score: result.risk_score || 50,
    security_issues: result.findings?.map((f: any) => f.description) || [],
    recommendations: result.recommendations || [],
    compliance_status: result.compliance_status || {},
    quick_wins: result.quick_wins || [],
    audit_summary: result.audit_summary || null,
    top_risks: result.top_risks || [],
    agent_reasoning: agentReasoning
  };
};

// ============================================
// STREAMING AUDIT (SSE) - NEW!
// ============================================

export interface AuditProgressEvent {
  type: 'start' | 'progress' | 'thinking' | 'complete' | 'error';
  message: string;
  progress: number;
  result?: any;
}

export const performStreamingAudit = (
  request: AuditRequest = {},
  onProgress: (event: AuditProgressEvent) => void
): Promise<ValidationResponse> => {
  return new Promise((resolve, reject) => {
    const frameworks = request.compliance_frameworks || ['pci_dss', 'hipaa', 'sox', 'gdpr', 'cis'];
    const url = `${API_URL}/audit/stream?compliance_frameworks=${frameworks.join(',')}`;
    
    const eventSource = new EventSource(url);
    
    eventSource.onmessage = (event) => {
      try {
        const data: AuditProgressEvent = JSON.parse(event.data);
        
        // Call progress callback
        onProgress(data);
        
        // If complete, extract result and resolve
        if (data.type === 'complete' && data.result) {
          eventSource.close();
          
          // Extract agent reasoning
          let agentReasoning = '';
          if (data.result.raw_response) {
            const reasoningMatch = data.result.raw_response.match(/ Agent Reasoning[\s\S]*?(?=##|$)/);
            if (reasoningMatch) {
              agentReasoning = reasoningMatch[0].trim();
            }
          }
          
          resolve({
            findings: data.result.findings || [],
            risk_score: data.result.risk_score || 50,
            security_issues: data.result.findings?.map((f: any) => f.description) || [],
            recommendations: data.result.recommendations || [],
            compliance_status: data.result.compliance_status || {},
            quick_wins: data.result.quick_wins || [],
            audit_summary: data.result.audit_summary || null,
            top_risks: data.result.top_risks || [],
            agent_reasoning: agentReasoning
          });
        }
        
        // If error, reject
        if (data.type === 'error') {
          eventSource.close();
          reject(new Error(data.message));
        }
      } catch (error) {
        console.error('Error parsing SSE event:', error);
      }
    };
    
    eventSource.onerror = (error) => {
      console.error('SSE error:', error);
      eventSource.close();
      reject(new Error('Stream connection failed'));
    };
  });
};

// ============================================
// ANALYZE HISTORY (MOCK FOR NOW)
// ============================================

export const analyzeHistory = async (request: AnalyzeHistoryRequest): Promise<AnalyzeHistoryResponse> => {
  // Mock implementation - will be replaced with real CloudTrail analysis
  await delay(3000);
  
  return {
    risk_reduction: 78,
    usage_summary: {
      total_permissions: 120,
      used_permissions: 26,
      unused_permissions: 94,
      usage_percentage: 22,
    },
    optimized_policy: {
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Action: "s3:GetObject",
          Resource: "arn:aws:s3:::specific-bucket/*"
        }
      ]
    },
    implementation_steps: [
      "Review the optimized policy to ensure it meets business needs.",
      "Create a new IAM policy version with the optimized JSON.",
      "Set the new policy version as the default for the role.",
      "Monitor application functionality after deployment."
    ],
    security_improvements: [
      "Reduced attack surface by removing 94 unused permissions.",
      "Enforced least privilege based on actual usage.",
      "Eliminated potential privilege escalation paths."
    ]
  };
};