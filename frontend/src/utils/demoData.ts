import { 
  GeneratePolicyRequest, 
  GeneratePolicyResponse, 
  ValidatePolicyRequest, 
  ValidatePolicyResponse, 
  AnalyzeHistoryRequest, 
  AnalyzeHistoryResponse,
  SecurityFinding,
  IAMPolicy,
  ComplianceFramework
} from '../types';

// ============================================
// GENERATE POLICY DEMO DATA
// ============================================

export const mockGeneratePolicyResponse = (request: GeneratePolicyRequest): GeneratePolicyResponse => {
  // Use common AWS services: S3 and Lambda (everyone knows these)
  const policy: IAMPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "AllowS3ReadAccess",
        Effect: "Allow",
        Action: [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket"
        ],
        Resource: [
          "arn:aws:s3:::my-app-uploads",
          "arn:aws:s3:::my-app-uploads/*"
        ]
      },
      {
        Sid: "AllowCloudWatchLogs",
        Effect: "Allow",
        Action: [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource: "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-function:*"
      }
    ]
  };
  
  const trustPolicy: IAMPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: {
          Service: "lambda.amazonaws.com"
        },
        Action: "sts:AssumeRole",
        Condition: {
          StringEquals: {
            "aws:SourceAccount": "123456789012"
          }
        }
      }
    ]
  };
  
  const permissionsExplanation = `1. AllowS3ReadAccess
Permission: s3:GetObject, s3:GetObjectVersion, s3:ListBucket on my-app-uploads bucket
Purpose: Grants Lambda function the ability to read files from the S3 bucket 'my-app-uploads'. This includes downloading objects, listing bucket contents, and accessing previous versions of objects if versioning is enabled.
Why It Matters: S3 access is restricted to a single specific bucket, preventing the Lambda function from accessing other S3 buckets in your AWS account. This follows the principle of least privilege by limiting scope to only what's needed.
Security: Resource-level restrictions ensure the function cannot accidentally access or modify data in other S3 buckets, reducing the attack surface significantly.

2. AllowCloudWatchLogs
Permission: logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents on Lambda function log group
Purpose: Enables Lambda to write application logs to CloudWatch Logs for monitoring, debugging, and audit purposes. The function can create log groups/streams and write log events.
Why It Matters: Logging permissions are scoped to this specific Lambda function's log group (/aws/lambda/my-function), preventing logs from being written to arbitrary log groups. This maintains log isolation and security.
Security: Regional scoping (us-east-1) and specific log group ARN prevent accidental logging to other regions or log groups, ensuring logs stay organized and secure.`;

  const trustExplanation = `The trust policy defines **who** is allowed to assume (use) this IAM role.

**Trusted Entity**: AWS Lambda Service (lambda.amazonaws.com) - Only Lambda functions can assume this role.

**Source Account Restriction**: The role can only be assumed by Lambda functions running in AWS account 123456789012. This aws:SourceAccount condition is critical for security.

**Confused Deputy Protection**: The source account condition prevents other AWS accounts from using this role, even if they somehow know the role ARN. This prevents cross-account confused deputy attacks.

**What This Means**:
• Only Lambda functions in YOUR account (123456789012) can use this role
• Lambda functions in other AWS accounts cannot assume this role
• No other AWS services (EC2, ECS, EKS, etc.) can use this role - only Lambda
• Reduces risk of unauthorized access and confused deputy vulnerability

**Best Practice**: This is the standard trust policy pattern for Lambda execution roles, providing secure service-to-service authentication within your AWS account without allowing external entities.`;

  const securityScore = request.restrictive ? 95 : 85;

  // Compliance features - detailed breakdown for each framework
  const complianceFeatures = [];
  
  if (request.compliance === 'pci-dss' || request.compliance === 'pci_dss') {
    complianceFeatures.push(
      {
        title: "Least-Privilege Access (Requirement 7.1.2)",
        subtitle: "Policy uses specific actions instead of wildcards",
        requirement: "PCI DSS Requirement 7.1.2: Restrict access to cardholder data by business need-to-know",
        description: "Policy uses specific actions (s3:GetObject, logs:PutLogEvents) instead of wildcards (*), limiting access to only necessary permissions. This ensures that even if credentials are compromised, attackers can only perform the exact operations needed for the intended function, significantly reducing the attack surface and protecting cardholder data.",
        link: "https://www.pcisecuritystandards.org/document_library/"
      },
      {
        title: "Resource-Level Restrictions",
        subtitle: "Permissions scoped to specific resources",
        requirement: "PCI DSS Requirement 7.1.2: Limit access to cardholder data environment",
        description: "Permissions are scoped to specific resources (S3 bucket 'my-app-uploads', CloudWatch log group '/aws/lambda/my-function') rather than using wildcards. This prevents unauthorized access to other resources in your account, ensuring cardholder data environments are properly isolated and protected from lateral movement attacks.",
        link: "https://www.pcisecuritystandards.org/document_library/"
      },
      {
        title: "Access Logging Ready (Requirement 10)",
        subtitle: "CloudWatch Logs permissions enable audit trails",
        requirement: "PCI DSS Requirement 10: Track and monitor all access to network resources and cardholder data",
        description: "CloudWatch Logs permissions enable comprehensive access monitoring and audit trails. All access to cardholder data can be logged and reviewed, supporting PCI DSS Requirement 10 which mandates tracking and monitoring all access to network resources and cardholder data for forensic analysis and compliance reporting.",
        link: "https://www.pcisecuritystandards.org/document_library/"
      },
      {
        title: "Network Segmentation Principles",
        subtitle: "Access limited to necessary services",
        requirement: "PCI DSS Requirement 1: Install and maintain network security controls",
        description: "By restricting permissions to specific resources and services, this policy supports network segmentation principles. Access is limited to only the necessary services (S3 and CloudWatch), reducing the risk of lateral movement if one component is compromised and protecting the cardholder data environment from unauthorized network access.",
        link: "https://www.pcisecuritystandards.org/document_library/"
      }
    );
  } else if (request.compliance === 'hipaa') {
    complianceFeatures.push(
      {
        title: "Access Controls (164.308(a)(4))",
        subtitle: "Least-privilege access controls to protect PHI",
        requirement: "HIPAA 164.308(a)(4): Information access management",
        description: "Policy implements least-privilege access controls to protect PHI (Protected Health Information). HIPAA requires covered entities to implement procedures to authorize access to ePHI only when such access is appropriate based on the user's role. This policy ensures that only necessary permissions are granted, reducing the risk of unauthorized PHI access and supporting role-based access control (RBAC) principles.",
        link: "https://www.hhs.gov/hipaa/for-professionals/security/guidance/administrative-safeguards/index.html"
      },
      {
        title: "Audit Logging (164.312(b))",
        subtitle: "CloudWatch Logs enable audit controls for ePHI",
        requirement: "HIPAA 164.312(b): Audit controls",
        description: "CloudWatch Logs permissions enable audit controls for access to ePHI. HIPAA requires implementation of hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI. This policy ensures all access to PHI is logged and can be audited for security incident response and compliance reporting.",
        link: "https://www.hhs.gov/hipaa/for-professionals/security/guidance/audit-controls/index.html"
      }
    );
  } else {
    complianceFeatures.push(
      {
        title: "Least Privilege Access",
        subtitle: "AWS IAM Best Practice",
        requirement: "AWS Security Best Practices",
        description: "All permissions are scoped to specific resources with minimal necessary actions. This follows AWS's principle of granting only the permissions required to perform a task, reducing the attack surface and potential impact of compromised credentials.",
        link: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
      },
      {
        title: "Resource-Level Permissions",
        subtitle: "Specific ARNs instead of wildcards",
        requirement: "AWS Security Best Practices",
        description: "Resources are explicitly defined with ARNs instead of using wildcards (*). This ensures permissions only apply to intended resources, preventing accidental or malicious access to other resources in your AWS account.",
        link: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
      }
    );
  }
  
  const complianceStatus: Record<string, ComplianceFramework> = {};
  
  if (request.compliance === 'hipaa') {
    complianceStatus['hipaa'] = {
      name: "HIPAA",
      status: "Compliant",
      gaps: [],
      violations: []
    };
  } else if (request.compliance === 'pci-dss' || request.compliance === 'pci_dss') {
    complianceStatus['pci-dss'] = {
      name: "PCI DSS",
      status: "Compliant",
      gaps: [],
      violations: []
    };
  } else {
    complianceStatus['general'] = {
      name: "AWS Security Best Practices",
      status: "Compliant",
      gaps: [],
      violations: []
    };
  }

  return {
    conversation_id: "demo-conversation-" + Date.now(),
    final_answer: "I've generated a secure IAM policy for a Lambda function that reads from an S3 bucket and writes logs to CloudWatch. The policy follows AWS security best practices with least-privilege access and resource-level restrictions.",
    message_count: 1,
    policy,
    trust_policy: trustPolicy,
    explanation: permissionsExplanation,
    trust_explanation: trustExplanation,
    permissions_score: securityScore,
    trust_score: 95,
    overall_score: Math.round((securityScore + 95) / 2),
    security_notes: {
      permissions: [
        "✅ Policy follows least-privilege principle with specific resource constraints",
        "✅ Actions are limited to only what's necessary for the described functionality",
        request.restrictive ? "✅ Enhanced security mode - additional restrictions enforced" : "⚠️ Standard mode - consider enabling restrictive mode for production",
        "✅ Resource ARNs explicitly specified (no wildcards)"
      ],
      trust: [
        "✅ Trust policy properly restricts role assumption to Lambda service only",
        "✅ Source account condition prevents confused deputy attacks",
        "✅ No wildcard principals that could allow unauthorized access"
      ]
    },
    score_breakdown: {
      permissions: {
        positive: [
          "Specific resource ARNs used instead of wildcards (*)",
          "Actions limited to minimum required operations (Get, List, Put)",
          "Regional restrictions applied to CloudWatch Logs"
        ],
        improvements: [
          "Consider adding time-based access restrictions using aws:CurrentTime condition",
          "Add IP-based restrictions if Lambda runs from known IP ranges"
        ]
      },
      trust: {
        positive: [
          "Service principal correctly configured for Lambda",
          "Source account condition prevents cross-account abuse",
          "No overly permissive wildcards in trust relationships"
        ],
        improvements: [
          "Consider adding aws:SourceArn for even more specificity",
          "Review whether external ID is needed for third-party access scenarios"
        ]
      }
    },
    security_features: {
      permissions: [
        "Resource-level restrictions prevent access to unintended S3 buckets",
        "Least-privilege principle limits potential damage from compromised credentials",
        "Logging permissions scoped to specific function's log group"
      ],
      trust: [
        "Service-specific trust relationship ensures only Lambda can use this role",
        "Account-level restrictions prevent cross-account misuse"
      ]
    },
    refinement_suggestions: {
      permissions: [
        "Add KMS key permissions if using encrypted S3 objects",
        "Consider S3:GetObjectAcl if you need to read object permissions",
        "Add s3:PutObject if Lambda needs to write files back to S3"
      ],
      trust: [
        "Add aws:SourceArn condition to restrict to specific Lambda function ARN",
        "Consider External ID if this role will be assumed by third-party services"
      ]
    },
    compliance_status: complianceStatus,
    compliance_features: complianceFeatures,
    reasoning: {
      plan: "Analyzed the permission requirements and identified the minimum necessary AWS actions and resources needed for a Lambda function to read from S3 and write logs.",
      actions: [
        "Identified specific S3 actions needed (GetObject, GetObjectVersion, ListBucket)",
        "Applied resource-level restrictions to limit access to specific bucket",
        "Added CloudWatch Logs permissions scoped to function's log group",
        request.restrictive ? "Applied additional security hardening with conditional restrictions" : "Applied standard security measures",
        "Configured trust policy with source account condition to prevent confused deputy attacks"
      ],
      reflection: "The generated policy balances functionality requirements with security best practices. All permissions are scoped to specific resources, and the trust policy includes account-level conditions to prevent unauthorized access."
    }
  };
};

// ============================================
// VALIDATE POLICY DEMO DATA
// ============================================

export const mockValidatePolicyResponse = (request: ValidatePolicyRequest): ValidatePolicyResponse => {
  // If validating via ARN, return response with role_details
  const isArnValidation = !request.policy_json && request.role_arn;
  
  const findings: SecurityFinding[] = [
    {
      id: "finding-1",
      severity: "High",
      type: "OverPrivileged",
      title: "Overly Broad S3 Permissions",
      description: "The policy grants s3:* permissions on all resources, which provides unnecessary access to all S3 operations across all buckets in your account.",
      recommendation: "Restrict S3 actions to specific operations (GetObject, PutObject, ListBucket) and limit to specific bucket ARNs.",
      affectedStatement: 0,
      code_snippet: `"Action": "s3:*",
"Resource": "*"`
    },
    {
      id: "finding-2",
      severity: "Medium",
      type: "Security",
      title: "Missing Resource Constraints",
      description: "CloudWatch Logs permissions use wildcard (*) for resources, allowing access to all log groups and streams in the account.",
      recommendation: "Add specific log group ARNs to limit the scope of logging permissions to intended log groups only.",
      affectedStatement: 1,
      code_snippet: `"Action": ["logs:CreateLogGroup", "logs:PutLogEvents"],
"Resource": "*"`
    },
    {
      id: "finding-3",
      severity: "Low",
      type: "BestPractice",
      title: "Missing Condition Constraints",
      description: "No conditional access controls are applied to limit when and how permissions can be used (e.g., IP restrictions, time-based access, MFA).",
      recommendation: "Add conditions like aws:SourceIp for IP allowlisting, aws:CurrentTime for time-based access, or aws:MultiFactorAuthPresent for MFA requirements.",
      affectedStatement: 0,
      code_snippet: `"Effect": "Allow",
"Action": "s3:*"`
    }
  ];

  const riskScore = 75;
  const securityScore = 25; // Inverted from risk
  
  const recommendations = [
    "Replace s3:* with specific actions: s3:GetObject, s3:PutObject, s3:ListBucket",
    "Replace Resource:'*' with specific ARNs for your S3 buckets and log groups",
    "Add conditional access controls (aws:SourceIp, aws:SecureTransport, aws:MultiFactorAuthPresent)",
    "Enable CloudTrail logging to monitor policy usage and detect anomalies",
    "Implement automated policy reviews every 90 days to remove unused permissions"
  ];

  const complianceStatus: Record<string, ComplianceFramework> = {
    "pci-dss": {
      name: "PCI DSS",
      status: "Partial",
      gaps: ["Network access controls", "Encryption enforcement", "Least privilege violations"],
      violations: [
        {
          requirement: "Requirement 7.1.2 (Least Privilege)",
          description: "Policy grants overly broad s3:* permissions that violate the principle of least privilege.",
          fix: "Replace s3:* with specific actions (GetObject, PutObject) and limit to specific bucket ARNs."
        }
      ]
    },
    "hipaa": {
      name: "HIPAA",
      status: "NonCompliant",
      gaps: ["Access logging", "Encryption controls", "Audit trails", "Minimum necessary access"],
      violations: [
        {
          requirement: "164.308(a)(4) - Access Controls",
          description: "Policy grants excessive permissions that violate HIPAA's minimum necessary standard.",
          fix: "Implement least-privilege access with specific resource restrictions and encryption requirements."
        },
        {
          requirement: "164.312(b) - Audit Controls",
          description: "CloudWatch permissions are too broad, making effective audit trails difficult.",
          fix: "Scope logging permissions to specific log groups related to PHI processing."
        }
      ]
    },
    "sox": {
      name: "SOX",
      status: "Partial",
      gaps: ["Change management controls", "Access segregation"],
      violations: [
        {
          requirement: "Section 404 - Internal Controls",
          description: "Wildcard permissions make it difficult to enforce proper separation of duties.",
          fix: "Implement role-based access with specific, segregated permissions for different operational functions."
        }
      ]
    },
    "gdpr": {
      name: "GDPR",
      status: "Partial",
      gaps: ["Data protection measures", "Access controls"],
      violations: [
        {
          requirement: "Article 32 - Security of Processing",
          description: "Broad S3 permissions may affect ability to protect personal data adequately.",
          fix: "Implement strict access controls with encryption requirements and specific resource limitations."
        }
      ]
    }
  };

  // Build response - include role_details if validating via ARN
  const response: any = {
    conversation_id: "demo-validate-" + Date.now(),
    final_answer: isArnValidation 
      ? `Validation complete for role ${request.role_arn}. Found 3 security findings: 1 High, 1 Medium, 1 Low severity.`
      : "Validation complete. Found 3 security findings: 1 High, 1 Medium, 1 Low severity.",
    message_count: 1,
    policy: null,
    findings,
    risk_score: riskScore,
    security_issues: [
      "Excessive permissions granted beyond functional requirements",
      "Lack of resource-level restrictions increases attack surface",
      "Missing security conditions and constraints",
      "No encryption enforcement for S3 operations"
    ],
    recommendations,
    compliance_status: complianceStatus,
    permissions_score: securityScore,
    trust_score: 0,
    overall_score: securityScore
  };
  
  // Add role_details for ARN validation
  if (isArnValidation && request.role_arn) {
    response.role_details = {
      role_arn: request.role_arn,
      role_name: request.role_arn.split('/').pop() || 'ExampleRole',
      attached_policies: [
        {
          name: "S3FullAccess",
          arn: "arn:aws:iam::123456789012:policy/S3FullAccess",
          document: {
            Version: "2012-10-17",
            Statement: [{
              Effect: "Allow",
              Action: "s3:*",
              Resource: "*"
            }]
          }
        },
        {
          name: "CloudWatchLogsFullAccess",
          arn: "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
          document: {
            Version: "2012-10-17",
            Statement: [{
              Effect: "Allow",
              Action: "logs:*",
              Resource: "*"
            }]
          }
        }
      ],
      inline_policies: [],
      trust_policy: {
        Version: "2012-10-17",
        Statement: [{
          Effect: "Allow",
          Principal: {
            Service: "lambda.amazonaws.com"
          },
          Action: "sts:AssumeRole"
        }]
      },
      instance_profiles: []
    };
  }
  
  return response;
};

// ============================================
// AUDIT ACCOUNT DEMO DATA
// ============================================

export const mockAuditAccountResponse = () => {
  return {
    success: true,
    audit_summary: {
      total_roles: 47,
      roles_analyzed: 47,
      total_findings: 23,
      critical_issues: 2,
      high_issues: 8,
      medium_issues: 10,
      low_issues: 3,
      cloudtrail_events_analyzed: 125000,
      unused_permissions_found: 156
    },
    risk_score: 65,
    security_score: 35,
    findings: [
      {
        id: "audit-finding-1",
        severity: "Critical" as const,
        type: "OverPrivileged",
        title: "Administrator Access on Production Lambda Role",
        description: "The 'ProductionLambdaRole' has the AdministratorAccess managed policy attached, granting full access to all AWS services. CloudTrail analysis shows this role only uses S3:GetObject and Logs:PutLogEvents in practice.",
        recommendation: "Remove AdministratorAccess and replace with a custom policy granting only s3:GetObject on specific buckets and logs:PutLogEvents on specific log groups.",
        role: "ProductionLambdaRole",
        affected_permissions: ["*:*"],
        why_it_matters: "Administrator permissions on production roles create an enormous attack surface. If this role is compromised (e.g., through Lambda code injection), an attacker would have complete control over your entire AWS account, including the ability to delete resources, steal data, or create new admin users.",
        impact: "Critical - Full AWS account compromise possible if role is compromised",
        detailed_remediation: "1. Analyze CloudTrail logs to confirm actual permissions used\n2. Create new custom policy with only s3:GetObject and logs:PutLogEvents\n3. Test in staging environment\n4. Swap policies during maintenance window\n5. Monitor for AccessDenied errors",
        compliance_violations: ["PCI DSS 7.1.2", "HIPAA 164.308(a)(4)", "SOX Section 404"],
        policy_snippet: '{"Effect": "Allow", "Action": "*", "Resource": "*"}'
      },
      {
        id: "audit-finding-2",
        severity: "High" as const,
        type: "UnusedPermissions",
        title: "156 Permissions Granted But Never Used",
        description: "Across 23 IAM roles, analysis of 90 days of CloudTrail data reveals 156 permissions that are granted but have never been invoked. This includes dangerous permissions like ec2:TerminateInstances, rds:DeleteDBInstance, and s3:DeleteBucket.",
        recommendation: "Remove all unused permissions identified in the analysis. Implement a quarterly review process to identify and remove permissions that aren't being used.",
        role: "Multiple roles (23 affected)",
        affected_permissions: ["ec2:TerminateInstances", "rds:DeleteDBInstance", "s3:DeleteBucket", "iam:DeleteRole", "lambda:DeleteFunction"],
        why_it_matters: "Unused permissions provide no operational value but significantly increase risk. If an attacker compromises any of these roles, they could use these dormant permissions to cause destruction or data loss.",
        impact: "High - Unnecessary risk exposure across multiple production roles",
        detailed_remediation: "For each role: 1) Review CloudTrail data to confirm permissions are truly unused\n2) Create new policy version excluding unused permissions\n3) Test in staging for 1 week\n4) Deploy to production\n5) Monitor for 30 days\n6) Schedule quarterly re-analysis"
      },
      {
        id: "audit-finding-3",
        severity: "High" as const,
        type: "Security",
        title: "Wildcard Resources on EC2 Management Role",
        description: "The 'EC2ManagementRole' uses Resource:'*' for EC2 permissions, allowing operations on all EC2 instances across all regions instead of limiting to specific instances or regions.",
        recommendation: "Add resource-level restrictions to limit EC2 operations to specific instance ARNs or add condition keys to restrict operations to specific regions (us-east-1, us-west-2).",
        role: "EC2ManagementRole",
        affected_permissions: ["ec2:StartInstances", "ec2:StopInstances", "ec2:TerminateInstances"],
        why_it_matters: "Without resource restrictions, this role could accidentally or maliciously affect EC2 instances in any region, including production instances that should never be terminated.",
        impact: "High - Risk of accidental or malicious termination of critical instances"
      },
      {
        id: "audit-finding-4",
        severity: "Medium" as const,
        type: "BestPractice",
        title: "Missing MFA Requirement for Sensitive Operations",
        description: "15 roles with permissions for destructive operations (Delete, Terminate) don't require MFA authentication.",
        recommendation: "Add aws:MultiFactorAuthPresent condition to all policies granting destructive permissions.",
        role: "Multiple roles (15 affected)",
        affected_permissions: ["s3:DeleteObject", "ec2:TerminateInstances", "rds:DeleteDBInstance"]
      }
    ],
    recommendations: [
      "🔴 CRITICAL: Remove AdministratorAccess from ProductionLambdaRole immediately",
      "🟠 HIGH: Remove 156 unused permissions across 23 roles to reduce attack surface",
      "🟠 HIGH: Add resource-level restrictions to EC2ManagementRole",
      "🟡 MEDIUM: Implement MFA requirements for destructive operations on 15 roles",
      "🟢 LOW: Enable AWS Config to track IAM policy changes automatically",
      "🟢 LOW: Set up CloudWatch alarms for suspicious IAM activity"
    ],
    compliance_status: {
      "pci-dss": {
        name: "PCI DSS",
        status: "Partial" as const,
        gaps: ["Network segmentation needed", "Access control specificity", "Audit logging enhancement"],
        violations: [
          {
            requirement: "Requirement 7.1.2",
            description: "Multiple roles grant broader access than necessary for job functions",
            fix: "Implement least-privilege policies based on CloudTrail usage analysis"
          }
        ]
      },
      "hipaa": {
        name: "HIPAA",
        status: "NonCompliant" as const,
        gaps: ["Access logging insufficient", "Encryption controls missing", "Minimum necessary principle violated"],
        violations: [
          {
            requirement: "164.308(a)(4)",
            description: "Administrator access violates minimum necessary access requirements",
            fix: "Replace admin policies with least-privilege, job-specific policies"
          }
        ]
      }
    },
    cloudtrail_analysis: {
      total_events: 125000,
      unused_actions: 156,
      roles_with_unused_permissions: 23,
      date_range: "Last 90 days"
    },
    timestamp: new Date().toISOString()
  };
};

// ============================================
// ANALYZE HISTORY DEMO DATA  
// ============================================

export const mockAnalyzeHistoryResponse = (request: AnalyzeHistoryRequest): AnalyzeHistoryResponse => {
  const totalPermissions = 47;
  const usedPermissions = 8;
  const usagePercentage = Math.round((usedPermissions / totalPermissions) * 100);

  const optimizedPolicy: IAMPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "OptimizedS3Access",
        Effect: "Allow",
        Action: [
          "s3:GetObject",
          "s3:PutObject"
        ],
        Resource: "arn:aws:s3:::my-bucket/data/*"
      },
      {
        Sid: "OptimizedCloudWatchLogs",
        Effect: "Allow",
        Action: [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource: "arn:aws:logs:us-east-1:*:log-group:/aws/lambda/my-function:*"
      }
    ]
  };

  const securityImprovements = [
    `Eliminated ${totalPermissions - usedPermissions} unused permissions, reducing attack surface by 83%`,
    "Removed wildcard resource permissions and applied specific resource ARNs",
    "Restricted actions to only those used in the past 90 days",
    "Applied principle of least privilege based on actual usage patterns",
    "Enhanced security posture with 67% risk reduction"
  ];

  const implementationSteps = [
    "Create a backup of the current policy before making changes",
    "Test the optimized policy in a staging environment first",
    "Deploy during maintenance window with rollback plan ready",
    "Monitor CloudTrail logs for any access denied errors after deployment",
    "Gradually reduce monitoring period once confirmed stable",
    "Schedule regular reviews every 90 days to maintain optimization"
  ];

  return {
    optimized_policy: optimizedPolicy,
    usage_summary: {
      total_permissions: totalPermissions,
      used_permissions: usedPermissions,
      unused_permissions: totalPermissions - usedPermissions,
      usage_percentage: usagePercentage
    },
    security_improvements: securityImprovements,
    implementation_steps: implementationSteps,
    risk_reduction: 67
  };
};

// ============================================
// CI/CD DEMO DATA
// ============================================

export const mockCICDAnalysisResponse = () => {
  return {
    id: "analysis-" + Math.random().toString(36).substring(2, 15),
    repo: "bhavikam28/aegis-iam",
    pr_number: 42,
    commit_sha: "7f8e9a2b",
    timestamp: new Date().toISOString(),
    risk_score: 55,
    findings: [
      {
        severity: "High" as const,
        title: "Wildcard S3 Permissions Detected",
        description: "Policy contains wildcard actions: s3:* which grants all possible S3 operations including dangerous ones like DeleteBucket."
      },
      {
        severity: "Medium" as const,
        title: "Wildcard Resources Used",
        description: "Policy uses Resource:'*' allowing actions on all S3 buckets in the account instead of specific buckets."
      }
    ],
    policies_analyzed: 2,
    files_analyzed: 1,
    status: "success" as const,
    message: "Security analysis completed. Found 2 issues across 2 IAM policies."
  };
};
