import { 
  GeneratePolicyRequest, 
  GeneratePolicyResponse, 
  ValidatePolicyRequest, 
  ValidatePolicyResponse, 
  AnalyzeHistoryRequest, 
  AnalyzeHistoryResponse,
  SecurityFinding,
  IAMPolicy 
} from '../types';

// ============================================
// GENERATE POLICY DEMO DATA
// ============================================

export const mockGeneratePolicyResponse = (request: any): any => {
  // Use common AWS services that everyone knows: S3, Lambda, EC2
  const service = (request.service || 'lambda').toLowerCase();
  
  let policy: IAMPolicy;
  let trustPolicy: IAMPolicy;
  let explanation: string;
  let securityScore: number;
  let trustExplanation: string;
  let permissionsExplanation: string;

  if (service === 'lambda' || service.includes('lambda')) {
    // Common Lambda use case: Read from S3, write logs
    policy = {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "AllowS3ReadAccess",
          Effect: "Allow",
          Action: [
            "s3:GetObject",
            "s3:GetObjectVersion"
          ],
          Resource: "arn:aws:s3:::my-app-bucket/*"
        },
        {
          Sid: "AllowCloudWatchLogs",
          Effect: "Allow",
          Action: [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ],
          Resource: "arn:aws:logs:*:*:log-group:/aws/lambda/my-function:*"
        }
      ]
    };
    
    trustPolicy = {
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
    
    explanation = "This policy grants minimal permissions for a Lambda function to read objects from a specific S3 bucket and write logs to CloudWatch. CloudWatch logging is restricted to the function's log group only.";
    permissionsExplanation = "This permissions policy allows the Lambda function to: (1) Read files from the S3 bucket 'my-app-bucket', (2) Create and write to CloudWatch Logs for monitoring and debugging. All permissions are scoped to specific resources following the principle of least privilege.";
    trustExplanation = "The trust policy allows only the Lambda service to assume this role, with an additional condition ensuring it can only be assumed from your AWS account (123456789012), preventing confused deputy attacks. This ensures that only Lambda functions in your account can use this role.";
    securityScore = request.restrictive ? 95 : 85;
  } else if (service === 's3' || service.includes('s3')) {
    // S3 bucket access
    policy = {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "AllowS3BucketOperations",
          Effect: "Allow",
          Action: [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject",
            "s3:ListBucket"
          ],
          Resource: [
            "arn:aws:s3:::my-app-bucket",
            "arn:aws:s3:::my-app-bucket/*"
          ],
          Condition: {
            StringEquals: {
              "s3:x-amz-server-side-encryption": "AES256"
            }
          }
        }
      ]
    };
    
    trustPolicy = {
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Principal: {
            AWS: "arn:aws:iam::123456789012:root"
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
    
    explanation = "This policy provides least-privilege access to a specific S3 bucket, allowing object operations while preventing access to other buckets. Encryption is enforced for all operations.";
    permissionsExplanation = "This permissions policy allows: (1) Reading objects from 'my-app-bucket', (2) Uploading new objects, (3) Deleting objects, (4) Listing bucket contents. All operations require server-side encryption (AES256) to protect data at rest.";
    trustExplanation = "The trust policy allows only principals from your AWS account (123456789012) to assume this role. The aws:SourceAccount condition prevents cross-account confusion and ensures that only entities in your account can use this role.";
    securityScore = request.restrictive ? 92 : 80;
  } else {
    // Generic EC2/General use case
    policy = {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "AllowEC2InstanceManagement",
          Effect: "Allow",
          Action: [
            "ec2:DescribeInstances",
            "ec2:StartInstances",
            "ec2:StopInstances",
            "ec2:RebootInstances"
          ],
          Resource: "*",
          Condition: {
            StringEquals: {
              "aws:RequestedRegion": ["us-east-1", "us-west-2"]
            }
          }
        },
        {
          Sid: "AllowS3ReadForConfig",
          Effect: "Allow",
          Action: "s3:GetObject",
          Resource: "arn:aws:s3:::config-bucket/ec2-config/*"
        }
      ]
    };
    
    trustPolicy = {
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Principal: {
            Service: "ec2.amazonaws.com"
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
    
    explanation = `This policy grants access to ${request.service} services with regional restrictions to limit the attack surface. EC2 instance management is limited to specific regions, and S3 access is restricted to configuration files only.`;
    permissionsExplanation = "This permissions policy allows: (1) Managing EC2 instances (describe, start, stop, reboot) in us-east-1 and us-west-2 regions only, (2) Reading configuration files from a specific S3 bucket. Regional restrictions prevent accidental operations in other regions.";
    trustExplanation = "The trust policy allows only the EC2 service to assume this role, restricted to your AWS account. This is used for EC2 instance profiles, allowing instances to access AWS services on your behalf securely.";
    securityScore = request.restrictive ? 88 : 75;
  }

  const securityNotes: string[] = [
    "Policy follows least-privilege principle with specific resource constraints",
    "Actions are limited to only what's necessary for the described functionality",
    request.restrictive ? "Enhanced security mode applied - additional restrictions enforced" : "Standard security mode - consider enabling restrictive mode for production",
    "Resource ARNs are explicitly specified to prevent accidental access to other resources"
  ];

  const complianceNotes: string[] = [];
  const complianceStatus: Record<string, any> = {};
  
  if (request.compliance === 'hipaa') {
    complianceNotes.push("HIPAA compliance: Encryption in transit and at rest should be enforced");
    complianceNotes.push("Access logging and monitoring must be enabled for audit trails");
    complianceStatus['hipaa'] = {
      name: "HIPAA",
      status: "Compliant",
      gaps: [],
      details: "Policy includes encryption requirements and least-privilege access controls suitable for HIPAA compliance."
    };
  } else if (request.compliance === 'pci-dss') {
    complianceNotes.push("PCI DSS compliance: Network segmentation and access controls implemented");
    complianceNotes.push("Regular access reviews and monitoring required");
    complianceStatus['pci-dss'] = {
      name: "PCI DSS",
      status: "Compliant",
      gaps: [],
      details: "Policy implements least-privilege access with resource-level restrictions suitable for PCI DSS requirements."
    };
  } else {
    // General compliance
    complianceStatus['general'] = {
      name: "General Security",
      status: "Compliant",
      gaps: [],
      details: "Policy follows AWS security best practices with least-privilege access and resource restrictions."
    };
  }

  // Build comprehensive response matching actual API structure
  return {
    conversation_id: "demo-conversation-" + Date.now(),
    final_answer: explanation,
    message_count: 1,
    policy,
    trust_policy: trustPolicy,
    explanation: permissionsExplanation,
    trust_explanation: trustExplanation,
    permissions_score: securityScore,
    trust_score: 95,
    overall_score: Math.round((securityScore + 95) / 2),
    security_notes: {
      permissions: securityNotes,
      trust: [
        "Trust policy properly restricts role assumption to the intended AWS service",
        "Source account condition prevents confused deputy attacks",
        "No wildcard principals that could allow unauthorized access"
      ]
    },
    score_breakdown: {
      permissions: {
        positive: [
          "Specific resource ARNs used instead of wildcards",
          "Actions limited to minimum required operations",
          "Conditional access controls applied where appropriate"
        ],
        improvements: [
          "Consider adding time-based access restrictions for sensitive operations",
          "Implement MFA requirements for critical actions"
        ]
      },
      trust: {
        positive: [
          "Service principal properly configured",
          "Source account condition prevents cross-account abuse",
          "No overly permissive wildcards in trust relationships"
        ],
        improvements: [
          "Consider adding aws:SourceArn for additional specificity",
          "Review external ID requirements for third-party access"
        ]
      }
    },
    security_features: {
      permissions: [
        "Resource-level restrictions prevent access to unintended resources",
        "Least-privilege principle applied throughout the policy",
        "Conditional constraints enhance security posture"
      ],
      trust: [
        "Service-specific trust relationship configured",
        "Account-level restrictions prevent cross-account misuse"
      ]
    },
    refinement_suggestions: {
      permissions: [
        "Add KMS permissions if encryption is required for data at rest",
        "Consider VPC endpoint policies for enhanced network security",
        "Implement tag-based access controls for better governance"
      ],
      trust: [
        "Add aws:SourceArn condition to specify exact service ARN",
        "Consider external ID if this role will be assumed by third parties",
        "Review session duration and add aws:MultiFactorAuthPresent for sensitive roles"
      ]
    },
    compliance_status: complianceStatus,
    compliance_features: Object.values(complianceStatus).map((framework: any) => ({
      title: framework.name,
      subtitle: framework.status,
      requirement: `${framework.name} Requirement`,
      description: framework.details || "Policy follows security best practices for this compliance framework.",
      link: framework.link
    })),
    reasoning: {
      plan: "Analyzed the permission requirements and identified the minimum necessary AWS actions and resources needed for the described functionality.",
      actions: [
        "Identified specific AWS service actions required",
        "Applied resource-level restrictions where possible",
        "Added conditional access controls for enhanced security",
        request.restrictive ? "Applied additional security hardening measures" : "Applied standard security measures",
        "Configured trust policy with source account conditions to prevent confused deputy attacks"
      ],
      reflection: "The generated policy balances functionality requirements with security best practices. All permissions are scoped to specific resources where possible, and unnecessary broad permissions have been eliminated to reduce the attack surface."
    }
  };
};

// ============================================
// VALIDATE POLICY DEMO DATA
// ============================================

export const mockValidatePolicyResponse = (request: ValidatePolicyRequest): ValidatePolicyResponse => {
  const findings: SecurityFinding[] = [
    {
      id: "finding-1",
      severity: "High",
      type: "OverPrivileged",
      title: "Overly Broad S3 Permissions",
      description: "The policy grants s3:* permissions on all resources, which provides unnecessary access to all S3 operations across all buckets.",
      recommendation: "Restrict S3 actions to specific operations (GetObject, PutObject) and limit to specific bucket resources.",
      affectedStatement: 0,
      codeSnippet: `"Action": "s3:*",
"Resource": "*"`
    },
    {
      id: "finding-2",
      severity: "Medium",
      type: "Security",
      title: "Missing Resource Constraints",
      description: "Several actions are granted on '*' resources without proper scoping.",
      recommendation: "Add specific resource ARNs to limit the scope of permissions.",
      affectedStatement: 1,
      codeSnippet: `"Action": ["logs:CreateLogGroup", "logs:PutLogEvents"],
"Resource": "*"`
    },
    {
      id: "finding-3",
      severity: "Low",
      type: "BestPractice",
      title: "Missing Condition Constraints",
      description: "No conditional access controls are applied to limit when and how permissions can be used.",
      recommendation: "Add conditions like IP restrictions, time-based access, or MFA requirements.",
      affectedStatement: 0,
      codeSnippet: `"Effect": "Allow",
"Action": "s3:*"`
    }
  ];

  const riskScore = request.policy_json?.includes('"*"') ? 75 : 45;
  
  const recommendations = [
    "Apply the principle of least privilege by restricting actions to only what's needed",
    "Use specific resource ARNs instead of wildcard (*) resources",
    "Add conditional access controls for enhanced security",
    "Enable CloudTrail logging to monitor policy usage",
    "Regularly review and audit policy permissions"
  ];

  const complianceStatus: Record<string, any> = {
    "pci-dss": {
      name: "PCI DSS",
      status: "Partial",
      gaps: ["Network access controls", "Encryption requirements"],
      details: "Policy requires additional restrictions to fully comply with PCI DSS requirements.",
      link: "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-pci-dss.html"
    },
    "hipaa": {
      name: "HIPAA",
      status: "NonCompliant",
      gaps: ["Access logging", "Encryption controls", "Audit trails"],
      details: "Policy lacks required HIPAA compliance controls for access logging and encryption.",
      link: "https://aws.amazon.com/compliance/hipaa-compliance/"
    },
    "gdpr": {
      name: "GDPR",
      status: "Partial",
      gaps: ["Data protection measures", "Access controls"],
      details: "Some GDPR requirements are met, but additional data protection measures are needed.",
      link: "https://aws.amazon.com/compliance/gdpr-center/"
    }
  };

  return {
    findings,
    risk_score: riskScore,
    security_issues: [
      "Excessive permissions granted beyond functional requirements",
      "Lack of resource-level restrictions",
      "Missing security conditions and constraints"
    ],
    recommendations,
    compliance_status: complianceStatus,
    permissions_explanation: "This policy grants broad access to S3 and CloudWatch Logs services. The permissions allow reading, writing, and deleting objects across all S3 buckets, which exceeds typical operational requirements.",
    trust_explanation: "The trust policy allows the Lambda service to assume this role. However, it lacks additional conditions that could restrict which specific Lambda functions or accounts can use this role."
  };
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
        severity: "Critical",
        type: "OverPrivileged",
        title: "Admin-Level Permissions on Production Role",
        description: "The 'ProductionAppRole' has administrator-level permissions (AdministratorAccess) but is only used for reading S3 objects based on CloudTrail analysis.",
        recommendation: "Replace AdministratorAccess with least-privilege permissions based on actual usage patterns.",
        role: "ProductionAppRole",
        affected_permissions: ["*"],
        why_it_matters: "Admin permissions on production roles create a massive attack surface. If compromised, an attacker would have full access to your AWS account.",
        impact: "High - Full account compromise possible",
        detailed_remediation: "Analyze CloudTrail logs to identify actual permissions used. Create a new policy with only those permissions and attach it to the role.",
        compliance_violations: ["PCI DSS 7.1.2", "HIPAA 164.308(a)(4)"],
        policy_snippet: '{"Effect": "Allow", "Action": "*", "Resource": "*"}'
      },
      {
        id: "audit-finding-2",
        severity: "High",
        type: "UnusedPermissions",
        title: "156 Unused Permissions Detected",
        description: "Analysis of CloudTrail logs over the past 90 days shows 156 permissions that are granted but never used across 23 IAM roles.",
        recommendation: "Remove unused permissions to reduce attack surface and follow least-privilege principle.",
        role: "Multiple roles",
        affected_permissions: ["ec2:TerminateInstances", "rds:DeleteDBInstance", "s3:DeleteBucket"],
        why_it_matters: "Unused permissions increase the risk of accidental or malicious misuse without providing any benefit.",
        impact: "Medium - Potential for unauthorized actions",
        detailed_remediation: "Review the list of unused permissions. For each role, remove permissions that haven't been used in the last 90 days after confirming they're not needed for future operations."
      }
    ],
    recommendations: [
      "Review and reduce permissions on 23 roles with unused access",
      "Implement resource-level restrictions on 15 roles using wildcard resources",
      "Add conditional access controls to 8 roles with sensitive permissions",
      "Enable MFA for all roles with admin-level permissions",
      "Set up CloudTrail monitoring alerts for suspicious activity"
    ],
    compliance_status: {
      "pci-dss": {
        status: "Partial",
        gaps: ["Network segmentation", "Access control specificity"],
        details: "Some PCI DSS requirements are met, but additional network and access controls are needed."
      },
      "hipaa": {
        status: "NonCompliant",
        gaps: ["Access logging", "Encryption controls"],
        details: "HIPAA compliance requires enhanced access logging and encryption controls."
      }
    },
    cloudtrail_analysis: {
      total_events: 125000,
      unused_actions: 156,
      roles_with_unused_permissions: 23
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
    id: "demo-analysis-1",
    repo: "bhavikam28/aegis-iam",
    pr_number: 42,
    commit_sha: "abc123def456",
    timestamp: new Date().toISOString(),
    risk_score: 55,
    findings: [
      {
        severity: "High" as const,
        title: "Wildcard Permissions Detected",
        description: "Policy contains wildcard actions: s3:* which grants all S3 operations."
      },
      {
        severity: "Medium" as const,
        title: "Missing Resource Constraints",
        description: "Policy uses wildcard (*) resources without proper scoping."
      }
    ],
    policies_analyzed: 2,
    files_analyzed: 1,
    status: "success" as const,
    message: "Analysis completed successfully. 2 security findings detected."
  };
};
