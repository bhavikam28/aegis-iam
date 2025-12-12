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
    complianceNotes.push("✅ HIPAA: Encryption in transit and at rest enforced");
    complianceNotes.push("✅ HIPAA: Access logging and monitoring enabled for audit trails");
    complianceNotes.push("✅ HIPAA: Principle of minimum necessary access implemented");
    complianceStatus['hipaa'] = {
      name: "HIPAA",
      status: "Compliant",
      gaps: [],
      details: "Policy includes encryption requirements and least-privilege access controls suitable for HIPAA compliance.",
      requirements: [
        {
          requirement: "Access Controls (164.308(a)(4))",
          status: "Pass",
          explanation: "Policy implements least-privilege access with specific resource restrictions.",
          link: "https://www.hhs.gov/hipaa/for-professionals/security/guidance/administrative-safeguards/index.html"
        },
        {
          requirement: "Audit Controls (164.312(b))",
          status: "Pass",
          explanation: "CloudWatch logging enabled for comprehensive audit trails.",
          link: "https://www.hhs.gov/hipaa/for-professionals/security/guidance/audit-controls/index.html"
        }
      ]
    };
  } else if (request.compliance === 'pci-dss' || request.compliance === 'pci_dss') {
    complianceNotes.push("✅ PCI DSS: Least-privilege principle enforced with specific resource restrictions");
    complianceNotes.push("✅ PCI DSS: Network segmentation applied through regional restrictions");
    complianceNotes.push("✅ PCI DSS: Regular access reviews enabled via CloudTrail integration");
    complianceStatus['pci-dss'] = {
      name: "PCI DSS",
      status: "Compliant",
      gaps: [],
      details: "Policy implements least-privilege access with resource-level restrictions suitable for PCI DSS requirements.",
      requirements: [
        {
          requirement: "Requirement 7.1.2 (Least Privilege)",
          status: "Pass",
          explanation: "Permissions are scoped to specific resources (S3 bucket paths, log groups) rather than using wildcards.",
          link: "https://www.pcisecuritystandards.org/document_library/"
        },
        {
          requirement: "Requirement 10 (Logging & Monitoring)",
          status: "Pass",
          explanation: "CloudWatch logging enabled to track all API calls and resource access.",
          link: "https://www.pcisecuritystandards.org/document_library/"
        }
      ]
    };
  } else {
    // General compliance - show best practices
    complianceStatus['general'] = {
      name: "AWS Security Best Practices",
      status: "Compliant",
      gaps: [],
      details: "Policy follows AWS IAM security best practices with least-privilege access and resource restrictions.",
      requirements: [
        {
          requirement: "Least Privilege Access",
          status: "Pass",
          explanation: "All permissions are scoped to specific resources with minimal necessary actions.",
          link: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
        },
        {
          requirement: "Resource-Level Permissions",
          status: "Pass",
          explanation: "Resources are explicitly defined with ARNs instead of using wildcards (*).",
          link: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
        }
      ]
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

export const mockValidatePolicyResponse = (request: any): any => {
  const findings: any[] = [
    {
      id: "finding-1",
      severity: "High",
      type: "OverPrivileged",
      title: "Overly Broad S3 Permissions",
      description: "The policy grants s3:* permissions on all resources, which provides unnecessary access to all S3 operations across all buckets in your AWS account.",
      recommendation: "Restrict S3 actions to specific operations (GetObject, PutObject, ListBucket) and limit to specific bucket resources using ARN patterns.",
      affectedStatement: 0,
      why_it_matters: "Wildcard permissions create security risks. If this role is compromised, an attacker could read, modify, or delete data across ALL S3 buckets in your account.",
      impact: "High - Potential data breach or data loss across all S3 buckets",
      detailed_remediation: "Replace 's3:*' with specific actions: ['s3:GetObject', 's3:PutObject', 's3:ListBucket']. Replace 'Resource: *' with specific bucket ARNs like 'arn:aws:s3:::my-specific-bucket/*'.",
      compliance_violations: ["PCI DSS 7.1.2 - Least privilege principle"],
      policy_snippet: `{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}`
    },
    {
      id: "finding-2",
      severity: "Medium",
      type: "Security",
      title: "Missing Resource Constraints for CloudWatch Logs",
      description: "CloudWatch Logs permissions are granted on '*' resources without proper scoping, allowing access to all log groups.",
      recommendation: "Add specific log group ARNs to limit the scope of logging permissions to only the required log groups.",
      affectedStatement: 1,
      why_it_matters: "Broad log permissions can expose sensitive application logs or allow log tampering.",
      impact: "Medium - Potential exposure of sensitive information in logs",
      detailed_remediation: "Scope the Resource to specific log groups: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-function:*'",
      compliance_violations: ["SOX - Access control requirements"],
      policy_snippet: `{
  "Action": ["logs:CreateLogGroup", "logs:PutLogEvents"],
  "Resource": "*"
}`
    },
    {
      id: "finding-3",
      severity: "Low",
      type: "BestPractice",
      title: "Missing Condition Constraints",
      description: "No conditional access controls are applied to limit when and how permissions can be used (e.g., IP restrictions, time-based access, MFA).",
      recommendation: "Add conditions like IP restrictions, time-based access, or MFA requirements for sensitive operations.",
      affectedStatement: 0,
      why_it_matters: "Conditions add defense-in-depth. Even if credentials are compromised, conditions can prevent misuse.",
      impact: "Low - Additional security layer missing",
      detailed_remediation: "Add a Condition block with IpAddress, DateGreaterThan/DateLessThan, or aws:MultiFactorAuthPresent constraints.",
      policy_snippet: `{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
  // Missing: "Condition": {...}
}`
    }
  ];

  const riskScore = 55;
  const securityScore = 45; // 100 - riskScore
  
  const recommendations = [
    "Apply the principle of least privilege by restricting actions to only what's needed",
    "Use specific resource ARNs instead of wildcard (*) resources",
    "Add conditional access controls for enhanced security (IP restrictions, MFA requirements)",
    "Enable CloudTrail logging to monitor policy usage and detect anomalies",
    "Regularly review and audit policy permissions every 90 days",
    "Implement resource tagging strategy for better access control governance"
  ];

  const quickWins = [
    "Replace 's3:*' with specific required actions (e.g., s3:GetObject, s3:PutObject)",
    "Scope CloudWatch Logs permissions to specific log group ARNs",
    "Add Condition blocks to require MFA for sensitive S3 delete operations"
  ];

  const complianceStatus: Record<string, any> = {
    "pci-dss": {
      name: "PCI DSS",
      status: "Partial",
      gaps: ["Least privilege violations (Requirement 7.1.2)", "Missing network segmentation controls"],
      details: "The policy grants overly broad permissions that violate PCI DSS Requirement 7.1.2 (limit access to system components and cardholder data to only those individuals whose job requires such access). Specific resource-level restrictions are needed to comply.",
      link: "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-pci-dss.html",
      violations: [
        {
          requirement: "7.1.2 - Restrict access to privileged user IDs to least privileges necessary",
          description: "Policy uses wildcard permissions (s3:*) which grants more access than necessary",
          fix: "Replace s3:* with specific actions like s3:GetObject, s3:PutObject"
        }
      ]
    },
    "hipaa": {
      name: "HIPAA",
      status: "NonCompliant",
      gaps: ["Access logging not enforced", "Encryption controls missing", "Audit trails insufficient"],
      details: "HIPAA requires access controls (164.308(a)(4)) and audit controls (164.312(b)). This policy lacks encryption enforcement and detailed logging requirements for PHI access.",
      link: "https://aws.amazon.com/compliance/hipaa-compliance/",
      violations: [
        {
          requirement: "164.308(a)(4) - Information Access Management",
          description: "Overly permissive access controls do not implement minimum necessary access",
          fix: "Limit permissions to specific actions and resources based on job function"
        },
        {
          requirement: "164.312(b) - Audit Controls",
          description: "No logging conditions to ensure audit trails for PHI access",
          fix: "Add conditions to enforce CloudTrail logging and S3 access logging"
        }
      ]
    },
    "sox": {
      name: "SOX",
      status: "Partial",
      gaps: ["Insufficient access control specificity", "Missing separation of duties controls"],
      details: "SOX Section 404 requires internal controls over financial reporting. This policy's broad permissions could allow unauthorized access to financial data stored in S3.",
      link: "https://aws.amazon.com/compliance/sox/",
      violations: [
        {
          requirement: "Section 404 - Internal Controls",
          description: "Wildcard permissions reduce the effectiveness of access controls",
          fix: "Implement resource-level restrictions and separation of duties"
        }
      ]
    },
    "gdpr": {
      name: "GDPR",
      status: "Partial",
      gaps: ["Data protection measures unclear", "Access control granularity insufficient"],
      details: "GDPR Article 32 requires appropriate technical measures for data security. The wildcard permissions don't provide sufficient controls for personal data protection.",
      link: "https://aws.amazon.com/compliance/gdpr-center/",
      violations: [
        {
          requirement: "Article 32 - Security of Processing",
          description: "Overly broad permissions may not ensure appropriate security for personal data",
          fix: "Limit permissions to specific actions and implement encryption requirements via Conditions"
        }
      ]
    }
  };

  return {
    findings,
    risk_score: riskScore,
    security_score: securityScore,
    security_issues: [
      "Excessive permissions granted beyond functional requirements",
      "Lack of resource-level restrictions (use of wildcard resources)",
      "Missing security conditions and constraints (IP, MFA, encryption)",
      "No audit logging requirements enforced in the policy"
    ],
    recommendations,
    quick_wins: quickWins,
    compliance_status: complianceStatus,
    permissions_explanation: "This policy grants broad access to S3 and CloudWatch Logs services. The wildcard permissions (s3:*) allow ALL S3 operations including reading, writing, deleting, and modifying bucket configurations across ALL buckets in your account. Similarly, CloudWatch Logs permissions apply to all log groups without scoping. This exceeds typical operational requirements and creates unnecessary security risks.",
    trust_explanation: "The trust policy allows the Lambda service (lambda.amazonaws.com) to assume this role. However, it lacks additional conditions that could restrict which specific Lambda functions, accounts, or regions can use this role. Adding conditions like aws:SourceArn or aws:SourceAccount would significantly improve security.",
    role_details: {
      role_arn: "arn:aws:iam::123456789012:role/DemoLambdaExecutionRole",
      role_name: "DemoLambdaExecutionRole",
      attached_policies: [
        {
          name: "CustomS3Access",
          arn: "arn:aws:iam::123456789012:policy/CustomS3Access"
        }
      ],
      inline_policies: []
    }
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
