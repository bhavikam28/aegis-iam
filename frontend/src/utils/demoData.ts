import { 
  GeneratePolicyRequest, 
  GeneratePolicyResponse, 
  ValidationRequest, 
  ValidationResponse, 
  AnalyzeHistoryRequest, 
  AnalyzeHistoryResponse,
  SecurityFinding,
  IAMPolicy,
  ComplianceFramework
} from '../types';

// Detailed \"Explain Simply\" demo content (separate from per-statement breakdown)
export const DEMO_SIMPLE_PERMISSIONS_EXPLANATION = `Access Policy Explanation

What This Policy Allows

This policy grants read-only access to two types of data that your Lambda function needs in order to run safely:

1. Access to Secure Data in S3
   - The function can list objects in the S3 bucket \"my-app-uploads\".
   - It can download objects and specific object versions from that bucket.
   - It cannot write, delete, or modify any objects.

2. Access to CloudWatch Logs
   - The function can create a log group and log stream for itself.
   - It can write log events so you can see execution details, errors, and performance.
   - It cannot access or modify logs for other applications.

Who Can Use This Access

Only the Lambda function that is using this role can use these permissions. Human users or other AWS services cannot directly use this policy unless they are explicitly attached to this same role.

Security Implications

This policy follows good security practices by:
- Providing read-only access (no ability to modify or delete data)
- Limiting access to a single S3 bucket instead of all buckets in your account
- Restricting CloudWatch permissions to this Lambda's own log group

However, any Lambda function using this role will be able to read all objects in the \"my-app-uploads\" bucket, which might be more than it really needs. For extra safety, you could limit access to a specific prefix such as \"my-app-uploads/config/*\".

Resources Accessible

In business terms, this policy grants access to:
- All objects stored in the S3 bucket \"my-app-uploads\"
- CloudWatch Logs under the log group \"/aws/lambda/my-function\" in the us-east-1 region.

This type of access is typically needed for applications that read configuration files or input data from S3 and write detailed execution logs for monitoring and troubleshooting.`;

export const DEMO_SIMPLE_TRUST_EXPLANATION = `Trust Policy Explanation

What This Policy Does

This policy is a trust relationship that specifies who can use a particular IAM role. It does not grant any permissions by itself – it only establishes who is allowed to \"step into\" this role.

In this demo, it allows AWS Lambda to temporarily assume the role and use the permissions defined in the access policy.

Who Can Use It

Only the Lambda service (lambda.amazonaws.com) in your AWS account (123456789012) can assume this role. Human IAM users or other AWS services (like EC2, ECS, EKS) cannot use this role through this trust policy.

Security Implications

This is a standard trust policy for Lambda and follows security best practices by:
- Limiting role access to only the Lambda service (not human users)
- Restricting which account's Lambda functions can assume the role using aws:SourceAccount
- Preventing other services or accounts from impersonating these Lambda functions

From a security perspective, the main risk is that any Lambda function in your account which is allowed to use this role will get the S3 and CloudWatch permissions defined in the access policy. To stay safe, attach this role only to the specific Lambda functions that truly need those permissions.

Resource Access

The trust policy itself does not grant access to data. It only establishes who can use the role. The actual resources this role can access are defined in the separate permissions policy attached to it (for example, the S3 bucket \"my-app-uploads\" and the CloudWatch Logs group).

In simple terms:
- The trust policy decides who can use the role.
- The permissions policy decides what they can do once they have it.`;

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
  
  // Trust policy has Principal field, which is not in IAMPolicy type - use any
  const trustPolicy: any = {
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

  const trustExplanation = `## Trust Policy Explanation

**Trusted Entity:** lambda.amazonaws.com

**What It Means:** Only the AWS Lambda service can assume this role to execute functions. This prevents other AWS services or accounts from using these permissions.

**Security:** Prevents other services or accounts from using these permissions. The role can only be assumed by Lambda functions in your AWS account.`;

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

export const mockValidatePolicyResponse = (request: ValidationRequest): ValidationResponse => {
  // If validating via ARN, return response with role_details
  const isArnValidation = !request.policy_json && !!request.role_arn;
  
  // For ARN validation, create findings that reference attached policies
  const findings: SecurityFinding[] = isArnValidation ? [
    {
      id: "finding-1",
      severity: "High",
      type: "OverPrivileged",
      title: "Full S3 Access on Attached Policy",
      description: "The role has S3FullAccess managed policy attached, which grants s3:* permissions on all resources. This provides unnecessary access to all S3 operations across all buckets in your account.",
      recommendation: "Replace S3FullAccess with a custom policy granting only required S3 actions (GetObject, PutObject, ListBucket) and limit to specific bucket ARNs.",
      affectedStatement: 0,
      code_snippet: `"Action": "s3:*",
"Resource": "*"`
    },
    {
      id: "finding-2",
      severity: "High",
      type: "OverPrivileged",
      title: "Full CloudWatch Logs Access",
      description: "The role has CloudWatchLogsFullAccess managed policy attached, granting logs:* permissions on all resources, allowing access to all log groups and streams in the account.",
      recommendation: "Create a custom policy scoping CloudWatch Logs permissions to specific log groups needed by this Lambda function.",
      affectedStatement: 0,
      code_snippet: `"Action": "logs:*",
"Resource": "*"`
    },
    {
      id: "finding-3",
      severity: "Medium",
      type: "Security",
      title: "Trust Policy Missing Source Account Condition",
      description: "The trust policy allows Lambda service to assume this role without restricting it to a specific AWS account, which could allow cross-account confused deputy attacks.",
      recommendation: "Add aws:SourceAccount condition to restrict role assumption to your specific AWS account ID.",
      affectedStatement: 0,
      code_snippet: `"Principal": {
  "Service": "lambda.amazonaws.com"
}`
    },
    {
      id: "finding-4",
      severity: "Low",
      type: "BestPractice",
      title: "No Permissions Boundary Set",
      description: "This role does not have a permissions boundary configured. Permissions boundaries provide an additional safety mechanism to limit maximum permissions.",
      recommendation: "Consider adding a permissions boundary to this role to set the maximum permissions it can have, even if policies are modified in the future.",
      affectedStatement: undefined,
      code_snippet: undefined
    }
  ] : [
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

  // Different risk scores for ARN vs policy validation
  const riskScore = isArnValidation ? 82 : 75;
  const securityScore = isArnValidation ? 18 : 25; // Inverted from risk
  
  const recommendations = isArnValidation ? [
    "Replace S3FullAccess managed policy with custom policy granting only required S3 actions (GetObject, PutObject) and limit to specific bucket ARNs",
    "Replace CloudWatchLogsFullAccess managed policy with custom policy scoped to specific log groups (/aws/lambda/my-function/*)",
    "Add aws:SourceAccount condition to trust policy to prevent cross-account role assumption",
    "Consider adding a permissions boundary to limit maximum permissions even if policies are modified",
    "Review attached managed policies and replace with least-privilege custom policies based on actual usage",
    "Enable CloudTrail logging to monitor role usage and detect anomalies"
  ] : [
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
      ? `Validation complete for role ${request.role_arn}. Found 4 security findings: 2 High, 1 Medium, 1 Low severity. The role has overly permissive managed policies attached.`
      : "Validation complete. Found 3 security findings: 1 High, 1 Medium, 1 Low severity.",
    message_count: 1,
    policy: null,
    findings,
    risk_score: riskScore,
    security_issues: isArnValidation ? [
      "Full S3 and CloudWatch Logs access via managed policies violates least-privilege principle",
      "Trust policy missing source account restriction allows potential cross-account abuse",
      "No permissions boundary configured to limit maximum role permissions",
      "Managed policies grant broader access than necessary for Lambda function requirements"
    ] : [
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
      user_managed_roles: 12,
      aws_service_roles_excluded: 35,
      roles_analyzed: 12,
      total_findings: 5, // Reduced from 23 due to grouping
      critical_issues: 1,
      high_issues: 2,
      medium_issues: 1,
      low_issues: 1,
      cloudtrail_events_analyzed: 12500,
      unused_permissions_found: 23
    },
    risk_score: 65,
    security_score: 35,
    findings: [
      {
        id: "audit-finding-1",
        severity: "Critical" as const,
        type: "OverPrivileged",
        title: "Administrator Access Detected",
        description: "The 'ProductionLambdaRole' has the AdministratorAccess managed policy attached, granting full access to all AWS services. CloudTrail analysis shows this role only uses S3:GetObject and Logs:PutLogEvents in practice.",
        recommendation: "Remove AdministratorAccess and replace with a custom policy granting only s3:GetObject on specific buckets and logs:PutLogEvents on specific log groups.",
        role: "ProductionLambdaRole",
        affected_permissions: ["*:*"],
        why_it_matters: "Administrator access grants complete control over all AWS resources and services. If compromised, attackers can create new admin users, modify all policies, delete critical resources, access all data, and cause complete account takeover.",
        impact: "Critical Impact: Complete AWS account compromise. Attackers can create new admin users, modify all policies, delete any resource, access all data, exfiltrate sensitive information, and cause financial damage through service abuse. Violates all major compliance frameworks.",
        detailed_remediation: "1. IMMEDIATE: Review role 'ProductionLambdaRole' actual usage in CloudTrail\n2. Identify minimum permissions needed\n3. Create custom policy with only required permissions (s3:GetObject, logs:PutLogEvents)\n4. Test in staging environment\n5. Replace AdministratorAccess during maintenance window\n6. Monitor closely for 48 hours\n7. Set up alerts for any permission denied errors",
        compliance_violations: ["PCI DSS 7.1.2 (Least Privilege)", "HIPAA 164.308(a)(4) (Access Control)", "SOC 2 CC6.1", "CIS AWS 1.1, 1.2", "SOX Section 404"],
        policy_snippet: JSON.stringify({
          "Effect": "Allow",
          "Action": "*",
          "Resource": "*"
        }, null, 2)
      },
      {
        id: "audit-finding-3",
        severity: "High" as const,
        type: "UnusedPermissions",
        title: "Unused IAM Permissions Detected",
        description: "Found 156 permissions that have not been used in the last 90 days across 23 IAM roles. This includes dangerous permissions like ec2:TerminateInstances, rds:DeleteDBInstance, and s3:DeleteBucket.",
        recommendation: "Remove unused permissions to follow principle of least privilege. For each role, create new policy version excluding unused permissions identified in CloudTrail analysis.",
        role: "Multiple roles (23)",
        affected_roles_list: ["ProductionLambdaRole", "EC2ManagementRole", "S3DataAccessRole", "RDSAdminRole", "CloudWatchMonitoringRole", "IAMAdminRole", "LambdaExecutionRole", "S3BackupRole", "EC2AutoScalingRole", "RDSReadOnlyRole", "CloudFormationRole", "CodeDeployRole", "ElasticBeanstalkRole", "ECSExecutionRole", "EKSNodeRole", "APIGatewayRole", "KinesisRole", "DynamoDBRole", "SNSRole", "SQSRole", "SESRole", "Route53Role", "CloudFrontRole"],
        affected_permissions: ["ec2:TerminateInstances", "rds:DeleteDBInstance", "s3:DeleteBucket", "iam:DeleteRole", "lambda:DeleteFunction", "s3:DeleteObject", "ec2:DeleteSecurityGroup", "rds:DeleteDBCluster"],
        why_it_matters: "Unused permissions provide no operational value but significantly increase risk. If an attacker compromises any role with unused permissions, they could use these dormant permissions to cause destruction, access sensitive data, or disrupt services.",
        impact: "High - Unnecessary risk exposure without operational benefit. If compromised, attackers could use these permissions to delete resources, access sensitive data, or cause service disruptions. Increases attack surface unnecessarily.",
        detailed_remediation: "1. Review CloudTrail data to confirm 156 permissions are truly unused\n2. For each role with unused permissions, create new policy version excluding them\n3. Test in staging environment for 1 week\n4. Deploy to production with monitoring\n5. Monitor for AccessDenied errors for 30 days\n6. Schedule quarterly re-analysis to identify new unused permissions",
        compliance_violations: ["PCI DSS 7.1.2 (Least Privilege)", "HIPAA 164.308(a)(4) (Access Control)", "SOC 2 CC6.1"],
        policy_snippet: JSON.stringify({
          "Note": "156 unused permissions identified via CloudTrail analysis",
          "Sample": ["ec2:TerminateInstances", "rds:DeleteDBInstance", "s3:DeleteBucket"]
        }, null, 2)
      },
      {
        id: "audit-finding-2",
        severity: "High" as const,
        type: "Security",
        title: "Wildcard Resources Detected (1521 instances)",
        description: "Multiple roles use wildcard resources (*) allowing actions on ALL resources instead of specific ones. Affected services: access-analyzer, bedrock, cloudwatch, ec2, eks, elasticloadbalancing, logs, oam, organizations, rds, and 2 more.",
        recommendation: "Specify exact resource ARNs instead of wildcards. For each role, identify specific resources needed and replace wildcard (*) with specific ARNs.",
        role: "Multiple roles (8)",
        affected_roles_list: ["APIGatewayToSQSRole", "AWSServiceRoleForAPIGateway", "AWSServiceRoleForRDS", "AWSServiceRoleForResourceExplorer", "EC2ManagementRole", "LambdaExecutionRole", "S3DataAccessRole", "CloudWatchMonitoringRole"],
        affected_services_list: ["access-analyzer", "bedrock", "cloudwatch", "ec2", "eks", "elasticloadbalancing", "logs", "oam", "organizations", "rds", "resource-explorer-2", "secretsmanager"],
        affected_permissions: ["redshift:DescribeEventSubscriptions", "inspector2:listCoverage", "xray:getInsightImpactGraph", "cloudformation:describeType", "cloudtrail:ListTrails", "mediapackage:listOriginEndpoints", "forecast:ListPredictors", "sagemaker:getModelPackageGroupPolicy", "connect:listQuickConnects", "appsync:getResolver"],
        why_it_matters: "Wildcard resources (*) allow actions on ALL resources of a service, not just intended ones. This violates the principle of least privilege and can lead to unauthorized data access, resource deletion, or compliance violations across your entire account.",
        impact: "High Impact: Unauthorized access to unintended resources across your entire account. Attackers could read, modify, or delete resources they should not have access to, leading to data breaches, service disruption, or compliance violations (PCI DSS 7.1.2, HIPAA 164.308).",
        detailed_remediation: "1. For each affected role (8 roles total), identify specific resources needed\n2. Replace wildcard (*) with specific resource ARNs for all services\n3. Use resource-level restrictions (e.g., arn:aws:service:region:account:resource/*)\n4. Add condition keys to further restrict access if needed\n5. Test in staging environment for each role\n6. Deploy to production with monitoring\n7. Monitor CloudTrail for unauthorized access attempts across all affected roles",
        compliance_violations: ["PCI DSS 7.1.2 (Least Privilege)", "HIPAA 164.308(a)(4) (Access Control)", "GDPR Article 5 (Data Minimization)", "SOC 2 CC6.1", "CIS AWS Benchmark 1.22"],
        policy_snippet: JSON.stringify({
          "Effect": "Allow",
          "Action": ["ec2:StartInstances", "ec2:StopInstances"],
          "Resource": "*"
        }, null, 2)
      },
      {
        id: "audit-finding-4",
        severity: "Medium" as const,
        type: "BestPractice",
        title: "Missing Condition Keys (2 instances)",
        description: "2 roles with permissions for sensitive service secretsmanager lack appropriate condition keys (e.g., aws:MultiFactorAuthPresent, aws:SourceIP). This weakens security controls.",
        recommendation: "Add appropriate condition keys (e.g., aws:MultiFactorAuthPresent, aws:SourceIP, encryption requirements) to restrict access based on context.",
        role: "Multiple roles (2)",
        affected_roles_list: ["AWSServiceRoleForRDS", "ProductionLambdaRole"],
        affected_permissions: ["ec2:DescribeLocalGatewayRouteTables", "ec2:AllocateAddress", "ec2:DescribeLocalGatewayRouteTablePermissions", "ec2:DescribeVpcAttribute", "ec2:ModifyVpcEndpoint", "ec2:CreateCoipPoolPermission", "ec2:DeleteVpcEndpoints", "ec2:AuthorizeSecurityGroupIngress", "ec2:UnassignPrivateIpAddresses", "kinesis:DeleteStream"],
        why_it_matters: "Missing condition keys remove important security restrictions. Conditions like IP whitelisting, encryption requirements, or MFA enforcement add critical security layers that prevent unauthorized access even if credentials are compromised.",
        impact: "Medium - Reduced security controls allow unauthorized access even with valid credentials. Missing conditions like IP restrictions or encryption requirements increase the risk of credential theft exploitation.",
        detailed_remediation: "1. Identify appropriate condition keys for each affected role (e.g., aws:MultiFactorAuthPresent, aws:SourceIP, s3:x-amz-server-side-encryption)\n2. Add Condition block to policy statements requiring MFA for destructive operations\n3. Test condition enforcement in staging\n4. Deploy to production\n5. Monitor for AccessDenied errors from users without MFA\n6. Communicate MFA requirement to users",
        compliance_violations: ["PCI DSS 8.3 (MFA Requirements)", "HIPAA 164.312(a)(2) (Access Control)", "SOC 2 CC6.2"],
        policy_snippet: JSON.stringify({
          "Effect": "Allow",
          "Action": ["s3:DeleteObject", "ec2:TerminateInstances"],
          "Resource": "*",
          "Condition": {
            "BoolIfExists": {
              "aws:MultiFactorAuthPresent": "false"
            }
          }
        }, null, 2)
      },
      {
        id: "audit-finding-5",
        severity: "Low" as const,
        type: "BestPractice",
        title: "Missing AWS Config for IAM Tracking",
        description: "AWS Config is not enabled to automatically track IAM policy changes. This makes it difficult to audit policy modifications and detect unauthorized changes.",
        recommendation: "Enable AWS Config to track IAM policy changes automatically. Set up CloudWatch alarms for suspicious IAM activity.",
        role: null,
        affected_permissions: [],
        why_it_matters: "This finding represents a security best practice that, while not immediately critical, should be addressed to maintain a strong security posture. AWS Config provides visibility into policy changes and helps detect unauthorized modifications.",
        impact: "Low Impact: Reduced visibility into IAM policy changes. While not immediately critical, enabling AWS Config improves audit capabilities and helps detect unauthorized policy modifications.",
        detailed_remediation: "1. Enable AWS Config in your AWS account\n2. Configure IAM resource recording\n3. Set up CloudWatch alarms for IAM policy changes\n4. Review Config rules for IAM compliance\n5. Set up SNS notifications for policy changes\n6. Schedule monthly reviews of Config findings",
        compliance_violations: ["SOC 2 CC7.2 (Monitoring)", "CIS AWS Benchmark 2.5"],
        policy_snippet: JSON.stringify({
          "Note": "Enable AWS Config to track IAM policy changes",
          "Recommendation": "Use AWS Config rules to monitor IAM policy modifications"
        }, null, 2)
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
      total_events: 12500,
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
    security_score: 45, // Inverted from risk_score (100 - 55 = 45)
    findings: [
      {
        severity: "High" as const,
        type: "WildcardPermissions",
        title: "Wildcard S3 Permissions Detected",
        description: "Policy contains wildcard actions: s3:* which grants all possible S3 operations including dangerous ones like DeleteBucket.",
        recommendation: "Replace s3:* with specific actions required for your use case (e.g., s3:GetObject, s3:PutObject, s3:ListBucket). This follows the principle of least privilege and reduces the risk of accidental or malicious data deletion.",
        affected_permissions: ["s3:*"],
        impact: "High - Risk of accidental or malicious deletion of S3 buckets and objects",
        policy_snippet: '{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}'
      },
      {
        severity: "Medium" as const,
        type: "WildcardResources",
        title: "Wildcard Resources Used",
        description: "Policy uses Resource:'*' allowing actions on all S3 buckets in the account instead of specific buckets.",
        recommendation: "Restrict resources to specific bucket ARNs (e.g., arn:aws:s3:::my-bucket/*) or use condition keys to limit access to specific bucket names.",
        affected_permissions: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        impact: "Medium - Actions can be performed on any S3 bucket in the account, increasing attack surface",
        policy_snippet: '{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}'
      }
    ],
    policies_analyzed: 2,
    files_analyzed: 1,
    status: "success" as const,
    message: "Security analysis completed. Found 2 issues across 2 IAM policies."
  };
};
