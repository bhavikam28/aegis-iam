import { GeneratePolicyResponse, ValidationResponse } from '../types';

// Demo data for Generate Policy feature
export const getDemoGeneratePolicyResponse = (): GeneratePolicyResponse => {
  return {
    conversation_id: 'demo-conversation-123',
    final_answer: 'Generated IAM policies with security analysis',
    message_count: 1,
    policy: {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "DynamoDBTableAccess",
          Effect: "Allow",
          Action: [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "dynamodb:Query",
            "dynamodb:Scan"
          ],
          Resource: "arn:aws:dynamodb:us-east-1:123456789012:table/customer-uploads"
        },
        {
          Sid: "CloudWatchLogsAccess",
          Effect: "Allow",
          Action: [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ],
          Resource: "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/*:*"
        }
      ]
    },
    trust_policy: {
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
    },
    explanation: "This policy grants a Lambda function the necessary permissions to read and write to a DynamoDB table and write logs to CloudWatch. The permissions follow the principle of least privilege by restricting access to specific resources and actions required for the function's operation.",
    trust_explanation: "The trust policy allows only the Lambda service to assume this role, with an additional condition ensuring it can only be assumed from your AWS account (123456789012), preventing confused deputy attacks.",
    permissions_score: 88,
    trust_score: 92,
    overall_score: 90,
    security_notes: {
      permissions: [
        "✓ Specific resource ARNs used instead of wildcards",
        "✓ Actions are scoped to only necessary DynamoDB and CloudWatch operations",
        "✓ No administrative or unnecessary permissions granted"
      ],
      trust: [
        "✓ Service principal restricted to lambda.amazonaws.com",
        "✓ Source account condition prevents cross-account access",
        "✓ No external entity can assume this role"
      ]
    },
    score_breakdown: {
      permissions: {
        positive: [
          "Resource-level permissions (DynamoDB table-specific)",
          "Action-specific permissions (no wildcards)",
          "Least-privilege principle applied"
        ],
        improvements: [
          "Consider adding encryption requirements",
          "Add time-based access conditions if applicable"
        ]
      },
      trust: {
        positive: [
          "Service principal properly restricted",
          "Source account condition applied",
          "No external access possible"
        ],
        improvements: [
          "Consider adding source ARN condition for specific Lambda functions"
        ]
      }
    },
    security_features: {
      permissions: [
        "Resource-level access control",
        "Action-specific permissions",
        "No wildcard resources"
      ],
      trust: [
        "Service principal restriction",
        "Account-level condition",
        "Secure trust relationship"
      ]
    },
    refinement_suggestions: {
      permissions: [
        "Add KMS key permissions if encryption is required",
        "Consider adding S3 access if file processing is needed"
      ],
      trust: []
    },
    compliance_status: {
      "PCI_DSS": {
        name: "PCI DSS",
        status: "Compliant" as const,
        gaps: []
      },
      "HIPAA": {
        name: "HIPAA",
        status: "Partial" as const,
        gaps: ["Consider adding encryption at rest requirements"]
      },
      "SOX": {
        name: "SOX",
        status: "Compliant" as const,
        gaps: []
      },
      "GDPR": {
        name: "GDPR",
        status: "Compliant" as const,
        gaps: []
      },
      "CIS": {
        name: "CIS",
        status: "Compliant" as const,
        gaps: []
      }
    },
    compliance_features: [
      {
        title: "Least Privilege Access",
        subtitle: "PCI DSS Requirement 7.1.2",
        requirement: "Restrict access to cardholder data",
        description: "Policy grants only necessary permissions for DynamoDB and CloudWatch operations",
        link: "https://www.pcisecuritystandards.org"
      }
    ],
    reasoning: {
      plan: "Analyzed the Lambda function requirements and identified minimum necessary permissions for DynamoDB table operations and CloudWatch logging.",
      actions: [
        "Identified required DynamoDB actions (GetItem, PutItem, UpdateItem, DeleteItem, Query, Scan)",
        "Scoped resources to specific DynamoDB table ARN",
        "Added CloudWatch Logs permissions with resource restrictions",
        "Created trust policy with service principal and source account condition"
      ],
      reflection: "The generated policies follow AWS security best practices with resource-level restrictions and least-privilege permissions. The trust policy includes source account conditions to prevent confused deputy attacks."
    }
  };
};

// Demo data for Validate Policy feature
export const getDemoValidatePolicyResponse = (): ValidationResponse => {
  return {
    findings: [
      {
        id: "IAM-001",
        severity: "High",
        type: "Wildcard Permissions",
        title: "Wildcard Action on S3 Service",
        description: "Policy uses s3:* wildcard allowing ANY action on the S3 service for all buckets.",
        recommendation: "Replace s3:* with specific required actions like s3:GetObject, s3:PutObject based on actual usage patterns.",
        affectedStatement: 0,
        code_snippet: '"Action": "s3:*"'
      },
      {
        id: "IAM-002",
        severity: "Medium",
        type: "Wildcard Resources",
        title: "Wildcard Resource for CloudWatch Logs",
        description: "Policy uses wildcard (*) for CloudWatch Logs resources, allowing access to all log groups and streams.",
        recommendation: "Scope CloudWatch Logs permissions to specific log groups using resource ARN pattern like arn:aws:logs:region:account:log-group:/aws/lambda/your-function:*",
        affectedStatement: 1,
        code_snippet: '"Resource": "*"'
      },
      {
        id: "IAM-003",
        severity: "Medium",
        type: "Trust Policy",
        title: "Trust Policy Missing Source Conditions",
        description: "The trust policy allows Lambda service to assume this role without additional conditions like aws:SourceAccount or aws:SourceArn.",
        recommendation: "Add aws:SourceAccount condition to restrict Lambda service to functions in your account, and optionally aws:SourceArn for specific functions.",
        affectedStatement: 0,
        code_snippet: '"Effect": "Allow",\n"Principal": { "Service": "lambda.amazonaws.com" }'
      }
    ],
    risk_score: 67,
    security_issues: [
      "Wildcard permissions grant excessive access",
      "Resource-level restrictions missing",
      "Trust policy lacks source account conditions"
    ],
    recommendations: [
      "Replace s3:* with specific required actions",
      "Add aws:SourceAccount condition to the Lambda trust policy",
      "Scope CloudWatch Logs permissions to specific log groups",
      "Implement resource-level restrictions for all actions"
    ],
    quick_wins: [
      "Replace 's3:*' with specific required actions like 's3:GetObject', 's3:PutObject'",
      "Add aws:SourceAccount condition to the Lambda trust policy",
      "Scope CloudWatch Logs permissions to specific log groups using a resource ARN pattern"
    ],
    compliance_status: {
      "PCI_DSS": {
        name: "PCI DSS",
        status: "Partial" as const,
        gaps: ["Requirement 7.1.2: Wildcard permissions violate least privilege principle"]
      },
      "HIPAA": {
        name: "HIPAA",
        status: "Partial" as const,
        gaps: ["Requirement 164.308(a)(4): Insufficient access controls"]
      },
      "SOX": {
        name: "SOX",
        status: "Partial" as const,
        gaps: ["Section 404: Overly permissive access patterns"]
      },
      "GDPR": {
        name: "GDPR",
        status: "Partial" as const,
        gaps: ["Article 32: Insufficient technical security measures"]
      },
      "CIS": {
        name: "CIS",
        status: "Partial" as const,
        gaps: ["CIS 1.4: Ensure least privilege access"]
      }
    }
  };
};

// Demo data for Audit Account feature
export const getDemoAuditResponse = () => {
  return {
    summary: {
      total_roles: 12,
      roles_analyzed: 12,
      total_policies: 24,
      total_findings: 18,
      critical_findings: 2,
      high_findings: 5,
      medium_findings: 8,
      low_findings: 3,
      overall_risk_score: 68
    },
    top_risks: [
      {
        role_name: "AdminRole",
        role_arn: "arn:aws:iam::123456789012:role/AdminRole",
        risk_score: 92,
        findings_count: 8,
        critical_count: 2
      },
      {
        role_name: "EC2InstanceRole",
        role_arn: "arn:aws:iam::123456789012:role/EC2InstanceRole",
        risk_score: 78,
        findings_count: 5,
        critical_count: 0
      }
    ],
    findings: [
      {
        id: "AUDIT-001",
        role_name: "AdminRole",
        role_arn: "arn:aws:iam::123456789012:role/AdminRole",
        severity: "Critical",
        title: "Over-privileged Administrative Role",
        description: "Role has AdministratorAccess managed policy attached, granting full access to all AWS services and resources.",
        recommendation: "Remove AdministratorAccess and create least-privilege policies with only necessary permissions. Use AWS managed policies for specific services.",
        affected_resources: ["All AWS services"]
      },
      {
        id: "AUDIT-002",
        role_name: "EC2InstanceRole",
        role_arn: "arn:aws:iam::123456789012:role/EC2InstanceRole",
        severity: "High",
        title: "Wildcard S3 Permissions",
        description: "Role has s3:* permissions on all buckets (*) without resource restrictions.",
        recommendation: "Restrict S3 permissions to specific buckets and actions required by the EC2 instances. Use bucket-level and object-level resource ARNs.",
        affected_resources: ["All S3 buckets"]
      }
    ],
    compliance_status: {
      "PCI_DSS": {
        status: "Partial",
        violations: ["Requirement 7.1.2: Over-privileged roles violate least privilege"]
      },
      "HIPAA": {
        status: "Partial",
        violations: ["Requirement 164.308(a)(4): Insufficient access controls"]
      }
    },
    cloudtrail_analysis: {
      total_events: 1523,
      analyzed_period_days: 90,
      unused_permissions: [
        "s3:DeleteBucket",
        "iam:DeleteUser",
        "ec2:TerminateInstances"
      ],
      used_permissions: [
        "s3:GetObject",
        "s3:PutObject",
        "ec2:DescribeInstances",
        "lambda:InvokeFunction"
      ]
    }
  };
};

