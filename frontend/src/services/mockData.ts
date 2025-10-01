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

export const mockGeneratePolicyResponse = (request: GeneratePolicyRequest): GeneratePolicyResponse => {
  // Generate realistic policy based on service and description
  const service = request.service.toLowerCase();
  
  let policy: IAMPolicy;
  let explanation: string;
  let securityScore: number;

  if (service === 'lambda') {
    policy = {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "AllowLambdaExecution",
          Effect: "Allow",
          Action: [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ],
          Resource: "arn:aws:logs:*:*:log-group:/aws/lambda/*"
        },
        {
          Sid: "AllowDynamoDBAccess",
          Effect: "Allow",
          Action: [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem"
          ],
          Resource: "arn:aws:dynamodb:*:*:table/customer-data"
        }
      ]
    };
    explanation = "This policy grants minimal permissions for a Lambda function to execute and interact with a specific DynamoDB table. CloudWatch logging is restricted to the function's log group.";
    securityScore = request.restrictive ? 95 : 78;
  } else if (service === 's3') {
    policy = {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "AllowS3BucketAccess",
          Effect: "Allow",
          Action: [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject"
          ],
          Resource: "arn:aws:s3:::my-app-bucket/*"
        },
        {
          Sid: "AllowS3BucketList",
          Effect: "Allow",
          Action: "s3:ListBucket",
          Resource: "arn:aws:s3:::my-app-bucket"
        }
      ]
    };
    explanation = "This policy provides least-privilege access to a specific S3 bucket, allowing object operations while preventing access to other buckets.";
    securityScore = request.restrictive ? 92 : 75;
  } else {
    // Generic policy for other services
    policy = {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "AllowServiceAccess",
          Effect: "Allow",
          Action: `${service}:*`,
          Resource: "*",
          Condition: {
            StringEquals: {
              "aws:RequestedRegion": ["us-east-1", "us-west-2"]
            }
          }
        }
      ]
    };
    explanation = `This policy grants access to ${request.service} services with regional restrictions to limit the attack surface.`;
    securityScore = request.restrictive ? 85 : 65;
  }

  const securityNotes: string[] = [
    "Policy follows least-privilege principle with specific resource constraints",
    "Actions are limited to only what's necessary for the described functionality",
    request.restrictive ? "Enhanced security mode applied - additional restrictions enforced" : "Standard security mode - consider enabling restrictive mode for production"
  ];

  const complianceNotes: string[] = [];
  if (request.compliance === 'hipaa') {
    complianceNotes.push("HIPAA compliance: Encryption in transit and at rest should be enforced");
    complianceNotes.push("Access logging and monitoring must be enabled for audit trails");
  } else if (request.compliance === 'pci-dss') {
    complianceNotes.push("PCI DSS compliance: Network segmentation and access controls implemented");
    complianceNotes.push("Regular access reviews and monitoring required");
  }

  return {
    policy,
    explanation,
    security_notes: securityNotes,
    compliance_notes: complianceNotes,
    security_score: securityScore,
    reasoning: {
      plan: "Analyzed the permission requirements and identified the minimum necessary AWS actions and resources needed for the described functionality.",
      actions: [
        "Identified specific AWS service actions required",
        "Applied resource-level restrictions where possible",
        "Added conditional access controls for enhanced security",
        request.restrictive ? "Applied additional security hardening measures" : "Applied standard security measures"
      ],
      reflection: "The generated policy balances functionality requirements with security best practices. All permissions are scoped to specific resources where possible, and unnecessary broad permissions have been eliminated to reduce the attack surface."
    }
  };
};

export const mockValidatePolicyResponse = (request: ValidatePolicyRequest): ValidatePolicyResponse => {
  const findings: SecurityFinding[] = [
    {
      id: "finding-1",
      severity: "High",
      type: "OverPrivileged",
      title: "Overly Broad S3 Permissions",
      description: "The policy grants s3:* permissions on all resources, which provides unnecessary access to all S3 operations across all buckets.",
      recommendation: "Restrict S3 actions to specific operations (GetObject, PutObject) and limit to specific bucket resources.",
      affectedStatement: 0
    },
    {
      id: "finding-2",
      severity: "Medium",
      type: "Security",
      title: "Missing Resource Constraints",
      description: "Several actions are granted on '*' resources without proper scoping.",
      recommendation: "Add specific resource ARNs to limit the scope of permissions.",
      affectedStatement: 1
    },
    {
      id: "finding-3",
      severity: "Low",
      type: "BestPractice",
      title: "Missing Condition Constraints",
      description: "No conditional access controls are applied to limit when and how permissions can be used.",
      recommendation: "Add conditions like IP restrictions, time-based access, or MFA requirements.",
      affectedStatement: 0
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

  const complianceStatus = {
    "pci-dss": {
      name: "PCI DSS",
      status: "Partial" as const,
      gaps: ["Network access controls", "Encryption requirements"]
    },
    "hipaa": {
      name: "HIPAA",
      status: "NonCompliant" as const,
      gaps: ["Access logging", "Encryption controls", "Audit trails"]
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
    compliance_status: complianceStatus
  };
};

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