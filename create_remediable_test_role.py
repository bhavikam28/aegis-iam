#!/usr/bin/env python3
"""
Create a test IAM role that CAN be auto-remediated by Aegis IAM.

This role has:
- Inline policy with EXPLICIT permissions (no wildcards)
- Some intentionally unused permissions
- Can be successfully remediated by removing unused permissions
"""

import boto3
import json

def create_remediable_test_role():
    iam = boto3.client('iam')
    role_name = "AegisRemediableTestRole"
    policy_name = "AegisRemediableTestPolicy"
    
    print("=" * 60)
    print("Creating Test Role for Successful Remediation")
    print("=" * 60)
    
    # Trust policy (who can assume this role)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    # Inline policy with EXPLICIT permissions (no wildcards!)
    # Some are commonly used, some are unused (will be removed)
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    # ✅ USED permissions (commonly used by Lambda):
                    "s3:GetObject",              # Used
                    "s3:PutObject",              # Used
                    "s3:ListBucket",             # Used
                    "logs:CreateLogGroup",       # Used
                    "logs:CreateLogStream",      # Used
                    "logs:PutLogEvents",         # Used
                    
                    # ❌ UNUSED permissions (will be flagged for removal):
                    "s3:DeleteBucket",           # Unused - DANGEROUS!
                    "s3:DeleteObject",           # Unused - can be removed
                    "iam:DeleteRole",            # Unused - DANGEROUS!
                    "iam:DeleteUser",            # Unused - DANGEROUS!
                    "ec2:TerminateInstances",    # Unused - DANGEROUS!
                    "rds:DeleteDBInstance",      # Unused - DANGEROUS!
                    "lambda:DeleteFunction",     # Unused - can be removed
                    "dynamodb:DeleteTable"       # Unused - DANGEROUS!
                ],
                "Resource": [
                    "arn:aws:s3:::my-test-bucket",
                    "arn:aws:s3:::my-test-bucket/*",
                    "arn:aws:logs:*:*:*",
                    "arn:aws:iam::*:role/*",
                    "arn:aws:ec2:*:*:instance/*",
                    "arn:aws:rds:*:*:db:*",
                    "arn:aws:lambda:*:*:function:*",
                    "arn:aws:dynamodb:*:*:table/*"
                ]
            }
        ]
    }
    
    try:
        # Create role
        print(f"\n[*] Creating role: {role_name}...")
        try:
            create_role_response = iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="Test role for Aegis IAM auto-remediation demo - has explicit unused permissions"
            )
            print(f"   Role created successfully!")
            print(f"   ARN: {create_role_response['Role']['Arn']}")
        except iam.exceptions.EntityAlreadyExistsException:
            print(f"   Role '{role_name}' already exists. Updating policy...")
        
        # Attach inline policy
        print(f"\n[*] Attaching inline policy: {policy_name}...")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(inline_policy)
        )
        print(f"   Policy attached successfully!")
        
        print("\n" + "=" * 60)
        print("TEST ROLE CREATED SUCCESSFULLY!")
        print("=" * 60)
        
        print(f"\nRole Details:")
        print(f"   Name: {role_name}")
        print(f"   Type: INLINE POLICY (not managed)")
        print(f"   Permissions: EXPLICIT (no wildcards)")
        
        print(f"\nUsed Permissions (6):")
        used = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", 
                "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        for perm in used:
            print(f"      + {perm}")
        
        print(f"\nUnused Permissions (8) - WILL BE REMOVED:")
        unused = ["s3:DeleteBucket", "s3:DeleteObject", "iam:DeleteRole", 
                  "iam:DeleteUser", "ec2:TerminateInstances", "rds:DeleteDBInstance",
                  "lambda:DeleteFunction", "dynamodb:DeleteTable"]
        for perm in unused:
            print(f"      - {perm}")
        
        print(f"\nNext Steps:")
        print(f"   1. Run a new audit in Aegis IAM")
        print(f"   2. Look for 'Unused IAM Permissions Detected' finding")
        print(f"   3. Select {role_name} for remediation")
        print(f"   4. Watch it SUCCESSFULLY remove the 8 unused permissions!")
        
        print(f"\nThis role CAN be auto-remediated because:")
        print(f"   + Has inline policy (not managed)")
        print(f"   + Uses explicit permissions (no wildcards)")
        print(f"   + Has unused permissions to remove")
        print(f"   + Won't break anything (unused permissions are safe to remove)")
        
        print("\n" + "=" * 60)
        
    except Exception as e:
        print(f"\n[ERROR] {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("\nAegis IAM - Create Remediable Test Role\n")
    success = create_remediable_test_role()
    
    if success:
        print("\nSUCCESS! Run your audit now to see remediation work!\n")
    else:
        print("\nFAILED! Check the error above.\n")

