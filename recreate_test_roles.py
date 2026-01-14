#!/usr/bin/env python3
"""
Delete and recreate test roles with EXPLICIT permissions (no wildcards)
This ensures remediation will work properly
"""

import boto3
import json

def delete_and_recreate_role(iam, role_name: str, used_permissions: list, unused_permissions: list, description: str):
    """Delete existing role and recreate with explicit permissions"""
    try:
        # Try to delete existing role
        try:
            # Delete inline policies first
            try:
                policies = iam.list_role_policies(RoleName=role_name)['PolicyNames']
                for policy_name in policies:
                    iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
                    print(f"   🗑️  Deleted policy: {policy_name}")
            except:
                pass
            
            # Delete role
            iam.delete_role(RoleName=role_name)
            print(f"   🗑️  Deleted existing role: {role_name}")
        except iam.exceptions.NoSuchEntityException:
            print(f"   ℹ️  Role {role_name} doesn't exist, will create new")
        except Exception as e:
            print(f"   ⚠️  Could not delete {role_name}: {e}")
            return False
        
        # Trust policy
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }
        
        # Permissions policy with EXPLICIT actions only (NO WILDCARDS)
        permissions_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": used_permissions + unused_permissions,  # Explicit list
                "Resource": "*"
            }]
        }
        
        # Create role
        print(f"   ✅ Creating role: {role_name}")
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=description
        )
        
        # Add inline policy with EXPLICIT permissions
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName='TestPolicy',
            PolicyDocument=json.dumps(permissions_policy)
        )
        print(f"   ✅ Added inline policy with {len(used_permissions)} used + {len(unused_permissions)} unused EXPLICIT permissions")
        return True
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

if __name__ == "__main__":
    iam = boto3.client('iam')
    
    print("🔄 Recreating test roles with EXPLICIT permissions...")
    print("="*70)
    
    test_roles = [
        {
            'name': 'AegisTestRole1',
            'used': ['s3:GetObject', 's3:PutObject', 's3:ListBucket'],
            'unused': ['s3:DeleteBucket', 'iam:DeleteUser'],
            'description': 'Aegis Test Role 1 - S3 and IAM unused permissions (EXPLICIT)'
        },
        {
            'name': 'AegisTestRole2',
            'used': ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query'],
            'unused': ['ec2:TerminateInstances', 'rds:DeleteDBInstance'],
            'description': 'Aegis Test Role 2 - EC2 and RDS unused permissions (EXPLICIT)'
        },
        {
            'name': 'AegisTestRole3',
            'used': ['lambda:InvokeFunction', 'logs:CreateLogGroup'],
            'unused': ['iam:DeleteRole', 's3:DeleteObject'],
            'description': 'Aegis Test Role 3 - IAM and S3 unused permissions (EXPLICIT)'
        }
    ]
    
    for role_config in test_roles:
        print(f"\n📋 Processing {role_config['name']}...")
        success = delete_and_recreate_role(
            iam,
            role_config['name'],
            role_config['used'],
            role_config['unused'],
            role_config['description']
        )
        if success:
            print(f"   ✅ {role_config['name']} ready for remediation testing!")
    
    print("\n" + "="*70)
    print("✅ DONE! Test roles recreated with EXPLICIT permissions")
    print("="*70)
    print("\n🎯 Next steps:")
    print("1. Run audit in Aegis IAM")
    print("2. You should see 'Unused IAM Permissions Detected' for these roles")
    print("3. Click 'Remediate All' - it should work now!")
    print("4. If you remediate again, it will say 'Already Remediated' ✅")
