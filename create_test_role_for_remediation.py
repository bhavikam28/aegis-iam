#!/usr/bin/env python3
"""
Create MULTIPLE test IAM roles with EXPLICIT permissions that can be auto-remediated.

These roles will have:
- Inline policies (not managed)
- Explicit actions (not wildcards)
- Unused permissions that can be safely removed
- Multiple roles to test multi-role remediation display
"""

import boto3
import json
import sys

def create_test_role(iam, role_name: str, unused_permissions: list, used_permissions: list, description: str):
    """Create a single test role with specified permissions"""
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
    
    # Permissions policy with EXPLICIT actions
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": used_permissions + unused_permissions,
                "Resource": "*"
            }
        ]
    }
    
    try:
        # Check if role exists
        try:
            iam.get_role(RoleName=role_name)
            print(f"⚠️  Role {role_name} already exists - skipping creation")
            return False
        except iam.exceptions.NoSuchEntityException:
            pass
        
        # Create role
        print(f"   Creating role: {role_name}")
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=description
        )
        print(f"   ✅ Role created: {role_name}")
        
        # Add inline policy
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName='TestPolicy',
            PolicyDocument=json.dumps(permissions_policy)
        )
        print(f"   ✅ Inline policy added with {len(used_permissions)} used + {len(unused_permissions)} unused permissions")
        return True
        
    except Exception as e:
        print(f"   ❌ Error creating {role_name}: {e}")
        return False

def create_all_test_roles():
    """Create multiple test roles for comprehensive testing"""
    iam = boto3.client('iam')
    
    print("🚀 Creating test roles for auto-remediation verification...")
    print("="*70)
    
    # Define test roles with different unused permissions
    test_roles = [
        {
            'name': 'AegisTestRole1',
            'used': ['s3:GetObject', 's3:PutObject', 's3:ListBucket'],
            'unused': ['s3:DeleteBucket', 'iam:DeleteUser'],
            'description': 'Aegis Test Role 1 - S3 and IAM unused permissions'
        },
        {
            'name': 'AegisTestRole2',
            'used': ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query'],
            'unused': ['ec2:TerminateInstances', 'rds:DeleteDBInstance'],
            'description': 'Aegis Test Role 2 - EC2 and RDS unused permissions'
        },
        {
            'name': 'AegisTestRole3',
            'used': ['lambda:InvokeFunction', 'logs:CreateLogGroup'],
            'unused': ['iam:DeleteRole', 's3:DeleteObject'],
            'description': 'Aegis Test Role 3 - IAM and S3 unused permissions'
        }
    ]
    
    created_count = 0
    skipped_count = 0
    
    for role_config in test_roles:
        print(f"\n📋 Creating {role_config['name']}...")
        success = create_test_role(
            iam,
            role_config['name'],
            role_config['unused'],
            role_config['used'],
            role_config['description']
        )
        if success:
            created_count += 1
        else:
            skipped_count += 1
    
    print("\n" + "="*70)
    print("✅ TEST ROLES SETUP COMPLETE!")
    print("="*70)
    print(f"\n📊 Summary:")
    print(f"   ✅ Created: {created_count} new role(s)")
    print(f"   ⏭️  Skipped: {skipped_count} existing role(s)")
    print(f"   📋 Total test roles: {len(test_roles)}")
    
    print(f"\n📋 Test Roles Created:")
    for role_config in test_roles:
        print(f"   • {role_config['name']}")
        print(f"     - Used: {', '.join(role_config['used'][:3])}{'...' if len(role_config['used']) > 3 else ''}")
        print(f"     - Unused (will be removed): {', '.join(role_config['unused'])}")
    
    print(f"\n🎯 NEXT STEPS TO TEST REMEDIATION:")
    print(f"1. Run an audit in Aegis IAM (these roles will be detected)")
    print(f"2. The audit will find 'Unused Permissions' for these roles")
    print(f"3. Click 'Remediate All' or select specific findings")
    print(f"4. Watch the beautiful detailed remediation results display!")
    print(f"5. Verify in AWS Console that unused permissions were removed")
    
    print(f"\n🔍 VERIFICATION:")
    print(f"   After remediation, check each role in AWS Console:")
    for role_config in test_roles:
        print(f"   • https://console.aws.amazon.com/iam/home#/roles/{role_config['name']}")
        print(f"     Should NOT have: {', '.join(role_config['unused'])}")
        print(f"     Should still have: {', '.join(role_config['used'])}")
    
    print(f"\n⚠️  CLEANUP (when done testing):")
    print(f"   Run this script with --cleanup flag to delete all test roles")
    print(f"   OR manually delete each role:")
    for role_config in test_roles:
        print(f"   aws iam delete-role-policy --role-name {role_config['name']} --policy-name TestPolicy")
        print(f"   aws iam delete-role --role-name {role_config['name']}")

def cleanup_test_roles():
    """Delete all test roles"""
    iam = boto3.client('iam')
    
    test_role_names = ['AegisTestRole1', 'AegisTestRole2', 'AegisTestRole3']
    
    print("🧹 Cleaning up test roles...")
    print("="*70)
    
    for role_name in test_role_names:
        try:
            # Delete inline policy
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName='TestPolicy')
                print(f"   ✅ Deleted policy for {role_name}")
            except iam.exceptions.NoSuchEntityException:
                print(f"   ⏭️  No policy found for {role_name}")
            
            # Delete role
            try:
                iam.delete_role(RoleName=role_name)
                print(f"   ✅ Deleted role: {role_name}")
            except iam.exceptions.NoSuchEntityException:
                print(f"   ⏭️  Role {role_name} doesn't exist")
        except Exception as e:
            print(f"   ❌ Error deleting {role_name}: {e}")
    
    print("\n✅ Cleanup complete!")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == '--cleanup':
        cleanup_test_roles()
    else:
        create_all_test_roles()

