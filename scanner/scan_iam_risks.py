import boto3
import uuid
from datetime import datetime, timezone

def save_to_dynamodb(service, resource_id, issue_type, severity, details=""):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('CloudSecurityFindings')

    item = {
        'finding_id': str(uuid.uuid4()),
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'service': service,
        'resource_id': resource_id,
        'issue_type': issue_type,
        'severity': severity,
        'details': details
    }

    table.put_item(Item=item)
    print(f" Saved finding to DynamoDB: {resource_id} → {issue_type}")

def scan_iam_risks():
    iam = boto3.client('iam')

    print("\n Scanning IAM Users and their Inline/Attached Policies...")

    try:
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']

            # Attached managed policies
            attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            for policy in attached_policies:
                policy_name = policy['PolicyName']
                if "AdministratorAccess" in policy_name or "PowerUserAccess" in policy_name or "SecurityAudit" in policy_name:
                    print(f" Overly permissive managed policy on user '{username}': {policy_name}")
                    save_to_dynamodb(
                        service='IAM',
                        resource_id=username,
                        issue_type='Over-permissive IAM Policy',
                        severity='High',
                        details=policy_name
                    )

            # Inline policies
            inline_policies = iam.list_user_policies(UserName=username)['PolicyNames']
            for policy_name in inline_policies:
                print(f" Inline policy found on user '{username}': {policy_name}")
                save_to_dynamodb(
                    service='IAM',
                    resource_id=username,
                    issue_type='Inline IAM Policy',
                    severity='Medium',
                    details=policy_name
                )

    except Exception as e:
        print(f" Error scanning users: {e}")

    # Root account MFA check
    print("\n Checking root account MFA status...")
    try:
        summary = iam.get_account_summary()['SummaryMap']
        if summary.get('AccountMFAEnabled', 0) == 0:
            print(" MFA is NOT enabled for the root account! HIGH RISK")
            save_to_dynamodb(
                service='IAM',
                resource_id='root',
                issue_type='Root MFA Disabled',
                severity='High',
                details='Root user does not have MFA enabled'
            )
        else:
            print(" Root MFA is enabled.")
    except Exception as e:
        print(f" Error checking root MFA: {e}")

    # Unused roles
    print("\n Checking for unused IAM roles (no recent activity)...")
    try:
        roles = iam.list_roles()['Roles']
        cloudtrail = boto3.client('cloudtrail')

        now = datetime.now(timezone.utc)
        for role in roles:
            role_name = role['RoleName']
            arn = role['Arn']

            try:
                response = cloudtrail.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'ResourceName',
                            'AttributeValue': role_name
                        },
                    ],
                    MaxResults=1
                )
                if not response['Events']:
                    print(f" Role '{role_name}' has never been used.")
                    save_to_dynamodb(
                        service='IAM',
                        resource_id=role_name,
                        issue_type='Unused IAM Role',
                        severity='Low',
                        details='No CloudTrail activity found'
                    )
            except Exception as e:
                print(f" Error checking activity for role '{role_name}': {e}")

    except Exception as e:
        print(f" Error listing roles: {e}")

if __name__ == "__main__":
    scan_iam_risks()
