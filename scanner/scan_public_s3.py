import boto3
import uuid
from datetime import datetime

def save_to_dynamodb(service, resource_id, issue_type, severity, details=""):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('CloudSecurityFindings')

    item = {
        'finding_id': str(uuid.uuid4()),
        'timestamp': datetime.utcnow().isoformat(),
        'service': service,
        'resource_id': resource_id,
        'issue_type': issue_type,
        'severity': severity,
        'details': details
    }

    table.put_item(Item=item)
    print(f" Saved finding to DynamoDB: {resource_id} → {issue_type}")

def check_bucket_encryption(s3, bucket_name):
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc['ServerSideEncryptionConfiguration']['Rules']
        print(f"    Encryption: Enabled ({rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']})")
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            print("    Encryption: Not enabled")
            save_to_dynamodb(
                service='S3',
                resource_id=bucket_name,
                issue_type='Missing Encryption',
                severity='Medium',
                details='No SSE configured'
            )
        else:
            print(f"    Error checking encryption: {e}")

def check_bucket_logging(s3, bucket_name):
    try:
        logging = s3.get_bucket_logging(Bucket=bucket_name)
        if 'LoggingEnabled' in logging:
            target_bucket = logging['LoggingEnabled']['TargetBucket']
            print(f"    Logging: Enabled (logs to {target_bucket})")
        else:
            print("    Logging: Not enabled")
            save_to_dynamodb(
                service='S3',
                resource_id=bucket_name,
                issue_type='Logging Disabled',
                severity='Low',
                details='No logging target configured'
            )
    except Exception as e:
        print(f"    Error checking logging: {e}")

def check_s3_public_buckets():
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    public_buckets = []

    for bucket in response['Buckets']:
        bucket_name = bucket['Name']
        print(f"\n Checking bucket: {bucket_name}")

        # Check for encryption and logging
        check_bucket_encryption(s3, bucket_name)
        check_bucket_logging(s3, bucket_name)

        # Check ACL
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission')
                if grantee.get('URI') == "http://acs.amazonaws.com/groups/global/AllUsers":
                    public_buckets.append({
                        'bucket': bucket_name,
                        'access': f'ACL - {permission}'
                    })
                    save_to_dynamodb(
                        service='S3',
                        resource_id=bucket_name,
                        issue_type='Public Access - ACL',
                        severity='High',
                        details=permission
                    )
        except Exception as e:
            print(f"    Error checking ACL: {e}")

        # Check Bucket Policy
        try:
            policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
            if policy_status['PolicyStatus']['IsPublic']:
                public_buckets.append({
                    'bucket': bucket_name,
                    'access': 'Bucket Policy - Public'
                })
                save_to_dynamodb(
                    service='S3',
                    resource_id=bucket_name,
                    issue_type='Public Access - Bucket Policy',
                    severity='High',
                    details='Bucket policy allows public access'
                )
        except s3.exceptions.from_code('NoSuchBucketPolicy'):
            continue
        except Exception as e:
            print(f"    Error checking policy: {e}")

    return public_buckets

if __name__ == "__main__":
    findings = check_s3_public_buckets()
    if findings:
        print("\n Public Buckets Found:")
        for bucket in findings:
            print(f"- {bucket['bucket']} → {bucket['access']}")
    else:
        print("\n No public buckets detected.")
