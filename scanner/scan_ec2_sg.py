import boto3
import uuid
from datetime import datetime, timezone

# Save finding to DynamoDB
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
    print(f"  Saved finding to DynamoDB: {resource_id} → {issue_type}")

# Scan EC2 Security Groups
def scan_ec2_security_groups():
    ec2 = boto3.client('ec2')
    response = ec2.describe_security_groups()

    risky_ports = [22, 3389, 80, 443]

    for sg in response['SecurityGroups']:
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', 'Unnamed')
        print(f"\n Scanning Security Group: {sg_id} ({sg_name})")

        for rule in sg['IpPermissions']:
            ip_ranges = rule.get('IpRanges', [])
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            protocol = rule.get('IpProtocol')

            for ip_range in ip_ranges:
                cidr = ip_range.get('CidrIp')
                if cidr == '0.0.0.0/0':
                    if from_port in risky_ports:
                        print(f"  Open port {from_port} to the world!")
                        save_to_dynamodb(
                            service='EC2',
                            resource_id=sg_id,
                            issue_type=f'Public access to port {from_port}',
                            severity='High',
                            details=f'CIDR: {cidr}, Protocol: {protocol}'
                        )

if __name__ == "__main__":
    scan_ec2_security_groups()
