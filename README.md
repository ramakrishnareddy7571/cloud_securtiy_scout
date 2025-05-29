Cloud Security Scout

A lightweight Python-based AWS misconfiguration scanner that detects insecure S3 buckets, risky IAM policies, and exposed EC2 security groups. Findings are saved to DynamoDB for centralized tracking.

Folder Structure

cloud-security-scout/ scanner/ ── scan_public_s3.py # Scans for public S3 buckets, encryption, logging ── scan_iam_risks.py # Checks IAM users, inline policies, root MFA, unused roles ── scan_ec2_sg.py # Detects overly permissive EC2 Security Group rules

── lambda_packages/ ── s3_lambda_package.zip # Deployable Lambda for scan_public_s3 ── iam_lambda_package.zip # Deployable Lambda for scan_iam_risks ── ec2_lambda_package.zip # Deployable Lambda for scan_ec2_sg

── requirements.txt ── README.md

Features

Detects public S3 buckets and misconfigured ACLs
Flags overly permissive IAM policies and missing root MFA
Finds open EC2 ports (SSH/RDP) accessible to the public
Stores all findings in a DynamoDB table (CloudSecurityFindings)
Ready to deploy as AWS Lambda functions
Requirements Install required dependencies: pip install -r requirements.txt

Deployment Each script can be zipped and deployed as a standalone AWS Lambda. Ensure: The Lambda IAM role has: AmazonDynamoDBFullAccess AmazonS3ReadOnlyAccess IAMReadOnlyAccess

DynamoDB table CloudSecurityFindings is created in your target AWS region

Author Rama Krishna Reddy Madireddy Cybersecurity Graduate Student | UNC Charlotte LinkedIn: https://www.linkedin.com/in/mramakrishnar/ Email: ramakrishnareddymadireddy34@gmail.com
