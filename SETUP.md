# 🛠️ Setup Guide

Complete step-by-step setup instructions for deploying the Honeypot Security System.

## Table of Contents
1. [AWS Prerequisites](#aws-prerequisites)
2. [Kubernetes Setup](#kubernetes-setup)
3. [Deploy Honeypots](#deploy-honeypots)
4. [Configure Lambda Functions](#configure-lambda-functions)
5. [Testing](#testing)
6. [Troubleshooting](#troubleshooting)

---

## AWS Prerequisites

### 1. Create IAM Roles

**Lambda S3 Role:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:CopyObject"
      ],
      "Resource": "arn:aws:s3:::cloud-project-ta2/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

**Lambda SES Role (additional permissions):**
```json
{
  "Effect": "Allow",
  "Action": [
    "ses:SendEmail",
    "ses:SendRawEmail"
  ],
  "Resource": "*"
}
```

**Lambda CloudWatch Role (additional permissions):**
```json
{
  "Effect": "Allow",
  "Action": [
    "logs:FilterLogEvents",
    "logs:DescribeLogStreams"
  ],
  "Resource": "arn:aws:logs:*:*:log-group:*"
}
```

### 2. Verify SES Email

```bash
aws ses verify-email-identity --email-address your-email@gmail.com --region ap-south-1

# Check verification status
aws ses get-identity-verification-attributes \
  --identities your-email@gmail.com \
  --region ap-south-1
```

Click the verification link in your email inbox.

### 3. Create S3 Bucket

```bash
# Create bucket
aws s3 mb s3://cloud-project-ta2 --region ap-south-1

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket cloud-project-ta2 \
  --versioning-configuration Status=Enabled \
  --region ap-south-1

# Create folder structure
aws s3api put-object --bucket cloud-project-ta2 --key uploads/
aws s3api put-object --bucket cloud-project-ta2 --key processed/
aws s3api put-object --bucket cloud-project-ta2 --key quarantine/
aws s3api put-object --bucket cloud-project-ta2 --key reports/

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket cloud-project-ta2 \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'
```

### 4. Create CloudWatch Log Groups

```bash
aws logs create-log-group --log-group-name cowrie-logs --region ap-south-1
aws logs create-log-group --log-group-name web-honeypot-logs --region ap-south-1

# Set retention
aws logs put-retention-policy \
  --log-group-name cowrie-logs \
  --retention-in-days 30

aws logs put-retention-policy \
  --log-group-name web-honeypot-logs \
  --retention-in-days 30
```

---

## Kubernetes Setup

### Option A: Using Minikube (Local Testing)

```bash
# Start minikube
minikube start --cpus=4 --memory=8192

# Enable addons
minikube addons enable ingress
minikube addons enable metrics-server
```

### Option B: Using EKS (Production)

```bash
# Install eksctl
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin

# Create cluster
eksctl create cluster \
  --name honeypot-cluster \
  --region ap-south-1 \
  --nodegroup-name standard-workers \
  --node-type t3.medium \
  --nodes 2 \
  --nodes-min 1 \
  --nodes-max 3 \
  --managed

# Configure kubectl
aws eks update-kubeconfig --name honeypot-cluster --region ap-south-1
```

---

## Deploy Honeypots

### 1. Build Web Honeypot Docker Image

```bash
cd web-honeypot

# Build image
docker build -t yourdockerhub/web-honeypot:latest .

# Test locally
docker run -p 5000:5000 \
  -e AWS_ACCESS_KEY_ID=your_key \
  -e AWS_SECRET_ACCESS_KEY=your_secret \
  yourdockerhub/web-honeypot:latest

# Push to Docker Hub
docker login
docker push yourdockerhub/web-honeypot:latest
```

### 2. Deploy Cowrie Honeypot

```bash
cd kubernetes/cowrie

# Update deployment.yaml with your Docker image if needed
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Verify deployment
kubectl get pods -l app=cowrie
kubectl get svc cowrie-service
```

### 3. Deploy Web Honeypot

```bash
cd kubernetes/web-honeypot

# Update image in deployment.yaml
# image: yourdockerhub/web-honeypot:latest

kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Verify
kubectl get pods -l app=web-honeypot
kubectl get svc web-honeypot-service
```

### 4. Get Access URLs

```bash
# For Minikube
minikube service web-honeypot-service --url
minikube service cowrie-service --url

# For EKS
kubectl get svc
# Use EXTERNAL-IP or configure LoadBalancer
```

---

## Configure Lambda Functions

### 1. Package File Scanner Lambda

```bash
cd lambda-functions/file-scanner

# Create deployment package
zip lambda_function.zip lambda_function.py

# Create Lambda function
aws lambda create-function \
  --function-name HoneypotFileScanner \
  --runtime python3.10 \
  --role arn:aws:iam::YOUR_ACCOUNT_ID:role/LambdaS3Role \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://lambda_function.zip \
  --timeout 60 \
  --memory-size 256 \
  --region ap-south-1
```

### 2. Package Alert Lambda

```bash
cd lambda-functions/alert-system

# Update email addresses in lambda_function.py
# SENDER = "your_verified_email@gmail.com"
# RECIPIENTS = ["email1@gmail.com", "email2@gmail.com"]

# Create deployment package
zip lambda_function.zip lambda_function.py

# Create Lambda function
aws lambda create-function \
  --function-name HoneypotAlertSystem \
  --runtime python3.10 \
  --role arn:aws:iam::YOUR_ACCOUNT_ID:role/LambdaSESRole \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://lambda_function.zip \
  --timeout 300 \
  --memory-size 512 \
  --region ap-south-1
```

### 3. Configure S3 Event Triggers

**For File Scanner (uploads/ folder):**

```bash
# Create notification configuration file
cat > s3-notification-scanner.json <<EOF
{
  "LambdaFunctionConfigurations": [
    {
      "Id": "FileUploadTrigger",
      "LambdaFunctionArn": "arn:aws:lambda:ap-south-1:YOUR_ACCOUNT_ID:function:HoneypotFileScanner",
      "Events": ["s3:ObjectCreated:*"],
      "Filter": {
        "Key": {
          "FilterRules": [
            {
              "Name": "prefix",
              "Value": "uploads/"
            }
          ]
        }
      }
    }
  ]
}
EOF

# Apply notification
aws s3api put-bucket-notification-configuration \
  --bucket cloud-project-ta2 \
  --notification-configuration file://s3-notification-scanner.json
```

**For Alert System (reports/ folder):**

```bash
cat > s3-notification-alert.json <<EOF
{
  "LambdaFunctionConfigurations": [
    {
      "Id": "ReportGeneratedTrigger",
      "LambdaFunctionArn": "arn:aws:lambda:ap-south-1:YOUR_ACCOUNT_ID:function:HoneypotAlertSystem",
      "Events": ["s3:ObjectCreated:*"],
      "Filter": {
        "Key": {
          "FilterRules": [
            {
              "Name": "prefix",
              "Value": "reports/"
            }
          ]
        }
      }
    }
  ]
}
EOF

aws s3api put-bucket-notification-configuration \
  --bucket cloud-project-ta2 \
  --notification-configuration file://s3-notification-alert.json
```

### 4. Grant S3 Permission to Invoke Lambda

```bash
# For Scanner
aws lambda add-permission \
  --function-name HoneypotFileScanner \
  --statement-id s3-trigger \
  --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn arn:aws:s3:::cloud-project-ta2 \
  --region ap-south-1

# For Alert
aws lambda add-permission \
  --function-name HoneypotAlertSystem \
  --statement-id s3-trigger \
  --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn arn:aws:s3:::cloud-project-ta2 \
  --region ap-south-1
```

---

## Testing

### 1. Test Web Honeypot

```bash
# Get URL
WEB_URL=$(kubectl get svc web-honeypot-service -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

# Test login
curl -X POST http://$WEB_URL:30007/ \
  -d "username=TA2&password=cloudproject" \
  -c cookies.txt

# Test file upload
echo "test content" > test.txt
curl -X POST http://$WEB_URL:30007/upload \
  -F "file=@test.txt" \
  -b cookies.txt
```

### 2. Test Cowrie Honeypot

```bash
# Attempt SSH connection
ssh root@$COWRIE_IP -p $COWRIE_PORT

# Try common credentials
# root/password
# admin/admin
```

### 3. Test Lambda File Scanner

```bash
# Upload suspicious file
aws s3 cp malware.exe s3://cloud-project-ta2/uploads/

# Check Lambda logs
aws logs tail /aws/lambda/HoneypotFileScanner --follow

# Verify file moved to quarantine
aws s3 ls s3://cloud-project-ta2/quarantine/
```

### 4. Test Alert System

```bash
# Upload report to trigger alert
echo "Test Report" > report.txt
aws s3 cp report.txt s3://cloud-project-ta2/reports/

# Check email inbox for alert
# Check Lambda logs
aws logs tail /aws/lambda/HoneypotAlertSystem --follow
```

---

## Troubleshooting

### Lambda Function Not Triggering

**Check S3 event configuration:**
```bash
aws s3api get-bucket-notification-configuration --bucket cloud-project-ta2
```

**Check Lambda permissions:**
```bash
aws lambda get-policy --function-name HoneypotFileScanner
```

### Email Not Sending

**Verify SES status:**
```bash
aws ses get-identity-verification-attributes \
  --identities your-email@gmail.com \
  --region ap-south-1
```

**Check SES sandbox status:**
If in sandbox, you can only send to verified addresses. Request production access.

### Kubernetes Pods Not Starting

```bash
# Check pod status
kubectl get pods
kubectl describe pod <pod-name>

# Check logs
kubectl logs <pod-name>

# Check events
kubectl get events --sort-by='.lastTimestamp'
```

### CloudWatch Logs Not Appearing

**Install CloudWatch agent on nodes:**
```bash
kubectl apply -f cloudwatch/logs-config.json
```

---

## Security Hardening

### 1. Network Isolation

```bash
# Create network policy
cat > network-policy.yaml <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: honeypot-isolation
spec:
  podSelector:
    matchLabels:
      app: web-honeypot
  policyTypes:
  - Ingress
  - Egress
  egress:
  - to:
    - podSelector: {}
    ports:
    - protocol: TCP
      port: 443
EOF

kubectl apply -f network-policy.yaml
```

### 2. Enable S3 Bucket Logging

```bash
aws s3api put-bucket-logging \
  --bucket cloud-project-ta2 \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "your-logging-bucket",
      "TargetPrefix": "honeypot-logs/"
    }
  }'
```

### 3. Set Up CloudWatch Alarms

```bash
# High file upload rate alarm
aws cloudwatch put-metric-alarm \
  --alarm-name HighUploadRate \
  --alarm-description "Alert on high file upload rate" \
  --metric-name NumberOfObjects \
  --namespace AWS/S3 \
  --statistic Average \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 100 \
  --comparison-operator GreaterThanThreshold
```

---

## Next Steps

✅ Review [ARCHITECTURE.md](ARCHITECTURE.md) for system design details  
✅ Set up monitoring dashboards  
✅ Configure automated backups  
✅ Implement log rotation  
✅ Schedule regular security audits  

---

**Need Help?** Open an issue on GitHub or contact the maintainers.
