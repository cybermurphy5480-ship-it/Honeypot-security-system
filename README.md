# 🍯 Cloud-Based Honeypot Security System

A comprehensive multi-layer honeypot deployment system on AWS and Kubernetes that detects, analyzes, and reports malicious activities in real-time.

![Architecture](https://img.shields.io/badge/Cloud-AWS-orange) ![Kubernetes](https://img.shields.io/badge/Platform-Kubernetes-blue) ![Python](https://img.shields.io/badge/Python-3.10-green)

## 📋 Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Components](#components)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

This project implements a sophisticated honeypot system that combines:
- **SSH/Telnet Honeypot** (Cowrie) - Captures credential theft attempts
- **Web Application Honeypot** - Monitors malicious file uploads
- **Automated Malware Analysis** - Static and dynamic file inspection
- **Real-time Threat Intelligence** - Correlates attacks and sends alerts

### Use Cases
✅ Threat intelligence gathering  
✅ Attacker behavior analysis  
✅ Malware sample collection  
✅ Security research and education  

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    KUBERNETES CLUSTER                        │
│  ┌──────────────────┐        ┌──────────────────┐          │
│  │  Cowrie Honeypot │        │  Web Honeypot    │          │
│  │  (SSH/Telnet)    │        │  (Flask App)     │          │
│  └────────┬─────────┘        └────────┬─────────┘          │
│           │                            │                     │
│           └──────────┬─────────────────┘                     │
└───────────────────────┼───────────────────────────────────────┘
                        │
                        ▼
              ┌─────────────────┐
              │  CloudWatch     │
              │  Logs           │
              └────────┬────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ S3 Bucket    │  │ Lambda #1    │  │ Lambda #2    │
│ (Storage)    │  │ (File Scan)  │  │ (Alerting)   │
└──────────────┘  └──────────────┘  └──────┬───────┘
                                            │
                                            ▼
                                    ┌──────────────┐
                                    │  AWS SES     │
                                    │  (Email)     │
                                    └──────────────┘
```

---

## ✨ Features

### 🎣 Multi-Protocol Honeypots
- **Cowrie**: Emulates SSH/Telnet servers to capture credential attacks
- **Web Portal**: Fake file upload interface with authentication

### 🔍 Automated Threat Detection
- Real-time file extension analysis
- Automatic quarantine of suspicious files (.exe, .bat, .sh, .js, .dll)
- Static and dynamic malware analysis

### 📊 Intelligence & Reporting
- Centralized logging via CloudWatch
- IP address extraction and correlation
- Automated email alerts with attack summaries
- Activity timeline reconstruction

### ☁️ Cloud-Native Design
- Kubernetes orchestration for scalability
- AWS Lambda serverless processing
- S3 for secure storage
- Infrastructure as Code (IaC) ready

---

## 📦 Components

### 1. Honeypots
| Component | Technology | Port | Purpose |
|-----------|-----------|------|---------|
| Cowrie | Python | 22, 23 | SSH/Telnet simulation |
| Web Honeypot | Flask | 80 | Malicious upload trap |

### 2. Processing Pipeline
| Component | Trigger | Function |
|-----------|---------|----------|
| Lambda Scanner | S3 upload | File type validation & quarantine |
| Lambda Alerter | Report generation | Log correlation & email alerts |
| Worker (Analysis) | Manual/Scheduled | Static/Dynamic malware analysis |

### 3. Storage & Logging
- **S3 Bucket**: `cloud-project-ta2`
  - `uploads/` - Initial file landing zone
  - `processed/` - Safe files
  - `quarantine/` - Suspicious files
  - `reports/` - Analysis outputs
- **CloudWatch**: Log aggregation from both honeypots

---

## 🔧 Prerequisites

### Required Services
- AWS Account with:
  - S3 bucket access
  - Lambda execution role
  - SES verified sender email
  - CloudWatch Logs permissions
- Kubernetes cluster (EKS, minikube, or self-hosted)
- Docker installed locally
- `kubectl` configured

### Software Requirements
```bash
Python 3.10+
Docker 20.10+
kubectl 1.24+
AWS CLI 2.x
```

---

## 🚀 Installation

### Step 1: Clone Repository
```bash
git clone https://github.com/yourusername/honeypot-security-system.git
cd honeypot-security-system
```

### Step 2: Configure AWS Credentials
```bash
aws configure
# Enter your AWS Access Key ID
# Enter your AWS Secret Access Key
# Region: ap-south-1
```

### Step 3: Create S3 Bucket
```bash
aws s3 mb s3://cloud-project-ta2 --region ap-south-1
aws s3api put-bucket-versioning \
  --bucket cloud-project-ta2 \
  --versioning-configuration Status=Enabled
```

### Step 4: Deploy Kubernetes Resources
```bash
# Deploy Cowrie Honeypot
kubectl apply -f kubernetes/cowrie/

# Deploy Web Honeypot
kubectl apply -f kubernetes/web-honeypot/
```

### Step 5: Build and Push Docker Image
```bash
cd web-honeypot
docker build -t yourdockerhub/web-honeypot:latest .
docker push yourdockerhub/web-honeypot:latest
```

### Step 6: Deploy Lambda Functions
```bash
## You can do this by GUI as well , paste the code into lamda_fucntion ##
cd lambda-functions

# Package Scanner Lambda
zip -r file-scanner.zip 1st_lambda_function.py
aws lambda create-function \
  --function-name HoneypotFileScanner \
  --runtime python3.10 \
  --role arn:aws:iam::YOUR_ACCOUNT:role/LambdaS3Role \
  --handler 1st_lambda_function.lambda_handler \
  --zip-file fileb://file-scanner.zip

# Package Alert Lambda
zip -r alert-system.zip lambda_function.py
aws lambda create-function \
  --function-name HoneypotAlertSystem \
  --runtime python3.10 \
  --role arn:aws:iam::YOUR_ACCOUNT:role/LambdaSESRole \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://alert-system.zip
```

### Step 7: Configure S3 Event Triggers
```bash
# Add trigger for uploads/ folder → Scanner Lambda
# Add trigger for reports/ folder → Alert Lambda
# (Use AWS Console or CloudFormation)
```

---

## ⚙️ Configuration

### Web Honeypot Credentials
Edit `web-honeypot/app.py`:
```python
APP_USERNAME = "your_username"
APP_PASSWORD = "your_secure_password"
S3_BUCKET = "your-bucket-name"
```

### Email Notifications
Edit `lambda-functions/lambda_function.py`:
```python
SENDER = "your_verified_email@gmail.com"
RECIPIENTS = [
    "recipient1@example.com",
    "recipient2@example.com"
]
```

### CloudWatch Logs
Update `cloudwatch/logs-config.json` with your instance IDs.

---

## 📖 Usage

### Access the Honeypots

**Web Honeypot:**
```bash
# Get the external IP
kubectl get svc web-honeypot-service

# Access at: http://<NODE_IP>:30007
```

**Cowrie SSH Honeypot:**
```bash
# Get the NodePort
kubectl get svc cowrie-service

# Test with: ssh root@<NODE_IP> -p <NodePort>
```

### Monitor Activity

**View Logs:**
```bash
# Cowrie logs
kubectl logs -f deployment/cowrie

# Web honeypot logs
kubectl logs -f deployment/web-honeypot
```

**Check CloudWatch:**
```bash
aws logs tail cowrie-logs --follow
aws logs tail web-honeypot-logs --follow
```

**Review S3 Files:**
```bash
aws s3 ls s3://cloud-project-ta2/quarantine/
aws s3 ls s3://cloud-project-ta2/processed/
```

### Run Malware Analysis
```bash
python analysis/worker.py --file <quarantined-file>
```

---

## 🔒 Security Considerations

### ⚠️ Important Warnings

1. **Isolation**: Deploy honeypots in isolated networks/VPCs
2. **No Real Data**: Never use actual credentials or sensitive data
3. **Monitor Resources**: Set billing alerts to prevent abuse
4. **Legal Compliance**: Ensure compliance with local laws regarding honeypots
5. **Access Control**: Restrict S3 bucket and Lambda access via IAM policies

### Recommended Security Measures
```yaml
✓ Enable S3 bucket encryption
✓ Use VPC endpoints for Lambda
✓ Implement CloudWatch alarms for unusual activity
✓ Regular security group audits
✓ Enable AWS CloudTrail for audit logging
✓ Use separate AWS account for honeypot infrastructure
```

---

## 📊 Project Structure

```
honeypot-security-system/
├── README.md
├── LICENSE
├── .gitignore
├── architecture.png
│
├── kubernetes/
│   ├── cowrie/
│   │   ├── deployment.yaml
│   │   └── service.yaml
│   └── web-honeypot/
│       ├── deployment.yaml
│       └── service.yaml
│
├── web-honeypot/
│   ├── app.py
│   ├── Dockerfile
│   └── requirements.txt
│
├── lambda-functions/
│   ├── file-scanner/
│   │   └── 1st_lambda_function.py
│   └── alert-system/
│       └── lambda_function.py
│
├── analysis/
│   └── worker.py
│
├── cloudwatch/
│   └── logs-config.json
│
├── docs/
│   ├── SETUP.md
│   ├── ARCHITECTURE.md
│   └── TROUBLESHOOTING.md
│
└── scripts/
    ├── deploy.sh
    └── cleanup.sh
```

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Cowrie Honeypot](https://github.com/cowrie/cowrie) - SSH/Telnet honeypot framework
- AWS Documentation
- Kubernetes Community

---

## 📧 Contact

**Project Maintainer**: Murphy
**Email**: cybermurphy5480@gmail.com
**Project Link**: https://github.com/cybermurphy5480-ship-it/Honeypot-security-system

---

**⚠️ Disclaimer**: This system is for educational and research purposes. Ensure you have proper authorization before deploying honeypots in any network.
