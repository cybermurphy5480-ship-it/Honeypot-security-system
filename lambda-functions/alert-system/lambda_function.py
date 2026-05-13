import boto3
from datetime import datetime, timedelta
import re

# -------- AWS Clients --------
s3 = boto3.client('s3')
logs_client = boto3.client('logs')
ses = boto3.client('ses')

# -------- EMAIL CONFIG --------
SENDER = "your_verified_email@gmail.com"

RECIPIENTS = [
    "email1@gmail.com",
    "email2@gmail.com",
    "email3@gmail.com"
]

# -------- GET LOGS --------
def get_logs(log_group):

    end_time = int(datetime.utcnow().timestamp() * 1000)
    start_time = int((datetime.utcnow() - timedelta(minutes=10)).timestamp() * 1000)

    response = logs_client.filter_log_events(
        logGroupName=log_group,
        startTime=start_time,
        endTime=end_time,
        limit=100
    )

    events = response.get('events', [])

    # Sort latest first
    events.sort(key=lambda x: x['timestamp'], reverse=True)

    latest_events = events[:10]

    return [e['message'] for e in latest_events]


# -------- EXTRACT COWRIE IP --------
def extract_ip_cowrie(log):
    match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log)
    return match.group(1) if match else None


# -------- EXTRACT WEB IP --------
def extract_ip_web(log):

    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log)

    ip = match.group(1) if match else None

    if ip in ["127.0.0.1", "0.0.0.0"]:
        return None

    return ip


# -------- SEND EMAIL --------
def send_email(body, attachment, filename):

    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.application import MIMEApplication

    msg = MIMEMultipart()

    msg['Subject'] = "🚨 Honeypot Alert"
    msg['From'] = SENDER
    msg['To'] = ", ".join(RECIPIENTS)

    msg.attach(MIMEText(body, 'plain'))

    part = MIMEApplication(attachment)
    part.add_header(
        'Content-Disposition',
        'attachment',
        filename=filename
    )

    msg.attach(part)

    response = ses.send_raw_email(
        Source=SENDER,
        Destinations=RECIPIENTS,
        RawMessage={'Data': msg.as_string()}
    )

    print("SES Response:", response)


# -------- MAIN --------
def lambda_handler(event, context):

    print("EVENT:", event)

    try:
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = event['Records'][0]['s3']['object']['key']

    except Exception as e:
        print("Error reading event:", str(e))
        return

    print("File:", key)

    # -------- ONLY REPORTS FOLDER --------
    if not key.startswith("reports/"):
        print("Not a report file")
        return

    # -------- DOWNLOAD FILE --------
    print("Downloading file...")

    file_obj = s3.get_object(Bucket=bucket, Key=key)
    file_data = file_obj['Body'].read()

    # -------- FETCH LOGS --------
    print("Fetching logs...")

    cowrie_logs = get_logs("cowrie-logs")
    web_logs = get_logs("web-honeypot-logs")

    # -------- EXTRACT ATTACKER IPS --------
    attacker_ips = set()

    for log in cowrie_logs:
        ip = extract_ip_cowrie(log)

        if ip:
            attacker_ips.add(ip)

    for log in web_logs:
        ip = extract_ip_web(log)

        if ip:
            attacker_ips.add(ip)

    # -------- BUILD REPORT --------
    report = f"""
🚨 Honeypot Correlation Alert

Uploaded File:
{key}

Attacker IPs:
{chr(10).join(attacker_ips) if attacker_ips else "No IP Found"}

========================
Cowrie Logs
========================

{chr(10).join(cowrie_logs)}

========================
Web Honeypot Logs
========================

{chr(10).join(web_logs)}
"""

    # -------- SEND EMAIL --------
    print("Sending email...")

    send_email(report, file_data, key)

    print("Done")