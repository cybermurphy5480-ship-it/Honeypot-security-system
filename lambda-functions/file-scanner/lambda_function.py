import boto3
import urllib.parse
import os
import json

s3 = boto3.client('s3')

def lambda_handler(event, context):
    print("🔥 EVENT RECEIVED:")
    print(json.dumps(event, indent=2))

    if 'Records' not in event:
        print("❌ No Records found in event")
        return

    for record in event['Records']:
        try:
            bucket = record['s3']['bucket']['name']
            key = urllib.parse.unquote_plus(record['s3']['object']['key'])

            print(f"📂 Processing file: {key}")

            if not key.startswith("uploads/"):
                print("⚠️ Not in uploads/, skipping")
                continue

            _, ext = os.path.splitext(key)
            ext = ext.lower()

            suspicious_ext = [".exe", ".bat", ".sh", ".js", ".dll"]

            if ext in suspicious_ext:
                destination = "quarantine/"
                print(f"🚨 Suspicious: {ext}")
            else:
                destination = "processed/"
                print(f"✅ Safe: {ext}")

            new_key = key.replace("uploads/", destination, 1)

            s3.copy_object(
                Bucket=bucket,
                CopySource={'Bucket': bucket, 'Key': key},
                Key=new_key
            )

            s3.delete_object(Bucket=bucket, Key=key)

            print(f"✅ Moved {key} → {new_key}")

        except Exception as e:
            print(f"❌ Error: {str(e)}")