import argparse
import boto3
from botocore.exceptions import NoCredentialsError
import re

def parse_log(log_entry):
    pattern = re.compile(r'(\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (\S+)$')

    match = pattern.match(log_entry.decode('utf-8'))

    if match:
        timestamp, client_ip, user_arn, request_id, event_type, bucket_name, \
        key, request_uri, http_status, error_code, bytes_sent, object_size, \
        total_time, turn_around_time, referrer, user_agent = match.groups()

        return {
            "Timestamp": timestamp,
            "Client IP": client_ip,
            "User ARN": user_arn,
            "Request ID": request_id,
            "Event Type": event_type,
            "Bucket Name": bucket_name,
            "Key": key,
            "Request URI": request_uri,
            "HTTP Status": http_status,
            "Error Code": error_code,
            "Bytes Sent": bytes_sent,
            "Object Size": object_size,
            "Total Time": total_time,
            "Turnaround Time": turn_around_time,
            "Referrer": referrer,
            "User Agent": user_agent,
        }
    else:
        print(f"Log Entry:\n{log_entry.decode('utf-8')}")
        return None

def format_log(parsed_log):
    if parsed_log:
        formatted_log = (
            f"Timestamp: {parsed_log.get('Timestamp', 'N/A')}\n"
            f"Client IP: {parsed_log.get('Client IP', 'N/A')}\n"
            f"User ARN: {parsed_log.get('User ARN', 'N/A')}\n"
            f"Request Method: {parsed_log.get('Request Method', 'N/A')}\n"
            f"Requested Resource: {parsed_log.get('Requested Resource', 'N/A')}\n"
            f"Status Code: {parsed_log.get('Status Code', 'N/A')}\n"
            f"Referrer: {parsed_log.get('Referrer', 'N/A')}\n"
            f"User Agent: {parsed_log.get('User Agent', 'N/A')}\n"
            f"Version ID: {parsed_log.get('Version ID', 'N/A')}\n"
            f"Host ID: {parsed_log.get('Host ID', 'N/A')}"
        )
        return formatted_log
    else:
        return "Invalid log entry"

def get_s3_logs(bucket_name, access_key, secret_key):
    logs = []
    s3 = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key)

    try:
        response = s3.list_objects(Bucket=bucket_name)
        for obj in response.get('Contents', []):
            log = s3.get_object(Bucket=bucket_name, Key=obj['Key'])
            parsed_log = parse_log(log['Body'].read())
            formatted_log = format_log(parsed_log)
            logs.append(formatted_log)
    except NoCredentialsError:
        print("Credentials not available. Make sure you have entered valid AWS access key and secret key.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return logs

def main(args):
    logs = get_s3_logs(args.bucket_name, args.access_key, args.secret_key)
    for log in logs:
        print(log)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S3 Log Viewer")
    parser.add_argument("access_key", help="AWS Access Key")
    parser.add_argument("secret_key", help="AWS Secret Key")
    parser.add_argument("bucket_name", help="S3 Bucket Name")
    args = parser.parse_args()
    main(args)
