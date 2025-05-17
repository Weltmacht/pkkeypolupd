#!/usr/bin/env python3

import json
import sys
import boto3
import argparse
import tempfile
import os
from botocore.exceptions import ClientError

def parse_args():
    parser = argparse.ArgumentParser(description="Update AWS KMS key policy with a predefined cross-account statement.")
    parser.add_argument("alias", help="KMS key alias in the form alias/<alias-name>")
    parser.add_argument("--profile", help="AWS CLI profile to use", default=None)
    return parser.parse_args()

def get_kms_client(profile=None):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client('kms')

def main():
    args = parse_args()
    kms = get_kms_client(args.profile)

    try:
        key_metadata = kms.describe_key(KeyId=args.alias)
        key_id = key_metadata['KeyMetadata']['KeyId']
    except ClientError as e:
        print(f"Error retrieving key ID: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        policy_str = kms.get_key_policy(KeyId=key_id, PolicyName='default')['Policy']
        policy = json.loads(policy_str)
    except ClientError as e:
        print(f"Error retrieving current key policy: {e}", file=sys.stderr)
        sys.exit(1)

    new_statement = {
        "Sid": "Allow use of the KMS key for central backup cross-account copy, in organization",
        "Effect": "Allow",
        "Principal": {
            "AWS": "arn:aws:iam::160382898764:root"
        },
        "Action": [
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:Encrypt",
            "kms:DescribeKey",
            "kms:Decrypt",
            "kms:CreateGrant"
        ],
        "Resource": "*"
    }

    if any(stmt.get("Sid") == new_statement["Sid"] for stmt in policy.get("Statement", [])):
        print("Policy already contains the required statement. No changes made.")
        sys.exit(0)

    policy['Statement'].append(new_statement)

    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
        json.dump(policy, f)
        f.flush()
        fpath = f.name

    try:
        with open(fpath, 'r') as policy_file:
            policy_json = policy_file.read()
        kms.put_key_policy(KeyId=key_id, PolicyName='default', Policy=policy_json)
        print("Policy successfully updated.")
    except ClientError as e:
        print(f"Failed to update key policy: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        os.remove(fpath)

if __name__ == "__main__":
    main()
