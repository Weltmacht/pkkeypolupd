#!/bin/bash

if [ $# -lt 1 ]
  then
    echo "Provide alias in format alias/<aliasname>.  No action taken."
    exit 1
fi

KEYID_EBS=$(aws kms describe-key --key-id $1 --query 'KeyMetadata.KeyId' --output text)
aws kms get-key-policy --key-id $KEYID_EBS --policy-name default --output text --query Policy |
python3 -c "
import json
import sys

statement_exists = False

new_statement = {
    \"Sid\": \"Allow use of the KMS key for central backup cross-account copy, in organization\",
    \"Effect\": \"Allow\",
    \"Principal\": {
        \"AWS\": \"arn:aws:iam::160382898764:root\"
    },
    \"Action\": [
        \"kms:ReEncrypt*\",
        \"kms:GenerateDataKey*\",
        \"kms:Encrypt\",
        \"kms:DescribeKey\",
        \"kms:Decrypt\",
        \"kms:CreateGrant\"
    ],
    \"Resource\": \"*\"
}

current_policy = json.load(sys.stdin)

for statement in current_policy['Statement']:
    if statement.get('Sid') == new_statement['Sid']:
        statement_exists = True
        break

if not statement_exists:
    current_policy['Statement'].append(new_statement)
    print(json.dumps(current_policy))
else:
    sys.exit(1)
" > updated_policy.json
aws kms put-key-policy --key-id $KEYID_EBS --policy-name default --policy file://updated_policy.json
