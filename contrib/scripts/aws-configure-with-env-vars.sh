#!/bin/sh
# Configure aws-cli using the AWS env vars created with aws-vault
#
# Usage: aws-vault exec <SOURCE_PROFILE> -- aws-configure-with-env-vars.sh [TARGET_PROFILE]
#

set -eu

aws configure --profile "${1:-$AWS_VAULT}" set region "$AWS_REGION"
aws configure --profile "${1:-$AWS_VAULT}" set aws_access_key_id "$AWS_ACCESS_KEY_ID"
aws configure --profile "${1:-$AWS_VAULT}" set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY"
aws configure --profile "${1:-$AWS_VAULT}" set aws_session_token "${AWS_SESSION_TOKEN:-}"
