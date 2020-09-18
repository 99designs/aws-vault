#!/bin/sh
# Adds a Yubikey TOTP device to IAM

set -eu

if [ -n "${AWS_SESSION_TOKEN:-}" ]; then
  echo "aws-vault must be run without a STS session, please run it with the --no-session flag" >&2
  exit 1
fi

cleanup()
{
  if [ -z "$OUTFILE" ]; then
    rm "$OUTFILE"
  fi
}
trap cleanup EXIT

ACCOUNT_ARN=$(aws sts get-caller-identity --query Arn --output text)
# Assume that the final portion of the ARN is the username
# Works for ARNs like `users/<user>` and `users/engineers/<user>`
USERNAME=$(echo "$ACCOUNT_ARN" | rev | cut -d/ -f1 | rev)

OUTFILE=$(mktemp)
SERIAL_NUMBER=$(aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name "$USERNAME" \
  --bootstrap-method Base32StringSeed \
  --outfile "$OUTFILE" \
  --query VirtualMFADevice.SerialNumber \
  --output text)

ykman oath add -t "$SERIAL_NUMBER" < "$OUTFILE" 2> /dev/null
rm "$OUTFILE"

CODE1=$(ykman oath code -s "$SERIAL_NUMBER")

echo "Waiting 30s before generating a second code" >&2
sleep 30

CODE2=$(ykman oath code -s "$SERIAL_NUMBER")

aws iam enable-mfa-device \
  --user-name "$USERNAME" \
  --serial-number "$SERIAL_NUMBER" \
  --authentication-code1 "$CODE1" \
  --authentication-code2 "$CODE2"
