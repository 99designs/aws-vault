#!/bin/sh

set -eu

ACCOUNT_ARN=$(aws sts get-caller-identity --query Arn --output text)
# Assume that the final portion of the ARN is the username
# Works for ARNs like `users/<user>` and `users/engineers/<user>`
USERNAME=$(echo "$ACCOUNT_ARN" | rev | cut -d/ -f1 | rev)
ACCOUNT_ID=$(echo "$ACCOUNT_ARN" | cut -d: -f5)
SERIAL_NUMBER="arn:aws:iam::${ACCOUNT_ID}:mfa/${USERNAME}"

CODE1=$(ykman oath code -s "$SERIAL_NUMBER")

# wait until next code can be generated
# if SECONDS are :00 or :30, generate right away
SECONDS=$(date +%S)
if (( ${SECONDS#0} >= 1 && ${SECONDS#0} <= 29 )); then
    WAIT_SECONDS=$(( 30 - ${SECONDS#0} ))
elif (( ${SECONDS#0} >= 31 && ${SECONDS#0} <= 59 )); then
    WAIT_SECONDS=$(( 60 - ${SECONDS#0} ))
fi

echo "Waiting ${WAIT_SECONDS:-0}s before generating a second code" >&2
sleep ${WAIT_SECONDS:-0}

CODE2=$(ykman oath code -s "$SERIAL_NUMBER")

aws iam resync-mfa-device \
    --user-name "$USERNAME" \
    --serial-number "$SERIAL_NUMBER" \
    --authentication-code1 "$CODE1" \
    --authentication-code2 "$CODE2"
