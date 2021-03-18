#!/bin/sh

set -eu

waittime() {
    # wait until next code can be generated
    # if SECONDS are :00 or :30, generate right away
    SECONDS=$(date +%S)
    if [ ${SECONDS#0} -gt 0 ] && [ ${SECONDS#0} -lt 30 ]; then
        WAIT_SECONDS=$(( 30 - ${SECONDS#0} ))
    elif [ ${SECONDS#0} -gt 30 ] && [ ${SECONDS#0} -lt 60 ]; then
        WAIT_SECONDS=$(( 60 - ${SECONDS#0} ))
    fi
    echo ${WAIT_SECONDS:-0}
}

ACCOUNT_ARN=$(aws sts get-caller-identity --query Arn --output text)
# Assume that the final portion of the ARN is the username
# Works for ARNs like `users/<user>` and `users/engineers/<user>`
USERNAME=$(echo "$ACCOUNT_ARN" | rev | cut -d/ -f1 | rev)
ACCOUNT_ID=$(echo "$ACCOUNT_ARN" | cut -d: -f5)
SERIAL_NUMBER="arn:aws:iam::${ACCOUNT_ID}:mfa/${USERNAME}"

CODE1=$(ykman oath code -s "$SERIAL_NUMBER")

WAIT_TIME=$(waittime)

echo "Waiting ${WAIT_TIME}s before generating a second code" >&2
sleep ${WAIT_TIME}

CODE2=$(ykman oath code -s "$SERIAL_NUMBER")

aws iam resync-mfa-device \
    --user-name "$USERNAME" \
    --serial-number "$SERIAL_NUMBER" \
    --authentication-code1 "$CODE1" \
    --authentication-code2 "$CODE2"
