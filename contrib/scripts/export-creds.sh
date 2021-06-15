#!/usr/bin/env sh

set -euo pipefail

umask 077

err_report() {
    echo "[ERROR] Command on line $1 exited with exit code $2"
    exit $2
}
trap 'err_report $LINENO $?' ERR

help() {
    echo "USAGE: $0 [--no-session] profile"
}

help_long() {
    help
    echo '

Options
	--no-session
		Passed thrugh to aws-vault. Skip creating STS session with GetSessionToken.

	profile
		Profile from aws-vault to export to ~/.aws/credentials. The profile name used in the
		credentials file will be "${profile}-creds".

Overview

	This script will export credentials in aws-vault for the given profile to ~/.aws/credentials. By
	default these are temporary credentials created by aws-vault either through get-session-token or
	assume-role, if --no-session is passed then the long-term credentials or exported instead if
	possible (this will not work as expected if source_profile is used).

Security

	Generally using temporary credentials through the credentials file is fairly safe. While it may seem
	odd to write credentials back out to this file when using aws-vault the primary benefit of using 
	aws-vault is to protect the long-term key while aws-vault is not in use.

	Assuming this script is not run with --no-session then this still applies, only short-term
	credentials will be present on disk. Having these on disk instead of in environment variables
	or available through the metadata service can to some degree protect against compromised low
	privileged users on the same computer, environment variables are typically readable by any
	user and network access is generally not restricted based on UID. Currently, this script doesn'"'"'t
	protect against this kind of attack when it is running due to the awscli not supporting secrets
	passed in through Stdin (TODO: patch to awscli to fix this). This however does not apply after
	the secret is exported to the credentials file.

	This script also checks the permissions on ~/.aws/credentials to ensure it is not readable by
	all users on the system and exits with an error if it is.
'
}

NO_SESSION=''
POSITIONAL=()
while test "$#" -gt 0; do
    case "$1" in
        --no-session)
        NO_SESSION='--no-session'
        shift
        ;;
        -h|--help)
        help_long
        exit 1
        shift
        ;;
        *)    # unknown option
        POSITIONAL+=("$1") # save it in an array for later
        shift # past argument
        ;;
    esac
done

set -- "${POSITIONAL[@]:-}" # restore positional parameters

if test "$#" -gt 1; then
    help
    exit 2
fi

PROFILE="${1:-}"

if test -z "$PROFILE"; then
    echo '[ERROR] Must include profile name to export.'
    help
    exit 4
fi
    
cred_file="$HOME/.aws/credentials" 
if ls -l "$cred_file" | grep -q '^.......r..'; then
    echo "[ERROR] The credentials file '${cred_file}' is readable by other users"
    exit 101
fi


aws-vault exec $NO_SESSION "${PROFILE}" -- sh -c "
    set -eu
    aws configure --profile "${PROFILE}-creds" set region \"\$AWS_REGION\"
    aws configure --profile "${PROFILE}-creds" set aws_access_key_id \"\$AWS_ACCESS_KEY_ID\"
    aws configure --profile "${PROFILE}-creds" set aws_secret_access_key \"\$AWS_SECRET_ACCESS_KEY\"
    aws configure --profile "${PROFILE}-creds" set aws_session_token \"\${AWS_SESSION_TOKEN:-}\"
"

echo "The profile ${PROFILE}-creds is set up."
