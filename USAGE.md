# TOC

* [Help](#help)
* [Managing profiles](#managing-profiles)
    * [Using multiple profiles](#using-multiple-profiles)
    * [Example ~/.aws/config](#example-~/.aws/config)
    * [Listing profiles](#listing-profiles)
    * [Removing profiles](#removing-profiles)
* [Environment variables](#environment-variables)
* [Backends](#backends)
* [Removing stored sessions](#removing-stored-sessions)
* [Logging into aws console](#logging-into-aws-console)
* [Using credential helper](#using-credential-helper)
* [Not using session credentials](#not-using-session-credentials)
     * [Considerations](#considerations)
     * [Assuming a role for more than 1h](#assuming-a-role-for-more-than-1h)
     * [Being able to perform certain sts operations](#being-able-to-perform-certain-sts-operations)
* [Rotating credentials](#rotating-credentials)
* [Overriding the aws cli to use aws-vault](#overriding-the-aws-cli-to-use-aws-vault)

# Help

Context-sensitive help is available for every command in `aws-vault`.

```bash
# Show general help about aws-vault
$ aws-vault --help

# Show longer help about all options in aws-vault
$ aws-vault --help-long

# Show the most detailed information about the exec command
$ aws-vault exec --help
```

# Managing Profiles

## Using multiple profiles

In addition to using IAM roles to assume temporary privileges as described in
[README.md](./USAGE.md), aws-vault can also be used with multiple profiles directly. This allows you
to use multiple separate AWS accounts that have no relation to one another, such as work and home.

```bash
# Store AWS credentials for the "home" profile
$ aws-vault add home
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %

# Execute a command using temporary credentials
$ aws-vault exec home -- aws s3 ls
bucket_1
bucket_2

# store credentials for the "work" profile
$ aws-vault add work
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %

# Execute a command using temporary credentials
$ aws-vault exec work -- aws s3 ls
another_bucket
```

## Example ~/.aws/config

Here is an example ~/.aws/config file, to help show the configuration. It defines two AWS accounts:
"home" and "work", both of which use MFA. The work account provides two roles, allowing the user to
become either profile.

```ini
[profile home]
region = us-east-1
mfa_serial = arn:aws:iam::IAM_ACCOUNTID:mfa/home-account

[profile work]
region = eu-west-1
mfa_serial = arn:aws:iam::IAM_ACCOUNTID:mfa/work-account

[profile work-read_only_role]
role_arn = arn:aws:iam::IAM_ACCOUNTID:role/read_only_role
source_profile = work

[profile work-admin_role]
role_arn = arn:aws:iam::IAM_ACCOUNTID:role/admin_role
source_profile = work
```

## Listing profiles

You can use the `aws-vault list` command to list out the defined profiles, and any session
associated with them.

```bash
$ aws-vault list
Profile                  Credentials              Sessions  
=======                  ===========              ========                 
home                     home                        
work                     work                     1525456570  
work-read_only_role      work                        
work-admin_role          work                        
``` 

## Removing profiles

The `aws-vault remove` command can be used to remove credentials. It works similarly to the
`aws-vault add` command.

```bash
# Remove AWS credentials for the "work" profile
$ aws-vault remove work
Delete credentials for profile "work"? (Y|n)y
Deleted credentials.
Deleted 1 sessions.
```

`aws-vault remove` can also be used to close a session, leaving the credentials in place.

```bash
# Remove the session for the "work" profile, leaving the credentials in place
$ aws-vault remove work --sessions-only
Deleted 1 sessions.
```

# Environment variables

The following environment variables can be set to override the default flag
values of `aws-vault` and its subcommands.

For the `aws-vault` command:

* `AWS_VAULT_BACKEND`: Secret backend to use (see the flag `--backend`)
* `AWS_VAULT_KEYCHAIN_NAME`: Name of macOS keychain to use (see the flag `--keychain`)
* `AWS_VAULT_PROMPT`: Prompt driver to use (see the flag `--prompt`)

For the `aws-vault exec` subcommand:

* `AWS_ASSUME_ROLE_TTL`: Expiration time for aws assumed role (see the flag `--assume-role-ttl`)
* `AWS_SESSION_TTL`:  Expiration time for aws session (see the flag `--session-ttl`)

For the `aws-vault login` subcommand:

* `AWS_ASSUME_ROLE_TTL`: Expiration time for aws assumed role console session when not using --no-session (see the flag `--assume-role-ttl`)
* `AWS_FEDERATION_TOKEN_TTL`: Expiration time for aws console session (see the flag `--federation-token-ttl`)


# Backends

You can choose among different pluggable secret storage backends. 

By default, Linux uses an encrypted file but you may prefer to use the secret-service backend which [abstracts over Gnome/KDE](https://specifications.freedesktop.org/secret-service/). This can be specified on the command line with `aws-vault --backend=secret-service` or by setting the environment variable `export AWS_VAULT_BACKEND=secret-service`.


# Removing stored sessions

If you want to remove sessions managed by `aws-vault` before they expire, you can do this with the `--sessions-only` flag.

```bash
aws-vault remove <profile> --sessions-only
```

# Logging into AWS console

You can use the `aws-vault login` command to open a browser window and login to AWS Console for a
given account:
```bash
$ aws-vault login work
```

# Using credential helper

Ref: https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
This allows you to use credentials of multiple profiles at the same time.

# Not using session credentials

The way `aws-vault` works, whichever profile you use, it starts by opening a session with AWS. This
is basically a signed request (with the IAM user credentials) to AWS to get a temporary set of
credentials (see
[`GetSessionToken`](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html#stsapi_comparison)).
This allows for your base user credentials (that don't change often) to not be exposed to your
applications that need a connection to AWS. There are however 2 use cases where this is a problem
and we'll detail after a word of caution.

## Considerations

Before considering the 2 use cases below that use the `--no-session` parameter, you should
understand the trade-off you are making.  
The AWS session offers 2 perks:
* **a *cached* connection/session** to AWS that can authenticate you with MFA. That means that with a
  session, through `aws-vault`, you do not have to enter your MFA every time you use the command.
* **a security for your IAM user credentials**. When you set up `aws-vault` you give it your IAM user
  credentials and those are stored safely in some encrypted backend. When you execute a command
through `aws-vault` with a session, those credentials are retrieved to sign the AWS authentication
request but they are never exposed. Instead `aws-vault` exposes the credentials of the **temporary**
session it just opened, which gives you (mostly) the same access as with your IAM user, but through
an `ACCESS_KEY_ID` and `SECRET_ACCESS_KEY` that expire, therefore improving the security.

Not using a session (as a solution for the limitations described in the following 2 sections) means
that you lose the *cached* connection and that you *might* lessen the security. 2 cases:
* If you use a connection profile that uses a simple IAM user and not a `role_arn`, then using
  `aws-vault` without session will expose your IAM user credentials directly to the
terminal/application you are running. This is basically the opposite of what you are trying to do
using `aws-vault`.
You can easily witness that by doing
```
aws-vault exec <iam_user_profile> -- env | grep AWS
```
You'll see an `AWS_ACCESS_KEY_ID` of the form `ASIAxxxxxx` which is a temporary one. Doing 
```
aws-vault exec <iam_user_profile> --no-session -- env | grep AWS
```
You'll see your IAM user `AWS_ACCESS_KEY_ID` of the form `AKIAxxxxx` directly exposed, as well as
the corresponding `AWS_SECRET_KEY_ID`.
* If you use a connection profile with a `role_arn`, since `aws-vault` will use the `AssumeRole`
  API, it will anyway only expose a set of *temporary* credentials and will therefore not lessen the
security of the setup. You can execute the same test as before to see it for yourself.

## Assuming a role for more than 1h

If you try to assume a role from an opened (temporary) session, AWS considers that as *role
chaining* and it limits your ability to assume the target role to only **1h**. Trying to use
`--assume-role-ttl` with a value bigger than **1h** will result in an error:
```
aws-vault: error: Failed to get credentials for default (source profile for pix4d): ValidationError:
The requested DurationSeconds exceeds the 1 hour session limit for roles assumed by role chaining.
        status code: 400, request id: aa58fa50-4a5e-11e9-9566-293ea5c350ee
```
There are reasons though where you'd like to assume a role for a longer period. For example, when
using a tool like [Terraform](https://www.terraform.io/), you need to have AWS credentials available
to the application for the entire duration of the infrastructure change. And in large setups, or for
complex resources, this can take more than 1h.  
There are 2 solutions:

1. Call aws-vault with `--no-session`. This means that the `AssumeRole` API
will be called by using directly the IAM user credentials and not opening a session. This is not a
*role chaining* and therefore you can request a role for up to 12 hours (`--assume-role-ttl=12h`),
so long as you have setup your role to allow such a thing (AWS role are created by *default* with a
max TTL of 1h). The drawback of this method is related to **MFA**. Since you are not using the AWS
session, which is cached by `aws-vault`, if you use **MFA** (and you should), you'll have to enter
your **MFA** token at every invocation of the `aws-vault` command. This can become a bit tedious.  

2. Start `aws-vault` as a server (`aws-vault exec <profile> -s`). This will start a background
   process that will immitate the [metadata
endpoint](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html) that you
would have on an EC2 instance. When your application will want to connect to AWS and fail to find
credentials (typically in env variables), it will instead contact this server that will issue a new
set of temporary credentials (using the same profile as the one the server was started with). This
server will work only for the duration of the session (`--session-ttl`).  
Note that this approach has the **major drawback** that while this `aws-vault` server runs, any
application wanting to **connect** to AWS will be able to do so **implicitely**, with the profile the
server was started with. Thanks to `aws-vault`, the credentials are not exposed, but the ability to
use them to connect to AWS is!

## Being able to perform certain STS operations

While using a standard `aws-vault` connection, using an IAM role or not, you cannot use any STS API
(except `AssumeRole`) due to the usage of the AWS session (see
[here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html#stsapi_comparison)).
Note that this is done for security reasons and makes sense. Needing to call the STS API from a
session is generally a **non-standard situation**.  
But if you are sure of your use case, using the `--no-session` parameter will solve the issue.

Note that for the 
[`GetFederationToken`](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html)
API, as a STS API, you can't call it from an AWS session, but you also cannot call it using an IAM
role. This means that the only way to call `GetFederationToken` is to use both `--no-session` and an
`aws-vault` profile that does not use a `role_arn`. This therefore exposes your IAM user's
credentials (see before) and you should really check your design before going forward.


# Rotating Credentials

Regularly rotating your access keys is a critical part of credential management. You can do this with the `aws-vault rotate <profile>` command as often as you like.

The minimal IAM policy required to rotate your own credentials is:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateAccessKey",
                "iam:DeleteAccessKey",
                "iam:GetUser"
            ],
            "Resource": [
                "arn:aws:iam::*:user/${aws:username}"
            ]
        }
    ]
}
```


# Overriding the aws CLI to use aws-vault

If you want the `aws` command to use aws-vault automatically, you can create an overriding script
(make it higher precedence in your PATH) that looks like the below:

```bash
#!/bin/bash
exec aws-vault exec "${AWS_DEFAULT_PROFILE:-work}" -- /usr/local/bin/aws "$@"
```

The exec helps reduce the number of processes that are hanging around. The `$@` passes on the
arguments from the wrapper to the original command.
