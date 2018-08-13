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


## Using aws-vault with multiple profiles

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


## Overriding the aws CLI to use aws-vault

If you want the `aws` command to use aws-vault automatically, you can create an overriding script
(make it higher precedence in your PATH) that looks like the below:

```bash
#!/bin/bash
exec aws-vault exec "${AWS_DEFAULT_PROFILE:-work}" -- /usr/local/bin/aws "$@"
```

The exec helps reduce the number of processes that are hanging around. The `$@` passes on the
arguments from the wrapper to the original command.


## Backends

You can choose different secret storage backends, which may be particularly useful on Linux, where
you may prefer to use the system keyring. This can be specified on the command line with
`aws-vault --backend=secret-service` or by setting the environment variable
`export AWS_VAULT_BACKEND=secret-service`.


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


## Logging into AWS console

You can use the `aws-vault login` command to open a browser window and login to AWS Console for a
given account:
```bash
$ aws-vault login work
```


## Not using session credentials

**Careful**: this section is about a run mode that **lessens the security** given by default by
aws-vault. It should be used only when there is a real reason to do so.

When you setup aws-vault, you give it your AWS Access Key. However, when running aws-vault, it opens
a temporary session and exposes this session's credentials rather than your original root
credentials. Your actual credentials are in fact never exposed.

Unfortunately, AWS enforces some limitations for connections opened using session credentials. One
of those limitations is that you cannot do a [GetFederationToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html)
action with such a connection.

In the rare cases where being able to perform this action is needed, you'll have to tell aws-vault
to run in a less secure mode and not give you a session, but rather expose the original credentials
like so
```
aws-vault exec work --no-session -- YOUR COMMAND
```

You can check the difference between

```
aws-vault exec work --no-session -- env | grep AWS
aws-vault exec work -- env | grep AWS
```

### Example use case

A common case is having a web application that uses AWS S3 as a file storage. This S3 space is
completely private for data privacy reasons. There is no public drop zone or whatever. When clients
of this application want to upload data to the service, they use an API to request temporary access
to S3. The application then uses AWS API to get a federation token, with specific IAM access rights
(typically can write only in a client specific location in the S3 bucket). The client can then use
those one-off temporary credentials with limited access to connect to S3 and drop some files there.

In such a situation, if you are running a local server, e.g. for dev, and want to call this API,
then you can't use an AWS session, because AWS will return a 403 on the GetFederationToken
operation. That is when you'll use the less secure solution described above.


## Environment variables

The following environment variables can be set to override the default flag
values of `aws-vault` and its subcommands.

For the `aws-vault` command:

* `AWS_VAULT_BACKEND`: Secret backend to use (see the flag `--backend`)
* `AWS_VAULT_KEYCHAIN_NAME`: Name of macOS keychain to use (see the flag `--keychain`)
* `AWS_VAULT_PROMPT`: Prompt driver to use (see the flag `--prompt`)

For the `aws-vault exec` subcommand:

* `AWS_ASSUME_ROLE_TTL`: Expiration time for aws assumed role (see the flag `--assume-role-ttl)
* `AWS_SESSION_TTL`:  Expiration time for aws session (see the flag `--session-ttl`)

For the `aws-vault login` subcommand:

* `AWS_FEDERATION_TOKEN_TTL`: Expiration time for aws console session (see the flag `--federation-token-ttl`)


## Example ~/.aws/config

Here is an example ~/.aws/config file, to help show the configuation. It defines two AWS accounts:
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
mfa_serial = arn:aws:iam::IAM_ACCOUNTID:mfa/work-account

[profile work-admin_role]
role_arn = arn:aws:iam::IAM_ACCOUNTID:role/admin_role
source_profile = work
mfa_serial = arn:aws:iam::IAM_ACCOUNTID:mfa/work-account
```
