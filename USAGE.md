
# Help

aws-vault --help


## Multiple profiles

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

You can create an overriding script (make it higher precedence in your PATH) that looks like the below:

```
#!/bin/bash
set -euo pipefail
 
AWS_PROFILE="${AWS_DEFAULT_PROFILE:-work}"
exec aws-vault exec "$AWS_PROFILE" -- /usr/local/bin/aws "$@"
```

The exec helps reduce the number of processes that are hanging around. The `$@` passes on the arguments from the wrapper to the original command.


## Backends

You can choose different secret storage backends, which may be particularly useful on Linux, where you may prefer to use the system keyring with this environment variable:

    AWS_VAULT_BACKEND=secret-service

## Not using session credentials

**Careful**: this section is about a run mode that **lessens the security** given by default by
aws-vault. It should be used only when there is a real reason to do so.

When you setup aws-vault, you give it your AWS Access Key. However, when running aws-vault, it
opens a temporary session and exposes this session's credentials rather than your original root
credentials. Your actual credentials are in fact never exposed.

Unfortunately, AWS enforces some limitations for connections opened using session credentials. One
of those limitations is that you cannot do a
[GetFederationToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html)
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

A common case is having a web application that uses AWS S3 as a file storage. This S3
space is completely private for data privacy reasons. There is no public drop zone or whatever. When
clients of this application want to upload data to the service, they use an API to request temporary
access to S3. The application then uses AWS API to get a federation token, with specific IAM access
rights (typically can write only in a client specific location in the S3 bucket). The client can
then use those one-off temporary credentials with limited access to connect to S3 and drop some
files there.

In such a situation, if you are running a local server, e.g. for dev, and want to call this API,
then you can't use an AWS session, because AWS will return a 403 on the GetFederationToken
operation. That is when you'll use the less secure solution described above.
