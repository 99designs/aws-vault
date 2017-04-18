
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
