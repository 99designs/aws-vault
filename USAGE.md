# Usage

* [Getting Help](#getting-help)
* [Config](#config)
  * [AWS config file](#aws-config-file)
    * [`include_profile`](#include_profile)
  * [Environment variables](#environment-variables)
* [Backends](#backends)
  * [Keychain](#keychain)
* [Managing credentials](#managing-credentials)
  * [Using multiple profiles](#using-multiple-profiles)
  * [Listing profiles and credentials](#listing-profiles-and-credentials)
  * [Removing credentials](#removing-credentials)
  * [Rotating credentials](#rotating-credentials)
* [Managing Sessions](#managing-sessions)
  * [Executing a command](#executing-a-command)
  * [Logging into AWS console](#logging-into-aws-console)
  * [Removing stored sessions](#removing-stored-sessions)
  * [Using --no-session](#using---no-session)
  * [Session duration](#session-duration)
  * [Using `--server`](#using---server)
    * [`--ecs-server`](#--ecs-server)
  * [Temporary credentials limitations with STS, IAM](#temporary-credentials-limitations-with-sts-iam)
* [MFA](#mfa)
  * [Gotchas with MFA config](#gotchas-with-mfa-config)
* [AWS Single Sign-On (AWS SSO)](#aws-single-sign-on-aws-sso)
* [Assuming roles with web identities](#assuming-roles-with-web-identities)
* [Using `credential_process`](#using-credential_process)
* [Using a Yubikey](#using-a-yubikey)
  * [Prerequisites](#prerequisites)
  * [Setup](#setup)
  * [Usage](#usage)
* [Shell completion](#shell-completion)
* [Desktop apps](#desktop-apps)


## Getting Help

Context-sensitive help is available for every command in `aws-vault`.

```shell
# Show general help about aws-vault
$ aws-vault --help

# Show longer help about all options in aws-vault
$ aws-vault --help-long

# Show the most detailed information about the exec command
$ aws-vault exec --help
```


## Config

### AWS config file

aws-vault uses your `~/.aws/config` to load AWS config. This should work identically to the config specified by the [aws-cli docs](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html).

#### `include_profile`

(Note: aws-vault v5 calls this `parent_profile`)

AWS Vault also recognises an extra config variable, `include_profile`, which is not recognised by the aws-cli. This variable allows a profile to load configuration horizontally from another profile.

This is a flexible mechanism for more complex configurations.

For example you can use it in "mixin" style where you import a common fragment. In this example, the `root`, `order-dev` and `order-staging-admin` profiles include the `region`, `mfa_serial` and `source_profile` configuration from `common`.

```ini
; The "common" profile here operates as a "config fragment" rather than a profile
[profile common]
region=eu-west-1
mfa_serial=arn:aws:iam::123456789:mfa/johnsmith
source_profile = root

[profile root]
include_profile = common

[profile order-dev]
include_profile = common
role_arn=arn:aws:iam::123456789:role/developers

[profile order-staging-admin]
include_profile = common
role_arn=arn:aws:iam::123456789:role/administrators
```

Or you could use it in "parent" style where you conflate the fragment with the profile. In this example the `order-dev` and `order-staging-admin` profiles include the `region`, `mfa_serial` and `source_profile` configuration from `root`, while also using the credentials stored against the `root` profile as the source credentials `source_profile = root`
```ini
; The "root" profile here operates as a profile, a config fragment as well as a source_profile
[profile root]
region=eu-west-1
mfa_serial=arn:aws:iam::123456789:mfa/johnsmith
source_profile = root

[profile order-dev]
include_profile = root
role_arn=arn:aws:iam::123456789:role/developers

[profile order-staging-admin]
include_profile = root
role_arn=arn:aws:iam::123456789:role/administrators
```


### Environment variables

To configure the default flag values of `aws-vault` and its subcommands:
* `AWS_VAULT_BACKEND`: Secret backend to use (see the flag `--backend`)
* `AWS_VAULT_KEYCHAIN_NAME`: Name of macOS keychain to use (see the flag `--keychain`)
* `AWS_VAULT_PROMPT`: Prompt driver to use (see the flag `--prompt`)
* `AWS_VAULT_PASS_PASSWORD_STORE_DIR`: Pass password store directory (see the flag `--pass-dir`)
* `AWS_VAULT_PASS_CMD`: Name of the pass executable (see the flag `--pass-cmd`)
* `AWS_VAULT_PASS_PREFIX`: Prefix to prepend to the item path stored in pass (see the flag `--pass-prefix`)
* `AWS_VAULT_FILE_PASSPHRASE`: Password for the "file" password store
* `AWS_CONFIG_FILE`: The location of the AWS config file

To override the AWS config file (used in the `exec`, `login` and `rotate` subcommands):
* `AWS_REGION`: The AWS region
* `AWS_DEFAULT_REGION`: The AWS region, applied only if `AWS_REGION` isn't set
* `AWS_STS_REGIONAL_ENDPOINTS`: STS endpoint resolution logic, must be "regional" or "legacy"
* `AWS_MFA_SERIAL`: The identification number of the MFA device to use
* `AWS_ROLE_ARN`: Specifies the ARN of an IAM role in the active profile
* `AWS_ROLE_SESSION_NAME`: Specifies the name to attach to the role session in the active profile

To override session durations (used in `exec` and `login`):
* `AWS_SESSION_TOKEN_TTL`: Expiration time for the `GetSessionToken` credentials. Defaults to 1h
* `AWS_CHAINED_SESSION_TOKEN_TTL`: Expiration time for the `GetSessionToken` credentials when chaining profiles. Defaults to 8h
* `AWS_ASSUME_ROLE_TTL`: Expiration time for the `AssumeRole` credentials. Defaults to 1h
* `AWS_FEDERATION_TOKEN_TTL`: Expiration time for the `GetFederationToken` credentials. Defaults to 1h
* `AWS_MIN_TTL`: The minimum expiration time allowed for a credential. Defaults to 5m

Note that the session durations above expect a unit after the number (e.g. 12h or 43200s).


## Backends

You can choose among different pluggable secret storage backends. You can set the backend using the `--backend` flag or the `AWS_VAULT_BACKEND` environment variable. Run `aws-vault --help` to see what your `--backend` flag supports.

### Keychain

If you're looking to configure the amount of time between having to enter your Keychain password for each usage of a particular profile, you can do so through Keychain: 

1. Open "Keychain Access"
2. Open the aws-vault keychain. If you do not have "aws-vault" in the sidebar of the Keychain app, then you can do "File -> Add Keychain" and select the `aws-vault.keychain-db`. This is typically created in `Users/{USER}/Library/Keychains`. 
3. Right click on aws-vault keychain, and select "Change Settings for Keychain 'aws-vault"
4. Update "Lock after X minutes of inactivity" to your desired value. 
5. Hit save.

![keychain-image](https://imgur.com/ARkr5Ba.png)


## Managing credentials

### Using multiple profiles

In addition to using IAM roles to assume temporary privileges as described in [README.md](./USAGE.md), aws-vault can also be used with multiple profiles directly. This allows you to use multiple separate AWS accounts that have no relation to one another, such as work and home.

```shell
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

Here is an example `~/.aws/config` file, to help show the configuration. It defines two AWS accounts: "home" and "work", both of which use MFA. The work account provides two roles, allowing the user to become either profile.

```ini
[default]
region = us-east-1

[profile home]
mfa_serial = arn:aws:iam::111111111111:mfa/home-account

[profile work]
mfa_serial = arn:aws:iam::111111111111:mfa/work-account
role_arn = arn:aws:iam::111111111111:role/ReadOnly

[profile work-admin]
role_arn = arn:aws:iam::111111111111:role/Administrator
source_profile = work
```

### Listing profiles and credentials

You can use the `aws-vault list` command to list out the defined profiles, and any session associated with them.

```shell
$ aws-vault list
Profile                  Credentials              Sessions  
=======                  ===========              ========                 
home                     home                        
work                     work                     1525456570  
work-read-only           work                        
work-admin               work                        
``` 

### Removing credentials

The `aws-vault remove` command can be used to remove credentials. It works similarly to the `aws-vault add` command.

```shell
# Remove AWS credentials for the "work" profile
$ aws-vault remove work
Delete credentials for profile "work"? (y|N) y
Deleted credentials.
```

### Rotating credentials

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


## Managing Sessions

### Executing a command

Running `aws-vault exec` will run a command with AWS credentials.

When using exec, you may find it useful to use the builtin `--` feature in bash, zsh and other POSIX shells. For example
```shell
aws-vault exec myprofile -- aws s3 ls
```
Using `--` signifies the end of the `aws-vault` options, and allows the shell autocomplete to kick in and offer autocompletions for the proceeding command.

If you use `exec` without specifying a command, AWS Vault will create a new interactive subshell. Note that when creating an interactive subshell, bash, zsh and other POSIX shells will execute the `~/.bashrc` or `~/.zshrc` file. If you have local variables, functions or aliases (for example your `PS1` prompt), ensure that they are defined in the rc file so they get executed when the subshell begins.

### Logging into AWS console

You can use the `aws-vault login` command to open a browser window and login to AWS Console for a given account:
```shell
$ aws-vault login work
```

### Removing stored sessions

If you want to remove sessions managed by `aws-vault` before they expire, you can do this with `aws-vault clear` command.

You can also specify a profile to remove sessions for this profile only.
```shell
aws-vault clear [profile]
```

### Using --no-session

AWS Vault will typically create temporary credentials using a combination of `GetSessionToken` and `AssumeRole`, depending on the config. The `GetSessionToken` call is made with MFA if available, and the resulting session is cached in the backend vault and can be used to assume roles from different profiles without further MFA prompts.

If you wish to skip the `GetSessionToken` call, you can use the `--no-session` flag.

However, consider that if you use `--no-session` with a profile using IAM credentials and NO `role_arn`, then your IAM credentials will be directly exposed to the terminal/application you are running. This is the opposite of what you are normally trying to achieve by using AWS Vault. You can easily witness that by doing
```shell
aws-vault exec <iam_user_profile> -- env | grep AWS
```
You'll see an `AWS_ACCESS_KEY_ID` of the form `ASIAxxxxxx` which is a temporary one. Doing 
```shell
aws-vault exec <iam_user_profile> --no-session -- env | grep AWS
```
You'll see your IAM user `AWS_ACCESS_KEY_ID` of the form `AKIAxxxxx` directly exposed, as well as the corresponding `AWS_SECRET_KEY_ID`.


### Session duration

If you try to [assume a role](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html) from a temporary session or another role, AWS considers that as [role chaining](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#iam-term-role-chaining) and limits your ability to assume the target role to 1h. Trying to use a duration longer than 1h may result in an error:
```
aws-vault: error: Failed to get credentials for default: ValidationError: The requested DurationSeconds exceeds the MaxSessionDuration set for this role.
        status code: 400, request id: aa58fa50-4a5e-11e9-9566-293ea5c350ee
```

For that reason, AWS Vault will not use `GetSessionToken` if `--duration` or the role's `duration_seconds` is longer than 1h.

### Using `--server`

There may be scenarios where you'd like to assume a role for a long length of time, or perhaps when using a tool where using temporary sessions on demand is preferable. For example, when using a tool like [Terraform](https://www.terraform.io/), you need to have AWS credentials available to the application for the entire duration of the infrastructure change.

AWS Vault can run a background server to imitate the [metadata endpoint](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html) that you would have on an EC2 instance. When your application uses the AWS SDK to locate credentials, it will automatically connect to this server that will issue a new set of temporary credentials (using the same profile as the one the server was started with). This server will continue to generate temporary credentials any time the application requests it.

This approach has the major security drawback that while this `aws-vault` server runs, any application wanting to connect to AWS will be able to do so, using the profile the server was started with. Thanks to `aws-vault`, the credentials are not exposed, but the ability to use them to connect to AWS is!

To use `--server`, AWS Vault needs root/administrator privileges in order to bind to the privileged port. AWS Vault runs a minimal proxy as the root user, proxying through to the real aws-vault instance.

#### `--ecs-server`

An ECS credential server can also be used instead of the ec2 metadata server. The ECS Credential provider binds to a random, ephemeral port and requires an authorization token, which offer the following advantages over the EC2 Metadata provider:
 1. Does not require root/administrator privileges
 2. Allows multiple providers simultaneously for discrete processes
 3. Mitigates the security issues that accompany the EC2 Metadata Service because the address is not well-known and the authorization token is only exposed to the subprocess via environment variables

However, this will only work with the AWS SDKs that support `AWS_CONTAINER_CREDENTIALS_FULL_URI`. The Ruby, .NET and PHP SDKs do not currently support it.

### Temporary credentials limitations with STS, IAM

When using temporary credentials you are restricted from using some STS and IAM APIs (see [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html#stsapi_comparison)). You may need to avoid the temporary session by using `--no-session`.


## MFA

To enable MFA for a profile, specify the `mfa_serial` in `~/.aws/config`. You can retrieve the MFA's serial (ARN) in the web console, or you can usually derive it pretty easily using the format `arn:aws:iam::[account-id]:mfa/[your-iam-username]`. If you have an account with an MFA associated, but you don't provide the IAM, you are unable to call IAM services, even if you have the correct permissions to do so.

AWS Vault will attempt to re-use a `GetSessionToken` between profiles that share a common `mfa_serial`. In the following example, aws-vault will cache and re-use sessions between role1 and role2. This means you don't have to continually enter MFA codes if the user is the same.

```ini
[profile tom]
mfa_serial = arn:aws:iam::111111111111:mfa/tom

[profile role1]
source_profile = tom
role_arn = arn:aws:iam::22222222222:role/role1
mfa_serial = arn:aws:iam::111111111111:mfa/tom

[profile role2]
source_profile = tom
role_arn = arn:aws:iam::33333333333:role/role2
mfa_serial = arn:aws:iam::111111111111:mfa/tom
```

Be sure to specify the `mfa_serial` for the source profile (in the above example `tom`) so that aws-vault can match the common `mfa_serial`.

You can also set the `mfa_serial` with the environment variable `AWS_MFA_SERIAL`.

### Gotchas with MFA config

aws-vault v4 would inherit the `mfa_serial` from the `source_profile`. While this was intuitive for some, it made certain configurations difficult to express and is different behaviour to the aws-cli.

aws-vault v5 corrected this problem. The `mfa_serial` must be specified for _each_ profile, the same way the aws-cli interprets the configuration. If you wish to avoid specifying the `mfa_serial` for each profile, consider using the `mfa_serial` in the `[default]` section, the `AWS_MFA_SERIAL` environment variable, or [`include_profile`](#include_profile). For example:

```ini
[profile jon]
mfa_serial = arn:aws:iam::111111111111:mfa/jon
source_profile=jon

[profile role1]
role_arn = arn:aws:iam::22222222222:role/role1
include_profile = jon

[profile role2]
role_arn = arn:aws:iam::33333333333:role/role2
include_profile = jon
```

## AWS Single Sign-On (AWS SSO)

If your organization uses AWS Single Sign-On ([AWS SSO](https://aws.amazon.com/single-sign-on/)), AWS Vault provides a method for using the credential information defined by [AWS SSO CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html). The configuration options are as follows:
* `sso_start_url` The URL that points to the organization's AWS SSO user portal.
* `sso_region` The AWS Region that contains the AWS SSO portal host. This is separate from, and can be a different region than the default CLI region parameter.
* `sso_account_id` The AWS account ID that contains the IAM role that you want to use with this profile.
* `sso_role_name` The name of the IAM role that defines the user's permissions when using this profile.

Here is an example configuration using AWS SSO.

```ini
[profile Administrator-123456789012]
sso_start_url=https://aws-sso-portal.awsapps.com/start
sso_region=eu-west-1
sso_account_id=123456789012
sso_role_name=Administrator
```

## Assuming roles with web identities

AWS supports assuming roles using [web identity federation and OpenID Connect](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html#cli-configure-role-oidc), including login using Amazon, Google, Facebook or any other OpenID Connect server. The configuration options are as follows:
* `web_identity_token_file` A file that contains an OpenID Connect identity token. The token is loaded and passed as the `WebIdentityToken` argument of the `AssumeRoleWithWebIdentity` operation.
* `web_identity_token_process` A command that executes to generate an OpenID Connect identity token. The token written to the command's standard out is passed as the `WebIdentityToken` argument of the `AssumeRoleWithWebIdentity` operation. This is a custom option supported only by `aws-vault`.

An example configuration using a static token:

```ini
[profile role1]
role_arn = arn:aws:iam::22222222222:role/role1
web_identity_token_file = /path/to/token.txt
```

An example using a token generated by an external command:

```ini
[profile role2]
role_arn = arn:aws:iam::33333333333:role/role2
web_identity_token_process = oidccli raw
```

## Using `credential_process`

The [AWS CLI config](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes) supports sourcing credentials directly from an external process, using `credential_process`.

```ini
[profile home]
credential_process = aws-vault exec home --json
```

If `mfa_serial` is set, please define the prompt driver (for example `osascript` for macOS), else the prompt will not show up.

```ini
[profile work]
mfa_serial = arn:aws:iam::123456789012:mfa/jonsmith
credential_process = aws-vault exec work --json --prompt=osascript
```

Note that `credential_process` is designed for retrieving master credentials, while aws-vault outputs STS credentials by default. If a role is present, the AWS CLI/SDK uses the master credentials from the `credential_process` to generate STS credentials itself. So depending on your use-case, it might make sense for aws-vault to output master credentials by using a profile without a role and the `--no-session` argument. For example:

```ini
[profile jon]
credential_process = aws-vault exec --no-session --json jon

[profile work]
mfa_serial = arn:aws:iam::123456789012:mfa/jonsmith
role_arn = arn:aws:iam::33333333333:role/role2
source_profile = jon
```

If you're using `credential_process` in your config you should not use `aws-vault exec` on the command line to execute commands directly - the AWS SDK executes `aws-vault` for you.


## Using a Yubikey

Yubikeys can be used with AWS Vault via Yubikey's OATH-TOTP support. TOTP is necessary because FIDO-U2F is unsupported on the AWS API.

### Prerequisites
 1. [A Yubikey that supports OATH-TOTP](https://support.yubico.com/support/solutions/articles/15000006419-using-your-yubikey-with-authenticator-codes)
 2. `ykman`, the [YubiKey Manager CLI](https://github.com/Yubico/yubikey-manager) tool

You can verify these prerequisites by running `ykman info` and checking `OATH` is enabled.

### Setup
 1. Log into the AWS web console with your IAM user credentials, and navigate to  _My Security Credentials_
 2. Under _Multi-factor authentication (MFA)_, click `Manage MFA device` and add a Virtual MFA device
 3. Instead of showing the QR code, click on `Show secret key` and copy the key.
 4. On a command line, run:
    ```shell
    ykman oath add -t arn:aws:iam::${ACCOUNT_ID}:mfa/${IAM_USERNAME}
    ```
    replacing `${ACCOUNT_ID}` with your AWS account ID and `${IAM_USERNAME}` with your IAM username. It will prompt you for a base32 text and you can input the key from step 3. Notice the above command uses `-t` which requires you to touch your YubiKey to generate authentication codes.
 5. Now you have to enter two consecutive MFA codes into the AWS website to assign your key to your AWS login. Just run `ykman oath code arn:aws:iam::${ACCOUNT_ID}:mfa/${IAM_USERNAME}` to get an authentication code. The codes are re-generated every 30 seconds, so you have to run this command twice with about 30 seconds in between to get two distinct codes. Enter the two codes in the AWS form and click `Assign MFA`

A script can be found at [contrib/scripts/aws-iam-create-yubikey-mfa.sh](contrib/scripts/aws-iam-create-yubikey-mfa.sh) to automate the process.

### Usage
Using the `ykman` prompt driver, aws-vault will execute `ykman` to generate tokens for any profile in your `.aws/config` using an `mfa_device`.
```shell
aws-vault exec --prompt ykman ${AWS_VAULT_PROFILE_USING_MFA} -- aws s3 ls
```
Further config:
 - `AWS_VAULT_PROMPT=ykman`: to avoid specifying `--prompt` each time
 - `YKMAN_OATH_CREDENTIAL_NAME`: to use an alternative ykman credential


## Shell completion

You can generate shell completions with
```shell
# for bash
eval "$(aws-vault --completion-script-bash)"

# for zsh
eval "$(aws-vault --completion-script-zsh)"
```

There are more completion scripts at [contrib/completions](contrib/completions).


## Desktop apps

You can use desktop apps with temporary credentials from AWS Vault too! For example on macOS run
```shell
aws-vault exec --server --prompt=osascript jonsmith -- open -a Lens
```
* `--server`: starts the background server so that temporary credentials get refreshed automatically
* `--prompt=osascript`: pop up a GUI for MFA prompts
* `open -a Lens`: run the applications
