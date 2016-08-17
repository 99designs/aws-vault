AWS Vault
=========

Securely store and access credentials for AWS. AWS Vault stores IAM credentials in your operating systems secure keystore and then generates temporary credentials from those to expose to your shell and applications. It's designed to be complementary to the aws cli tools, and is aware of your [profiles and configuration in `~/.aws/config`](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-config-files).

Currently macOS (Mac OS X)/Keychain and Linux/KWallet are supported, support for Linux's libsecret and Windows planned.

## Installing

Download the [latest release](https://github.com/99designs/aws-vault/releases).

On macOS, you may instead use [homebrew cask](https://github.com/caskroom/homebrew-cask) to install:

    brew cask install aws-vault

The macOS release is code-signed, and you can verify this with `codesign`:

    codesign -dvvv $(which aws-vault) | grep NRM9HVJ62Z
    Authority=3rd Party Mac Developer Application: 99designs Inc (NRM9HVJ62Z)

## Usage

```bash

$ aws-vault add home
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %

$ aws-vault exec default -- aws s3 ls
bucket_1
bucket_2

$ aws-vault add work
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %

$ aws-vault exec work -- aws s3 ls
another_bucket
```

## Security

Notice in the above how a session token gets written out. This is because `aws-vault` uses Amazon's STS service
to generate [temporary credentials](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html) them via the GetSessionToken or AssumeRole API calls. These expire in a short period of time, so the risk of leaking credentials is reduced.

The credentials are exposed to the subprocess in one of two ways:

 * Environment variables are written to the sub-process.

 * Local [EC2 Instance Metadata server](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html) is started. This approach has the advantage that anything that uses Amazon's SDKs will automatically refresh credentials as needed, so session times can be as short as possible. The downside is that only one can run per host and because it binds to `169.254.169.254:80`, your sudo password is required.

The default is to use environment variables, but you can opt-in to the local instance metadata server the `--server` flag to the `exec` command.

## MFA Tokens

If you have an MFA device attached to your account, the STS service will generate session tokens that are *invalid* unless you provide an MFA code. To enable MFA for a profile, specify the MFA serial in `~/.aws/config`:

```
[profile default]
mfa_serial=arn:aws:iam::123456789012:mfa/jonsmith
```

You can retrieve the MFA's serial (ARN) in the web console, or you can usually derive it pretty easily using the format `arn:aws:iam::[account-id]:mfa/[your-iam-username].

Note that if you have an account with an MFA associated, but you don't provide the IAM, you are unable to call IAM services, even if you have the correct permissions to do so.

## Assuming Roles

Best-practice is to have a read-only account that you use on a day-to-day basis, and then use [IAM roles to assume temporary admin privileges](http://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html) along with an MFA.

First you'll need to [setup an MFA token in the AWS Console](http://docs.aws.amazon.com/IAM/latest/UserGuide/GenerateMFAConfigAccount.html) and create a role with admin access.

Edit your `~/.aws/config` to add the role_arn and MFA serial number into a new profile:

```
[profile read-only]
region=us-east-1

[profile admin]
mfa_serial = arn:aws:iam::123456789012:mfa/jonsmith
source_profile = read-only
role_arn = arn:aws:iam::123456789012:role/admin-access
```

Then when you use the `admin` profile, `aws-vault` will look in the `read-only` profile's keychain for credentials and then use those credentials to assume the `admin` role. This assumed role is stored as a short duration session in your keychain so you will only have to enter MFA once per session.

## Development

Developed with golang 1.5 with `GO15VENDOREXPERIMENT=1`, to install:

```
export GO15VENDOREXPERIMENT=1
go get github.com/99designs/aws-vault
```

## References and Inspiration

 * https://github.com/pda/aws-keychain
 * http://docs.aws.amazon.com/IAM/latest/UserGuide/MFAProtectedAPI.html
 * http://docs.aws.amazon.com/IAM/latest/UserGuide/IAMBestPractices.html#create-iam-users
 * https://github.com/paperg/awsudo
 * https://github.com/AdRoll/hologram
 * https://github.com/realestate-com-au/credulous
 * https://github.com/dump247/aws-mock-metadata
 * http://boto.readthedocs.org/en/latest/boto_config_tut.html

