AWS Vault
=========

Securely store and access credentials for AWS. AWS Vault stores IAM credentials in your operating systems secure keystore and then generates temporary credentials from those to expose to your shell and applications. It's designed to be complementary to the aws cli tools, and is aware of your [profiles and configuration in `~/.aws/config`](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-config-files).

Currently OSX and Keychain are supported, with support for Linux and Windows planned.

## Installing

Download the [latest release](https://github.com/99designs/aws-vault/releases). The OSX release is code-signed, and you can verify this with `codesign -dvvv aws-vault`.

## Usage

```bash

# make use of the default profile
$ aws-vault add default
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %

$ aws-vault exec default -- env | grep AWS
AWS_ACCESS_KEY_ID=asdasd
AWS_SECRET_ACCESS_KEY=aasdasdasda
AWS_SESSION_TOKEN=aslksdjlskdhlskdjflkj%lskdjfsl

# add an extra profile
$ aws-vault add work
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %

$ aws-vault exec work -- env | grep AWS
AWS_ACCESS_KEY_ID=asdasd
AWS_SECRET_ACCESS_KEY=aasdasdasda
AWS_SESSION_TOKEN=aslksdjlskdhlskdjflkj%lskdjfsl
```

## Security

Notice in the above how a session token gets written out. This is because `aws-vault` uses Amazon's STS service
to generate [temporary credentials](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html). These expire in a short period of time, so the risk of leaking credentials is reduced.

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

