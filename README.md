AWS Vault
=========

Securely store and access credentials for AWS. AWS Vault stores IAM credentials in your operating systems secure keystore and then generates temporary credentials from those to expose to your shell and applications. It's designed to be complementary to the aws cli tools, and is aware of your configuration in `~/.aws/config`.

Currently OSX and Keychain are supported, with support for Linux and Windows planned.

## Usage

```bash

# make use of the default profile
$ aws-vault store
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %

$ aws-vault exec env | grep AWS
AWS_DEFAULT_PROFILE=default
AWS_ACCESS_KEY_ID=asdasd
AWS_SECRET_ACCESS_KEY=aasdasdasda

# add an extra profile
$ aws-vault store --profile work
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %

$ aws-vault exec --profile work env | grep AWS
AWS_DEFAULT_PROFILE=work
AWS_ACCESS_KEY_ID=asdasd
AWS_SECRET_ACCESS_KEY=aasdasdasda
```

## Multi-Factor Authentication

First you'll need to [setup an MFA token in the AWS Console](http://docs.aws.amazon.com/IAM/latest/UserGuide/GenerateMFAConfigAccount.html).

Edit your `~/.aws/config` to add the mfa_serial into either the default or a profile

```
[default]
region=us-east-1
mfa_serial = arn:aws:iam::123456789012:mfa/jonsmith
```

Test it out:

```bash
aws-vault exec aws iam get-user
Enter token code for "arn:aws:iam::123456789012:mfa/jonsmith": %
{
    "User": {
        "UserName": "jonsmith",
        "PasswordLastUsed": "2015-01-08T03:01:24Z",
        "CreateDate": "2011-06-13T23:32:35Z",
        "UserId": "AIDAAS545ABFI3NS",
        "Path": "/",
        "Arn": "arn:aws:iam::123456789012:user/jonsmith"
    }
}
```

## References and Inspiration

 * http://docs.aws.amazon.com/IAM/latest/UserGuide/MFAProtectedAPI.html
 * http://docs.aws.amazon.com/IAM/latest/UserGuide/IAMBestPractices.html#create-iam-users
 * https://github.com/paperg/awsudo
 * https://github.com/AdRoll/hologram
 * https://github.com/realestate-com-au/credulous
 * https://github.com/dump247/aws-mock-metadata
 * http://boto.readthedocs.org/en/latest/boto_config_tut.html

