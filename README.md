AWS Vault
=========

Securely store and access credentials for AWS. AWS Vault stores IAM credentials in your operating systems secure keystore and then generates temporary credentials from those to expose to your shell and applications. It's designed to be complementary to the aws cli tools, and is aware of your configuration in `~/.aws/config`.

Currently OSX and Keychain are supported, with support for Linux and Windows planned.

## Usage

```bash
$ aws-vault store
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %

$ aws-vault exec bash -c "env | grep AWS"
AWS_DEFAULT_PROFILE=default
AWS_ACCESS_KEY_ID=asdasd
AWS_SECRET_ACCESS_KEY=aasdasdasda

$ aws-vault rm
Delete credentials for profile "default"? Y
```

## Reference

 * http://docs.aws.amazon.com/IAM/latest/UserGuide/IAMBestPractices.html#create-iam-users

