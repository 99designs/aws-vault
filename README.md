# AWS Vault

[![Downloads](https://img.shields.io/github/downloads/99designs/aws-vault/total.svg)](https://github.com/99designs/aws-vault/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/99designs/aws-vault)](https://goreportcard.com/report/github.com/99designs/aws-vault)
[![Continuous Integration](https://github.com/99designs/aws-vault/workflows/Continuous%20Integration/badge.svg)](https://github.com/99designs/aws-vault/actions)

AWS Vault is a tool to securely store and access AWS credentials in a development environment.

AWS Vault stores IAM credentials in your operating system's secure keystore and then generates temporary credentials from those to expose to your shell and applications. It's designed to be complementary to the AWS CLI tools, and is aware of your [profiles and configuration in `~/.aws/config`](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-config-files).

Check out the [announcement blog post](https://99designs.com.au/tech-blog/blog/2015/10/26/aws-vault/) for more details.

## Installing

You can install AWS Vault:
- by downloading the [latest release](https://github.com/99designs/aws-vault/releases/latest)
- on macOS with [Homebrew Cask](https://formulae.brew.sh/cask/aws-vault): `brew cask install aws-vault`
- on macOS with [MacPorts](https://ports.macports.org/port/aws-vault/summary): `port install aws-vault`
- on Windows with [Chocolatey](https://chocolatey.org/packages/aws-vault): `choco install aws-vault`
- on Windows with [Scoop](https://scoop.sh/): `scoop install aws-vault`
- on Linux with [Homebrew on Linux](https://formulae.brew.sh/formula-linux/aws-vault): `brew install aws-vault`
- on [Arch Linux](https://www.archlinux.org/packages/community/x86_64/aws-vault/): `pacman -S aws-vault`
- on [FreeBSD](https://www.freshports.org/security/aws-vault/): `pkg install aws-vault`
- with [Nix](https://nixos.org/nixos/packages.html?attr=aws-vault): `nix-env -i aws-vault`

## Documentation

Config, usage, tips and tricks are available in the [USAGE.md](./USAGE.md) file.

## Vaulting Backends

The supported vaulting backends are:

* [macOS Keychain](https://support.apple.com/en-au/guide/keychain-access/welcome/mac)
* [Windows Credential Manager](https://support.microsoft.com/en-au/help/4026814/windows-accessing-credential-manager)
* Secret Service ([Gnome Keyring](https://wiki.gnome.org/Projects/GnomeKeyring), [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5))
* [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5)
* [Pass](https://www.passwordstore.org/)
* Encrypted file

Use the `--backend` flag or `AWS_VAULT_BACKEND` environment variable to specify.

## Quick start

```shell
# Store AWS credentials for the "jonsmith" profile
$ aws-vault add jonsmith
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %%%

# Execute a command (using temporary credentials)
$ aws-vault exec jonsmith -- aws s3 ls
bucket_1
bucket_2

# open a browser window and login to the AWS Console
$ aws-vault login jonsmith

# List credentials
$ aws-vault list
Profile                  Credentials              Sessions
=======                  ===========              ========
jonsmith                 jonsmith                 -
```

## How it works

`aws-vault` uses Amazon's STS service to generate [temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html) via the `GetSessionToken` or `AssumeRole` API calls. These expire in a short period of time, so the risk of leaking credentials is reduced.

AWS Vault then exposes the temporary credentials to the sub-process in one of two ways

1. **Environment variables** are written to the sub-process. Notice in the below example how the AWS credentials get written out
   ```shell
   $ aws-vault exec jonsmith -- env | grep AWS
   AWS_VAULT=jonsmith
   AWS_DEFAULT_REGION=us-east-1
   AWS_REGION=us-east-1
   AWS_ACCESS_KEY_ID=%%%
   AWS_SECRET_ACCESS_KEY=%%%
   AWS_SESSION_TOKEN=%%%
   AWS_SECURITY_TOKEN=%%%
   AWS_SESSION_EXPIRATION=2020-04-16T11:16:27Z
   ```
2. **Local [EC2 Instance Metadata server](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)** is started. This approach has the advantage that anything that uses Amazon's SDKs will automatically refresh credentials as needed, so session times can be as short as possible. The downside is that only one can run per host and because it binds to `169.254.169.254:80`, your sudo password is required.

The default is to use environment variables, but you can opt-in to the local instance metadata server with the `--server` flag on the `exec` command.

## Roles and MFA

[Best-practice](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#delegate-using-roles) is to [create Roles to delegate permissions](https://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html). For security, you should also require that users provide a one-time key generated from a multi-factor authentication (MFA) device.

First you'll need to create the users and roles in IAM, as well as [setup an MFA device](https://docs.aws.amazon.com/IAM/latest/UserGuide/GenerateMFAConfigAccount.html). You can then [set up IAM roles to enforce MFA](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html#cli-configure-role-mfa).

Here's an example configuration using roles and MFA:

```ini
[default]
region = us-east-1

[profile jonsmith]
mfa_serial = arn:aws:iam::111111111111:mfa/jonsmith

[profile foo-readonly]
source_profile = jonsmith
role_arn = arn:aws:iam::22222222222:role/ReadOnly

[profile foo-admin]
source_profile = jonsmith
role_arn = arn:aws:iam::22222222222:role/Administrator
mfa_serial = arn:aws:iam::111111111111:mfa/jonsmith

[profile bar-role1]
source_profile = jonsmith
role_arn = arn:aws:iam::333333333333:role/Role1
mfa_serial = arn:aws:iam::111111111111:mfa/jonsmith

[profile bar-role2]
source_profile = bar-role1
role_arn = arn:aws:iam::333333333333:role/Role2
mfa_serial = arn:aws:iam::111111111111:mfa/jonsmith
```

Here's what you can expect from aws-vault 

| Command                                  | Credentials                 | Cached        | MFA |
|------------------------------------------|-----------------------------|---------------|-----|
| `aws-vault exec jonsmith --no-session`   | Long-term credentials       | No            | No  |
| `aws-vault exec jonsmith`                | session-token               | session-token | Yes |
| `aws-vault exec foo-readonly`            | role                        | No            | No  |
| `aws-vault exec foo-admin`               | session-token + role        | session-token | Yes |
| `aws-vault exec foo-admin --duration=2h` | role                        | role          | Yes |
| `aws-vault exec bar-role2`               | session-token + role + role | session-token | Yes |
| `aws-vault exec bar-role2 --no-session`  | role + role                 | role          | Yes |

## Development

The [macOS release builds](https://github.com/99designs/aws-vault/releases) are code-signed to avoid extra prompts in Keychain. You can verify this with:
```shell
$ codesign --verify --verbose $(which aws-vault)
```

If you are developing or compiling the aws-vault binary yourself, you can [generate a self-signed certificate](https://support.apple.com/en-au/guide/keychain-access/kyca8916/mac) by accessing Keychain Access > Certificate Assistant > Create Certificate -> Certificate Type: Code Signing. You can then sign your binary with:
```shell
$ go build .
$ codesign --sign <Name of certificate created above> ./aws-vault
```

## References and Inspiration

 * https://github.com/pda/aws-keychain
 * https://docs.aws.amazon.com/IAM/latest/UserGuide/MFAProtectedAPI.html
 * https://docs.aws.amazon.com/IAM/latest/UserGuide/IAMBestPractices.html#create-iam-users
 * https://github.com/makethunder/awsudo
 * https://github.com/AdRoll/hologram
 * https://github.com/realestate-com-au/credulous
 * https://github.com/dump247/aws-mock-metadata
 * https://boto.readthedocs.org/en/latest/boto_config_tut.html
