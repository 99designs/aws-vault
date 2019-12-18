# AWS Vault

AWS Vault is a tool to securely store and access AWS credentials in a development environment.

AWS Vault stores IAM credentials in your operating system's secure keystore and then generates temporary credentials from those to expose to your shell and applications. It's designed to be complementary to the AWS CLI tools, and is aware of your [profiles and configuration in `~/.aws/config`](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-config-files).

The supported backends are:

* [macOS Keychain](https://support.apple.com/en-au/guide/keychain-access/welcome/mac)
* [Windows Credential Manager](https://support.microsoft.com/en-au/help/4026814/windows-accessing-credential-manager)
* Secret Service ([Gnome Keyring](https://wiki.gnome.org/Projects/GnomeKeyring), [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5))
* [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5)
* [Pass](https://www.passwordstore.org/)
* Encrypted file

Check out the [announcement blog post](https://99designs.com.au/tech-blog/blog/2015/10/26/aws-vault/) for more details.


## Installing

You can install aws-vault:
- by downloading the [latest release](https://github.com/99designs/aws-vault/releases)
- on macOS via [Homebrew Cask](https://github.com/caskroom/homebrew-cask) with `brew cask install aws-vault`
- on Linux via [Homebrew on Linux](https://docs.brew.sh/Homebrew-on-Linux) with `brew install aws-vault`
- on Windows via [choco](https://chocolatey.org/packages/aws-vault) with `choco install aws-vault`
- on Archlinux via the [AUR](https://aur.archlinux.org/packages/aws-vault/)
- by compiling with `go get github.com/99designs/aws-vault`


## Basic Usage

```bash
# Store AWS credentials for the "home" profile
$ aws-vault add home
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %%%

# Execute a command (using temporary credentials)
$ aws-vault exec home -- aws s3 ls
bucket_1
bucket_2

# open a browser window and login to the AWS Console
$ aws-vault login home

# List credentials
$ aws-vault list
Profile                  Credentials              Sessions
=======                  ===========              ========
home                     home                     -
```
See the [USAGE](./USAGE.md) document for more help and tips.


## Security
```bash
$ aws-vault exec home -- env | grep AWS
AWS_VAULT=home
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=%%%
AWS_SECRET_ACCESS_KEY=%%%
AWS_SESSION_TOKEN=%%%
AWS_SECURITY_TOKEN=%%%
```

Notice in the above environment how a session token gets written out. This is because `aws-vault` uses Amazon's STS service to generate [temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html) via the `GetSessionToken` or `AssumeRole` API calls. These expire in a short period of time, so the risk of leaking credentials is reduced.

The credentials are exposed to the subprocess in one of two ways:

 * Environment variables are written to the sub-process.

 * Local [EC2 Instance Metadata server](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html) is started. This approach has the advantage that anything that uses Amazon's SDKs will automatically refresh credentials as needed, so session times can be as short as possible. The downside is that only one can run per host and because it binds to `169.254.169.254:80`, your sudo password is required.

The default is to use environment variables, but you can opt-in to the local instance metadata server with the `--server` flag on the `exec` command.

### Assuming Roles

[Best-practice](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#delegate-using-roles) is to [create Roles to delegate permissions](https://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html).

First you'll need to create the users and roles in IAM. Next, edit your `~/.aws/config` to add profiles with a `role_arn`. For example:

```ini
[profile jonsmith]
region = us-east-1

[profile prod-readonly]
region=us-east-1
role_arn = arn:aws:iam::111111111111:role/ReadOnly
source_profile = jonsmith

[profile prod-admin]
region=us-east-1
role_arn = arn:aws:iam::111111111111:role/Administrator
source_profile = jonsmith
```

Now when you use the `prod-admin` profile, `aws-vault` will look in the `jonsmith` profile's keychain for credentials and then use those credentials to assume the `Administrator` role.

### Using MFA

For security, you should also require that users provide a one-time key generated from a multi-factor authentication (MFA) device.

First you'll need to [setup an MFA device](https://docs.aws.amazon.com/IAM/latest/UserGuide/GenerateMFAConfigAccount.html). You can then [set up IAM roles to enforce MFA](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html#cli-configure-role-mfa). Next, add a line to the role profile that specifies the ARN of the user's MFA device. For example:

```ini
[profile jonsmith]
region = us-east-1

[profile prod-readonly]
region=us-east-1
role_arn = arn:aws:iam::111111111111:role/ReadOnly
source_profile = jonsmith

[profile prod-admin]
region=us-east-1
role_arn = arn:aws:iam::111111111111:role/Administrator
mfa_serial = arn:aws:iam::111111111111:mfa/jonsmith
source_profile = jonsmith
```

Now when you use the `prod-admin` profile `aws-vault` will prompt you for an MFA token. This assumed role's session is stored in your keychain so you will only have to enter your MFA once.

### Using credential_process

This allows you to switch profiles using the environment variable of `AWS_PROFILE=<profile-name>`

Be sure you have `AWS_SDK_LOAD_CONFIG=true` in your environment. What's needed is an alias profile that when setting environment variable can be the parameter

```ini
# ~/.aws/config
[profile jonsmith]

[profile _source_prod_admin]
source_profile=jonsmith
role_arn=arn:aws:iam::111111111111:role/Administrator
mfa_serial=arn:aws:iam::000000000000:mfa/jonsmith

[profile prod_admin]
credential_process=aws-vault exec _source_prod_admin --json
```

One can add this alias to switch profiles using `assume <profile-name>`

```
assume() {
  export AWS_PROFILE=$1
}
```


## macOS Code Signing

The [macOS release builds](https://github.com/99designs/aws-vault/releases) are code-signed to avoid extra prompts in Keychain. You can verify this with:

    $ codesign --verify --verbose $(which aws-vault)

If you are developing or compiling the aws-vault binary yourself, you can [generate a self-signed certificate](https://support.apple.com/en-au/guide/keychain-access/kyca8916/mac) by accessing Keychain Access > Certificate Assistant > Create Certificate > Code Signing Certificate. You can then sign your binary with:

    $ go build .
    $ codesign --sign "Name of my certificate" ./aws-vault


## References and Inspiration

 * https://github.com/pda/aws-keychain
 * https://docs.aws.amazon.com/IAM/latest/UserGuide/MFAProtectedAPI.html
 * https://docs.aws.amazon.com/IAM/latest/UserGuide/IAMBestPractices.html#create-iam-users
 * https://github.com/makethunder/awsudo
 * https://github.com/AdRoll/hologram
 * https://github.com/realestate-com-au/credulous
 * https://github.com/dump247/aws-mock-metadata
 * https://boto.readthedocs.org/en/latest/boto_config_tut.html
