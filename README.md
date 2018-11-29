# AWS Vault

AWS Vault is a tool to securely store and access AWS credentials in a development environment.

AWS Vault stores IAM credentials in your operating system's secure keystore and then generates temporary credentials from those to expose to your shell and applications. It's designed to be complementary to the AWS CLI tools, and is aware of your [profiles and configuration in `~/.aws/config`](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-config-files).

Currently the supported backends are:

* [macOS Keychain Access](https://support.apple.com/en-au/guide/keychain-access/kyca1083/mac)
* [Windows Credential Manager](https://support.microsoft.com/en-au/help/4026814/windows-accessing-credential-manager)
* [Secret Service](https://specifications.freedesktop.org/secret-service/)
* [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5)
* [Pass](https://www.passwordstore.org/)
* Encrypted file

Check out the [announcement blog post](https://99designs.com.au/tech-blog/blog/2015/10/26/aws-vault/) for more details.


## Installing

You can install aws-vault:
- by downloading the [latest release](https://github.com/99designs/aws-vault/releases)
- on macOS via [homebrew](https://github.com/caskroom/homebrew-cask) with `brew cask install aws-vault`
- on Windows via [choco](https://chocolatey.org/packages/aws-vault) with `choco install aws-vault`
- on Archlinux via the [AUR](https://wiki.archlinux.org/index.php/Arch_User_Repository)
- by compiling with `go get github.com/99designs/aws-vault`


## Usage

See the [USAGE](./USAGE.md) document for more help and tips.

```bash
# Store AWS credentials for the "home" profile
$ aws-vault add home
Enter Access Key Id: ABDCDEFDASDASF
Enter Secret Key: %

# Execute a command using temporary credentials
$ aws-vault exec home -- aws s3 ls
bucket_1
bucket_2

# open a browser window and login to AWS Console
$ aws-vault login home # the optional -s flag returns the link to STDOUT

# List credentials
$ aws-vault list
Profile                  Credentials              Sessions
=======                  ===========              ========
home                     home                     -
```

#### Yubikey

Yubikey is supported, but not required, as a MFA device. Remove any existing MFA device on your account before attempting to add a Yubikey.

```
# Add your Yubikey (with optional require touch)
$ aws-vault add-yubikey <aws username> <profile> --touch
```

Use the QR code output with a virtual MFA app, such as Google Authenticator, to provide a way to get a OTP should your Yubikey be unavailable for any reason. Open Yubico Authenticator to see the added config.

Once added, commands that require a OTP, eg `exec`, will get one from your Yubikey *for any profile that has the same `mfa_serial=arn:aws:iam::123456789012:mfa/jonsmith` as the profile used when adding the Yubikey* (see [assuming-roles](#assuming-roles)).

To login to the aws console you'll need to use Yubico Authenticator (or the app you scanned the QR code with) to generate a OTP as the [AWS SDK doesn't support U2F](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_u2f_supported_configurations.html#id_credentials_mfa_u2f_cliapi) (TOTP is used as a fallback, but that requires a code to be entered for console login).

```
# Remove Yubikey (for all profiles that use the same mfa_serial)
$ aws-vault remove-yubikey <aws username> <profile>
```

## Security
```bash
$ aws-vault exec home -- env | grep AWS
AWS_VAULT=work
AWS_DEFAULT_REGION=us-east-1
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=%%%
AWS_SECRET_ACCESS_KEY=%%%
AWS_SESSION_TOKEN=%%%
AWS_SECURITY_TOKEN=%%%
```

Notice in the above environment how a session token gets written out. This is because `aws-vault` uses Amazon's STS service to generate [temporary credentials](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html) via the `GetSessionToken` or `AssumeRole` API calls. These expire in a short period of time, so the risk of leaking credentials is reduced.

The credentials are exposed to the subprocess in one of two ways:

 * Environment variables are written to the sub-process.

 * Local [EC2 Instance Metadata server](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html) is started. This approach has the advantage that anything that uses Amazon's SDKs will automatically refresh credentials as needed, so session times can be as short as possible. The downside is that only one can run per host and because it binds to `169.254.169.254:80`, your sudo password is required.

The default is to use environment variables, but you can opt-in to the local instance metadata server with the `--server` flag on the `exec` command.


### Assuming Roles

Best-practice is to have a read-only account that you use on a day-to-day basis, and then use [IAM roles to assume temporary admin privileges](http://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html) along with an MFA.

First you'll need to [setup an MFA token in the AWS Console](http://docs.aws.amazon.com/IAM/latest/UserGuide/GenerateMFAConfigAccount.html) (alternatively [use a Yubikey](#yubikey)) and create a role with admin access.

Edit your `~/.aws/config` to add the role_arn and MFA serial number into a new profile:

```ini
[profile read-only]
region=us-east-1

[profile admin]
source_profile = read-only
role_arn = arn:aws:iam::123456789012:role/admin-access
mfa_serial = arn:aws:iam::123456789012:mfa/jonsmith
```

Then when you use the `admin` profile, `aws-vault` will look in the `read-only` profile's keychain for credentials and then use those credentials to assume the `admin` role. This assumed role is stored as a short duration session in your keychain so you will only have to enter MFA once per session.

**Note:** If you have an MFA device attached to your account, the STS service will generate session tokens that are *invalid* unless you provide an MFA code. To enable MFA for a profile, specify the `mfa_serial` in `~/.aws/config`. You can retrieve the MFA's serial (ARN) in the web console, or you can usually derive it pretty easily using the format `arn:aws:iam::[account-id]:mfa/[your-iam-username]`. If you have an account with an MFA associated, but you don't provide the IAM, you are unable to call IAM services, even if you have the correct permissions to do so.

`mfa_serial` will be inherited from the profile designated in `source_profile`, which can be very convenient if you routinely assume multiple roles from the same source because you will only need to provide an MFA token once per source profile session.

In the example below, profiles `admin-a` and `admin-b` do not specify an `mfa_serial`, but because `read-only` specifies an `mfa_serial`, the user will be prompted for a token when either profile is used if the keychain does not contain an active session for `read-only`.

Another benefit of using this configuration strategy is that the user only needs to personalize the configuration of profiles which use access keys. The set of profiles for roles can be copy / pasted from documentation sources.

```ini
[profile read-only]
mfa_serial = arn:aws:iam::123456789012:mfa/jonsmith

[profile admin-a]
source_profile = read-only
role_arn = arn:aws:iam::123456789012:role/admin-access

[profile admin-b]
source_profile = read-only
role_arn = arn:aws:iam::987654321987:role/admin-access
```

You can also define a chain of roles to assume:

```ini
[profile read-only]
mfa_serial = arn:aws:iam::123456789012:mfa/jonsmith

[profile intermediary]
source_profile = read-only
role_arn = arn:aws:iam::123456789012:role/intermediary

[profile target]
source_profile = intermediary
role_arn = arn:aws:iam::123456789012:role/target
```

## macOS Code-signing

The [macOS release builds](https://github.com/99designs/aws-vault/releases) are code-signed to avoid extra prompts in Keychain. You can verify this with:

    $ codesign -dvv $(which aws-vault) 2>&1 | grep Authority
    Authority=Developer ID Application: 99designs Inc (NRM9HVJ62Z)
    Authority=Developer ID Certification Authority
    Authority=Apple Root CA

### Self-signing your binary

If you are developing or compiling the aws-vault binary yourself, you can generate a self-signed code signing certificate.

Check out Apple's guide on it [here](http://web.archive.org/web/20090119080759/http://developer.apple.com/documentation/Security/Conceptual/CodeSigningGuide/Procedures/chapter_3_section_2.html), or find it in `Keychain Access > Certificate Assistant > Create Certificate > Code Signing Certificate`.

You can then sign your binary like this:

```bash
make build
codesign -s "Name of my certificate" ./aws-vault
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
 * https://github.com/kreuzwerker/awsu
