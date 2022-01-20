module github.com/99designs/aws-vault/v6

go 1.17

require (
	github.com/99designs/keyring v1.1.6
	github.com/alecthomas/kingpin v0.0.0-20200323085623-b6657d9477a6
	github.com/aws/aws-sdk-go-v2 v1.13.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.16.0
	github.com/aws/aws-sdk-go-v2/service/sso v1.9.0
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.10.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.14.0
	github.com/google/go-cmp v0.5.7
	github.com/mitchellh/go-homedir v1.1.0
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966
	golang.org/x/crypto v0.0.0-20220112180741-5e0467b6c7ce
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	gopkg.in/ini.v1 v1.66.2
)

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.2.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.7.0 // indirect
	github.com/aws/smithy-go v1.10.0 // indirect
	github.com/danieljoos/wincred v1.1.2 // indirect
	github.com/dvsekhvalnov/jose2go v1.5.0 // indirect
	github.com/godbus/dbus v0.0.0-20190726142602-4481cbc300e2 // indirect
	github.com/gsterjov/go-libsecret v0.0.0-20161001094733-a6f4afe4910c // indirect
	github.com/keybase/go-keychain v0.0.0-20211119201326-e02f34051621 // indirect
	github.com/mtibben/percent v0.2.1 // indirect
)

replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
