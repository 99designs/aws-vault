module github.com/99designs/aws-vault

go 1.13

require (
	github.com/99designs/keyring v1.1.4
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20190924025748-f65c72e2690d // indirect
	github.com/aws/aws-sdk-go v1.25.37
	github.com/google/go-cmp v0.3.1
	github.com/keybase/go-keychain v0.0.0-20191220220820-f65a47cbe0b1 // indirect
	github.com/maxbrunsfeld/counterfeiter/v6 v6.2.3
	github.com/mitchellh/go-homedir v1.1.0
	github.com/skratchdot/open-golang v0.0.0-20190402232053-79abb63cd66e
	github.com/smartystreets/goconvey v1.6.4 // indirect
	golang.org/x/crypto v0.0.0-20200210222208-86ce3cb69678
	golang.org/x/sys v0.0.0-20200202164722-d101bd2416d5 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/ini.v1 v1.51.0
)

replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
