module github.com/99designs/aws-vault/v6

go 1.14

require (
	github.com/99designs/keyring v1.1.5
	github.com/aws/aws-sdk-go v1.25.37
	github.com/google/go-cmp v0.3.1
	github.com/keybase/go-keychain v0.0.0-20200325143049-65d7292bc904 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/skratchdot/open-golang v0.0.0-20190402232053-79abb63cd66e
	github.com/smartystreets/goconvey v1.6.4 // indirect
	golang.org/x/crypto v0.0.0-20200423211502-4bdfaf469ed5
	golang.org/x/sys v0.0.0-20200420163511-1957bb5e6d1f // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/ini.v1 v1.55.0
)

replace (
	github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
	gopkg.in/alecthomas/kingpin.v2 v2.2.6 => github.com/alecthomas/kingpin v0.0.0-20200323085623-b6657d9477a6
)
