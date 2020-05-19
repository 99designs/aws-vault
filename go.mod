module github.com/99designs/aws-vault/v6

go 1.14

require (
	github.com/99designs/keyring v1.1.5
	github.com/alecthomas/kingpin v0.0.0-20200323085623-b6657d9477a6
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20190924025748-f65c72e2690d // indirect
	github.com/aws/aws-sdk-go v1.31.0
	github.com/danieljoos/wincred v1.1.0 // indirect
	github.com/google/go-cmp v0.4.1
	github.com/keybase/go-keychain v0.0.0-20200502122510-cda31fe0c86d // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966
	github.com/smartystreets/goconvey v1.6.4 // indirect
	golang.org/x/crypto v0.0.0-20200510223506-06a226fb4e37
	golang.org/x/sys v0.0.0-20200515095857-1151b9dac4a9 // indirect
	gopkg.in/ini.v1 v1.56.0
)

replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
