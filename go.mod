module github.com/99designs/aws-vault/v6

go 1.16

require (
	github.com/99designs/keyring v1.1.6
	github.com/alecthomas/kingpin v0.0.0-20200323085623-b6657d9477a6
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20210208195552-ff826a37aa15 // indirect
	github.com/aws/aws-sdk-go v1.38.0
	github.com/danieljoos/wincred v1.1.0 // indirect
	github.com/dvsekhvalnov/jose2go v1.5.0 // indirect
	github.com/google/go-cmp v0.5.2
	github.com/keybase/go-keychain v0.0.0-20200502122510-cda31fe0c86d // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mtibben/androiddnsfix v0.0.0-20200907095054-ff0280446354
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966
	github.com/smartystreets/goconvey v1.6.4 // indirect
	golang.org/x/crypto v0.0.0-20210317152858-513c2a44f670
	golang.org/x/sys v0.0.0-20210319071255-635bc2c9138d // indirect
	golang.org/x/term v0.0.0-20210317153231-de623e64d2a6 // indirect
	gopkg.in/ini.v1 v1.62.0
)

replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
