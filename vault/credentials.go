package vault

import "github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/aws/aws-sdk-go/service/sts"

type Credentials struct {
	AccessKeyId string
	SecretKey   string
}

func (c Credentials) Environ() []string {
	return []string{
		"AWS_ACCESS_KEY_ID=" + c.AccessKeyId,
		"AWS_SECRET_ACCESS_KEY=" + c.SecretKey,
	}
}

type SessionCredentials struct {
	*sts.Credentials
}

func (sc SessionCredentials) Environ() []string {
	if sc.Credentials == nil {
		return []string{}
	}
	return []string{
		"AWS_ACCESS_KEY_ID=" + *sc.Credentials.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + *sc.Credentials.SecretAccessKey,
		"AWS_SESSION_TOKEN=" + *sc.Credentials.SessionToken,
	}
}
