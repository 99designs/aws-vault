package vault

const ServiceName = "aws-vault"

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
