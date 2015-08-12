package sts

import "github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/aws/aws-sdk-go/aws"

func init() {
	initRequest = func(r *aws.Request) {
		switch r.Operation.Name {
		case opAssumeRoleWithSAML, opAssumeRoleWithWebIdentity:
			r.Handlers.Sign.Clear() // these operations are unsigned
		}
	}
}
