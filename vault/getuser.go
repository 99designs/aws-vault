package vault

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

var getUserErrorRegexp = regexp.MustCompile(`^AccessDenied: User: arn:aws:iam::(\d+):user/(.+) is not`)

// GetUsernameFromSession returns the IAM username (or root) associated with the current aws session
func GetUsernameFromSession(sess *session.Session) (string, error) {
	resp, err := iam.New(sess).GetUser(&iam.GetUserInput{})
	if err != nil {
		// Even if GetUser fails, the current user is included in the error. This happens when you have o IAM permissions
		// on the master credentials, but have permission to use assumeRole later
		matches := getUserErrorRegexp.FindStringSubmatch(err.Error())
		if len(matches) > 0 {
			pathParts := strings.Split(matches[2], "/")
			return pathParts[len(pathParts)-1], nil
		}

		return "", err
	}

	if resp.User.UserName != nil {
		return *resp.User.UserName, nil
	}

	if resp.User.Arn != nil {
		arnParts := strings.Split(*resp.User.Arn, ":")
		return arnParts[len(arnParts)-1], nil
	}

	return "", fmt.Errorf("Couldn't determine current username")
}
