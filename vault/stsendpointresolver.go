package vault

import (
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// getEndpointResolver resolves endpoints in accordance with
// https://docs.aws.amazon.com/credref/latest/refdocs/setting-global-sts_regional_endpoints.html
func getSTSEndpointResolver(stsRegionalEndpoints string) aws.EndpointResolverWithOptionsFunc {
	return func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if stsRegionalEndpoints == "legacy" && service == sts.ServiceID {
			if region == "ap-northeast-1" ||
				region == "ap-south-1" ||
				region == "ap-southeast-1" ||
				region == "ap-southeast-2" ||
				region == "aws-global" ||
				region == "ca-central-1" ||
				region == "eu-central-1" ||
				region == "eu-north-1" ||
				region == "eu-west-1" ||
				region == "eu-west-2" ||
				region == "eu-west-3" ||
				region == "sa-east-1" ||
				region == "us-east-1" ||
				region == "us-east-2" ||
				region == "us-west-1" ||
				region == "us-west-2" {
				log.Println("Using legacy STS endpoint sts.amazonaws.com")

				return aws.Endpoint{
					URL:           "https://sts.amazonaws.com",
					SigningRegion: region,
				}, nil
			}
		}

		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	}
}
