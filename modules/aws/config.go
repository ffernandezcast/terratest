package aws

//Reference for mocking purposes https://github.com/aws/aws-sdk-go/blob/master/aws/config.go

import (
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
)

type RequestRetryer interface{}

type Config struct {
	CredentialsChainVerboseErrors *bool

	Credentials *credentials.Credentials

	Endpoint *string

	EndpointResolver endpoints.Resolver

	EnforceShouldRetryCheck *bool

	Region *string

	DisableSSL *bool

	HTTPClient *http.Client

	MaxRetries *int

	Retryer RequestRetryer

	DisableParamValidation *bool

	DisableComputeChecksums *bool

	S3ForcePathStyle *bool

	S3Disable100Continue *bool

	S3UseAccelerate *bool

	S3DisableContentMD5Validation *bool

	S3UseARNRegion *bool

	EC2MetadataDisableTimeoutOverride *bool

	UseDualStack *bool

	SleepDelay func(time.Duration)

	DisableRestProtocolURICleaning *bool

	EnableEndpointDiscovery *bool

	DisableEndpointHostPrefix *bool

	STSRegionalEndpoint endpoints.STSRegionalEndpoint

	S3UsEast1RegionalEndpoint endpoints.S3UsEast1RegionalEndpoint
}

var once sync.Once

var defaultConfig *Config

func NewCustomConfig(c *Config) *Config {
	once.Do(func() {
		defaultConfig = c
	})

	return defaultConfig
}

func GetCustomConfig() *Config {
	return defaultConfig
}
