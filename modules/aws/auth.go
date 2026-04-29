package aws

import (
	"context"
	"fmt"
	"os"
	"time"

	v2aws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	v2credentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/pquerna/otp/totp"
)

const (
	// AuthAssumeRoleEnvVar is the OS environment variable name through which an
	// Assume Role ARN may be passed for authentication.
	AuthAssumeRoleEnvVar = "TERRATEST_IAM_ROLE"
)

// NewAuthenticatedSessionContext creates an AWS Config following to standard AWS authentication workflow.
// If AuthAssumeIamRoleEnvVar environment variable is set, assumes IAM role specified in it.
// The ctx parameter supports cancellation and timeouts.
func NewAuthenticatedSessionContext(ctx context.Context, region string) (*v2aws.Config, error) {
	if assumeRoleArn, ok := os.LookupEnv(AuthAssumeRoleEnvVar); ok {
		return NewAuthenticatedSessionFromRoleContext(ctx, region, assumeRoleArn)
	}

	return NewAuthenticatedSessionFromDefaultCredentialsContext(ctx, region)
}

// NewAuthenticatedSession creates an AWS Config following to standard AWS authentication workflow.
// If AuthAssumeIamRoleEnvVar environment variable is set, assumes IAM role specified in it.
//
// Deprecated: Use [NewAuthenticatedSessionContext] instead.
func NewAuthenticatedSession(region string) (*v2aws.Config, error) {
	return NewAuthenticatedSessionContext(context.Background(), region)
}

// NewAuthenticatedSessionFromDefaultCredentialsContext gets an AWS Config, checking that the user has credentials properly configured in their environment.
// The ctx parameter supports cancellation and timeouts.
func NewAuthenticatedSessionFromDefaultCredentialsContext(ctx context.Context, region string) (*v2aws.Config, error) {
	// If a custom config is set (e.g. localstack), honor it by building a v2 aws.Config from it.
	if customConfig := GetCustomConfig(); customConfig != nil {
		cfg := getAwsConfigFromCustomConfig(customConfig, region)
		return &cfg, nil
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, CredentialsError{UnderlyingErr: err}
	}

	return &cfg, nil
}

// NewAuthenticatedSessionFromDefaultCredentials gets an AWS Config, checking that the user has credentials properly configured in their environment.
//
// Deprecated: Use [NewAuthenticatedSessionFromDefaultCredentialsContext] instead.
func NewAuthenticatedSessionFromDefaultCredentials(region string) (*v2aws.Config, error) {
	return NewAuthenticatedSessionFromDefaultCredentialsContext(context.Background(), region)
}

// NewAuthenticatedSessionFromRoleContext returns a new AWS Config after assuming the
// role whose ARN is provided in roleARN. If the credentials are not properly
// configured in the underlying environment, an error is returned.
// The ctx parameter supports cancellation and timeouts.
func NewAuthenticatedSessionFromRoleContext(ctx context.Context, region string, roleARN string) (*v2aws.Config, error) {
	cfg, err := NewAuthenticatedSessionFromDefaultCredentialsContext(ctx, region)
	if err != nil {
		return nil, err
	}

	client := sts.NewFromConfig(*cfg)

	roleProvider := stscreds.NewAssumeRoleProvider(client, roleARN)

	retrieve, err := roleProvider.Retrieve(ctx)
	if err != nil {
		return nil, CredentialsError{UnderlyingErr: err}
	}

	// Build a new config that uses the assumed role credentials.
	return &v2aws.Config{
		Region: region,
		Credentials: v2aws.NewCredentialsCache(v2credentials.StaticCredentialsProvider{Value: v2aws.Credentials{
			AccessKeyID:     retrieve.AccessKeyID,
			SecretAccessKey: retrieve.SecretAccessKey,
			SessionToken:    retrieve.SessionToken,
		}}),
	}, nil
}

// NewAuthenticatedSessionFromRole returns a new AWS Config after assuming the
// role whose ARN is provided in roleARN. If the credentials are not properly
// configured in the underlying environment, an error is returned.
//
// Deprecated: Use [NewAuthenticatedSessionFromRoleContext] instead.
func NewAuthenticatedSessionFromRole(region string, roleARN string) (*v2aws.Config, error) {
	return NewAuthenticatedSessionFromRoleContext(context.Background(), region, roleARN)
}

// CreateAwsSessionWithCredsContext creates a new AWS Config using explicit credentials. This is useful if you want to create an IAM User dynamically and
// create an AWS Config authenticated as the new IAM User.
// The ctx parameter is accepted for API consistency but not currently used.
func CreateAwsSessionWithCredsContext(ctx context.Context, region string, accessKeyID string, secretAccessKey string) (*v2aws.Config, error) {
	return &v2aws.Config{
		Region:      region,
		Credentials: v2aws.NewCredentialsCache(v2credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")),
	}, nil
}

// CreateAwsSessionWithCreds creates a new AWS Config using explicit credentials. This is useful if you want to create an IAM User dynamically and
// create an AWS Config authenticated as the new IAM User.
//
// Deprecated: Use [CreateAwsSessionWithCredsContext] instead.
func CreateAwsSessionWithCreds(region string, accessKeyID string, secretAccessKey string) (*v2aws.Config, error) {
	return CreateAwsSessionWithCredsContext(context.Background(), region, accessKeyID, secretAccessKey)
}

// CreateAwsSessionWithMfaContext creates a new AWS Config authenticated using an MFA token retrieved using the given STS client and MFA Device.
// The ctx parameter supports cancellation and timeouts.
func CreateAwsSessionWithMfaContext(ctx context.Context, region string, stsClient *sts.Client, mfaDevice *types.VirtualMFADevice) (*v2aws.Config, error) {
	tokenCode, err := GetTimeBasedOneTimePassword(mfaDevice)
	if err != nil {
		return nil, err
	}

	output, err := stsClient.GetSessionToken(ctx, &sts.GetSessionTokenInput{
		SerialNumber: mfaDevice.SerialNumber,
		TokenCode:    v2aws.String(tokenCode),
	})
	if err != nil {
		return nil, err
	}

	accessKeyID := *output.Credentials.AccessKeyId
	secretAccessKey := *output.Credentials.SecretAccessKey
	sessionToken := *output.Credentials.SessionToken

	return &v2aws.Config{
		Region:      region,
		Credentials: v2aws.NewCredentialsCache(v2credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken)),
	}, nil
}

// CreateAwsSessionWithMfa creates a new AWS Config authenticated using an MFA token retrieved using the given STS client and MFA Device.
//
// Deprecated: Use [CreateAwsSessionWithMfaContext] instead.
func CreateAwsSessionWithMfa(region string, stsClient *sts.Client, mfaDevice *types.VirtualMFADevice) (*v2aws.Config, error) {
	return CreateAwsSessionWithMfaContext(context.Background(), region, stsClient, mfaDevice)
}

// GetTimeBasedOneTimePassword gets a One-Time Password from the given mfaDevice. Per the RFC 6238 standard, this value will be different every 30 seconds.
func GetTimeBasedOneTimePassword(mfaDevice *types.VirtualMFADevice) (string, error) {
	base32StringSeed := string(mfaDevice.Base32StringSeed)

	otp, err := totp.GenerateCode(base32StringSeed, time.Now())
	if err != nil {
		return "", err
	}

	return otp, nil
}

// ReadPasswordPolicyMinPasswordLengthContext returns the minimal password length.
// The ctx parameter supports cancellation and timeouts.
func ReadPasswordPolicyMinPasswordLengthContext(ctx context.Context, iamClient *iam.Client) (int, error) {
	output, err := iamClient.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		return -1, err
	}

	return int(*output.PasswordPolicy.MinimumPasswordLength), nil
}

// ReadPasswordPolicyMinPasswordLength returns the minimal password length.
//
// Deprecated: Use [ReadPasswordPolicyMinPasswordLengthContext] instead.
func ReadPasswordPolicyMinPasswordLength(iamClient *iam.Client) (int, error) {
	return ReadPasswordPolicyMinPasswordLengthContext(context.Background(), iamClient)
}

// CredentialsError is an error that occurs because AWS credentials can't be found.
type CredentialsError struct {
	UnderlyingErr error
}

func (err CredentialsError) Error() string {
	return fmt.Sprintf("Error finding AWS credentials. Did you set the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables or configure an AWS profile? Underlying error: %v", err.UnderlyingErr)
}

// getAwsConfigFromCustomConfig maps the legacy custom Config (from v1-style helpers)
// into an aws-sdk-go-v2 Config. We intentionally map only safe/portable fields.
func getAwsConfigFromCustomConfig(customConfig *Config, region string) v2aws.Config {
	// Prefer explicit region from custom config when present.
	finalRegion := region
	if customConfig.Region != nil {
		finalRegion = *customConfig.Region
	}

	cfg := v2aws.Config{Region: finalRegion}

	// HTTP client
	if customConfig.HTTPClient != nil {
		cfg.HTTPClient = customConfig.HTTPClient
	}

	// Credentials (v1 -> v2): attempt to extract static credentials if provided.
	if customConfig.Credentials != nil {
		if val, err := customConfig.Credentials.Get(); err == nil {
			provider := v2credentials.NewStaticCredentialsProvider(val.AccessKeyID, val.SecretAccessKey, val.SessionToken)
			cfg.Credentials = v2aws.NewCredentialsCache(provider)
		}
	}

	// If an explicit endpoint is provided, create a trivial EndpointResolver that returns it.
	if customConfig.Endpoint != nil {
		endpointURL := *customConfig.Endpoint
		cfg.EndpointResolver = v2aws.EndpointResolverFunc(func(service, region string) (v2aws.Endpoint, error) {
			return v2aws.Endpoint{URL: endpointURL, HostnameImmutable: true}, nil
		})
	}

	return cfg
}
