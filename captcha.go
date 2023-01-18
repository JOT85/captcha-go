// package captcha is a package for verifying captcha responses from Cloudflare Turnstile, Google
// reCAPTCHA v2 (checkbox and invisible), reCAPTCHA v3 or any other custom endpoint.
//
// ## Why build another library?
//
// This has been done before, but I had a list of requirements that weren't quite met by one I
// found:
//
// - Supports Cloudflare Turnstile, Google reCAPTCHA v2, reCAPTCHA v3 (and any custom endpoint),
// - Actually checks `Hostname`/`ApkPackageName` and `Action`,
// - Doesn't use a web framework except the standard library,
// - Allows setting a custom `http.Client` for requests,
// - Makes the `cdata` field (from Turnstile) accessible,
// - Makes proper use of errors, with helpful error messages wrapping the underlying error and
//   without writing logs itself to the default logger.
//
// ## Usage
//
// For direct access to the response from the verification server, the `CaptchaVerifier` type can be
// used, constructed with the endpoint and secret. The `Verify` method takes a client response and will
// return a `VerifyResponse` which you can then check yourself.
//
// For more abstract usage, a `SimpleCaptchaVerifier` can be constructed. It contains expected values
// for things like `Hostname` and `Action`, which are checked against responses. This means that the
// `Verify` method returns a `bool`, indicating if the verification succeeded and matched the expected
// values. More details can be found in the API documentation.

package captcha

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Endpoint URL to verify requests, e.g. `GoogleRecaptcha`, `CloudflareTurnstile` or a custom URL.
type Endpoint string

// Google reCAPTCHA endpoint for both v2 (checkbox and invisible) and v3, see
// https://developers.google.com/recaptcha/docs/verify
const GoogleRecaptcha Endpoint = "https://www.google.com/recaptcha/api/siteverify"

// CloudflareTurnstile endpoint, see
// https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
const CloudflareTurnstile Endpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// ErrorNon200StatusCode is an error returned when the endpoint returns a HTTP status code which
// isn't 200.
type ErrorNon200StatusCode struct {
	// StatusCode is the HTTP status code which was returned instead of 200.
	StatusCode int
}

func (err ErrorNon200StatusCode) Error() string {
	return fmt.Sprint("captcha verify endpoint returned non-200 status:", err.StatusCode)
}

// CaptchaVerifier is a client for verifying captchas! It provides direct access to the
// `VerifyResponse` returned by the endpoint, for a more abstract type which returns a boolean, you
// can construct a `SimpleCaptchaVerifier`.
//
// It supports any custom endpoint, including Cloudflare Turnstile, Google reCAPTCHA v2 and
// reCAPTCHA v3.
type CaptchaVerifier struct {
	HttpClient      *http.Client
	captchaEndpoint Endpoint
	captchaSecret   string
}

// NewCaptchaVerifier creates a new `CaptchaVerifier` with `http.DefaultClient`.
func NewCaptchaVerifier(captchaEndpoint Endpoint, captchaSecret string) *CaptchaVerifier {
	return &CaptchaVerifier{
		HttpClient:      http.DefaultClient,
		captchaEndpoint: captchaEndpoint,
		captchaSecret:   captchaSecret,
	}
}

// VerifyRequest is the data sent in a request to the API endpoint.
type VerifyRequest struct {
	// Secret key for the verify API
	Secret string `json:"secret"`

	// Response provided by the client
	Response string `json:"response"`

	// RemoteIP is, optionally, the clients IP address
	RemoteIP string `json:"remoteip"`
}

// Verify sends this request to an `endpoint` and returns the `VerifyResponse`.
//
// Most of the time you probably want to use the `Verify` method on `CaptchaVerifier` or
// `SimpleCaptchaVerifier` instead.
func (req *VerifyRequest) Verify(
	client *http.Client,
	endpoint Endpoint,
) (resp *VerifyResponse, err error) {
	// Format request
	jsonReq, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to format verify request: %w", err)
	}

	// Make the POST request
	httpResp, err := client.Post(
		string(endpoint),
		"application/json", bytes.NewReader(jsonReq),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to perform POST to captcha verify endpoint: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != 200 {
		return nil, ErrorNon200StatusCode{httpResp.StatusCode}
	}

	// Parse response
	resp = &VerifyResponse{}
	err = json.NewDecoder(httpResp.Body).Decode(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse verify response: %w", err)
	}
	return
}

// VerifyResponse is the data returned by the API endpoint.
type VerifyResponse struct {
	// Success will be true iff the validation was successful. This should be returned by all APIs.
	Success bool `json:"success"`

	// Score from reCAPTCHA v3, between 0 and 1.
	//
	// 0 indicates a likely bot and 1 is a likely good interaction. According to Google's docs
	// (https://developers.google.com/recaptcha/docs/v3), you can sensibly use 0.5 as a threshold.
	//
	// This isn't populated by reCAPTCHA v2 or Cloudflare Turnstile.
	Score float32 `json:"score"`

	// ChallengeTime is the time when the challenge was solved (ISO format yyyy-MM-ddTHH:mm:ssZZ).
	//
	// All reCAPTCHA versions and Turnstile return this.
	ChallengeTime string `json:"challenge_ts"`

	// Action name of the validation, set by the client. It's recommended to verify this.
	//
	// Cloudflare Turnstile and reCAPTCHA v3 provide this, reCAPTCHA v2 does not.
	Action string

	// Hostname is the hostname of the site the captcha was solved on (if solving a web captcha).
	//
	// All web reCAPTCHA versions and Turnstile return this.
	Hostname string `json:"hostname"`

	// ApkPackageName is the package name of the app the captcha was solved on (if solved in an
	// android app). Provided by all android reCAPTCHA version.
	ApkPackageName string `json:"apk_package_name"`

	// ErrorCodes is a list of errors that occurred.
	//
	// A list of possible errors can be found at
	// https://developers.cloudflare.com/turnstile/get-started/server-side-validation/#error-codes
	// and https://developers.google.com/recaptcha/docs/verify#error_code_reference
	//
	// In addition, most error codes are provided as documented constant in this package.
	ErrorCodes []string `json:"error-codes"`

	// CData is customer data passed on the client side.
	//
	// Provided by Cloudflare Turnstile but not reCAPTCHA.
	CData string `json:"cdata"`
}

// ParsedChallengeTime returns `resp.ChallengeTime` parsed in the RFC3339 layout.
func (resp *VerifyResponse) ParsedChallengeTime() (time.Time, error) {
	return time.Parse(time.RFC3339, resp.ChallengeTime)
}

// Attempt to verify a captcha response, optionally verifying the client IP. This returns the
// `VerifyResponse`, which you must yourself validate. Use `SimpleCaptchaVerifier` to automatically
// verify this.
//
// Leave `remoteIP` empty to not verify the IP address.
func (client *CaptchaVerifier) Verify(
	clientResponse,
	remoteIP string,
) (resp *VerifyResponse, err error) {
	return (&VerifyRequest{
		Secret:   client.captchaSecret,
		Response: clientResponse,
		RemoteIP: remoteIP,
	}).Verify(client.HttpClient, client.captchaEndpoint)
}

// SimpleCaptchaVerifier wraps a `CaptchaVerifier` with some expected response values. The `Verify`
// method can then be used to check a validation response is successful and matches the expected
// response.
type SimpleCaptchaVerifier struct {
	Verifier CaptchaVerifier

	// MinScore is the minimum allowed `Score` value. If reCAPTCHA v3 isn't being used (i.e. if
	// Cloudflare Turnstile or reCAPTCHA v2 is being used) this should be set to 0. According to
	// Google's docs (https://developers.google.com/recaptcha/docs/v3), you can sensibly use 0.5 as
	// a threshold.
	MinScore float32

	// ExpectedAction is the expected value of the `Action` field. If using reCAPTCHA v2, which
	// doesn't provide this, it should be an empty string.
	//
	// This field can be overridden on a case-by-case basis using the `VerifyAction` method.
	ExpectedAction string

	// ExpectedHostname is the expected value of the `Hostname` field. If using an Android app, this
	// should be an empty string and `ExpectedApkPackageName` should be set.
	ExpectedHostname string

	// ExpectedApkPackageName is the expected value of the `ApkPackageName` field. If using an
	// web app, this should be an empty string and `ExpectedHostname` should be set.
	ExpectedApkPackageName string
}

// Verify a captcha response, optionally verifying the client IP. The response will be validated
// against the expected values set in the `SimpleCaptchaVerifier`. `Success` must also be true, and
// the list of error codes must be empty.
//
// Leave `remoteIP` empty to not verify the IP address.
func (verifier SimpleCaptchaVerifier) Verify(clientResponse, remoteIP string) (bool, error) {
	return verifier.VerifyAction(clientResponse, remoteIP, verifier.ExpectedAction)
}

// VerifyWithResponse is like Verify, but also returns the VerifyResponse.
func (verifier SimpleCaptchaVerifier) VerifyWithResponse(
	clientResponse,
	remoteIP string,
) (*VerifyResponse, bool, error) {
	return verifier.VerifyActionWithResponse(clientResponse, remoteIP, verifier.ExpectedAction)
}

// Verify a captcha response, optionally verifying the client IP, overriding the expected action.
// The response will be validated against the expected values set in the `SimpleCaptchaVerifier`,
// except that `Action` must instead be equal to the passed `expectedAction`. `Success` must also be
// true, and the list of error codes must be empty.
//
// Leave `remoteIP` empty to not verify the IP address.
func (verifier SimpleCaptchaVerifier) VerifyAction(
	clientResponse,
	remoteIP,
	expectedAction string,
) (bool, error) {
	resp, err := verifier.Verifier.Verify(clientResponse, remoteIP)
	if err != nil {
		return false, err
	}
	return resp.Success &&
		len(resp.ErrorCodes) == 0 &&
		resp.Score >= verifier.MinScore &&
		resp.Action == expectedAction &&
		resp.Hostname == verifier.ExpectedHostname &&
		resp.ApkPackageName == verifier.ExpectedApkPackageName, nil
}

// VerifyActionWithResponse is like VerifyAction, but also returns the VerifyResponse.
func (verifier SimpleCaptchaVerifier) VerifyActionWithResponse(
	clientResponse,
	remoteIP,
	expectedAction string,
) (*VerifyResponse, bool, error) {
	resp, err := verifier.Verifier.Verify(clientResponse, remoteIP)
	if err != nil {
		return nil, false, err
	}
	return resp, resp.Success &&
		len(resp.ErrorCodes) == 0 &&
		resp.Score >= verifier.MinScore &&
		resp.Action == expectedAction &&
		resp.Hostname == verifier.ExpectedHostname &&
		resp.ApkPackageName == verifier.ExpectedApkPackageName, nil
}

// ErrorCodeMissingInputSecret is caused when the secret is not passed.
const ErrorCodeMissingInputSecret string = "missing-input-secret"

// ErrorCodeInvalidInputSecret is caused when the secret is invalid.
const ErrorCodeInvalidInputSecret string = "invalid-input-secret"

// ErrorCodeMissingInputResponse is caused when the response is not passed.
const ErrorCodeMissingInputResponse string = "missing-input-response"

// ErrorCodeInvalidInputResponse is caused when the response is not valid.
const ErrorCodeInvalidInputResponse string = "invalid-input-response"

// ErrorCodeBadRequest is caused by a malformed request.
const ErrorCodeBadRequest string = "bad-request"

// ErrorCodeTimeoutOrDuplicate is caused when the response is either too old or has been used
// previously.
const ErrorCodeTimeoutOrDuplicate string = "timeout-or-duplicate"

// ErrorCodeInternalError is caused when an unknown internal error has occurred. The request can be
// retried.
const ErrorCodeInternalError string = "internal-error"
