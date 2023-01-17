# captcha-go

[![Go Report Card](https://goreportcard.com/badge/github.com/JOT85/captcha-go)](https://goreportcard.com/report/github.com/JOT85/captcha-go)
[![GoDoc](https://pkg.go.dev/badge/github.com/JOT85/captcha-go)](https://pkg.go.dev/github.com/JOT85/captcha-go)

A Go module for verifying captcha responses from
[Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/),
[Google reCAPTCHA v2](https://developers.google.com/recaptcha/docs/verify)
([checkbox](https://developers.google.com/recaptcha/docs/display) and
[invisible](https://developers.google.com/recaptcha/docs/invisible)),
[reCAPTCHA v3](https://developers.google.com/recaptcha/docs/v3) or any other custom endpoint.

## Why build another library?

This has been done before, but I had a list of requirements that weren't quite met by one I found:

- Supports Cloudflare Turnstile, Google reCAPTCHA v2, reCAPTCHA v3 (and any custom endpoint),
- Actually checks `Hostname`/`ApkPackageName` and `Action`,
- Doesn't use a web framework except the standard library,
- Allows setting a custom `http.Client` for requests,
- Makes the `cdata` field (from Turnstile) accessible,
- Makes proper use of errors, with helpful error messages wrapping the underlying error and without
  writing logs itself to the default logger.

## Usage

For direct access to the response from the verification server, the
[`CaptchaVerifier`](https://pkg.go.dev/github.com/JOT85/captcha-go#CaptchaVerifier) type can be
used, constructed with the endpoint and secret. The
[`Verify`](https://pkg.go.dev/github.com/JOT85/captcha-go#CaptchaVerifier.Verify) method takes a
client response and will return a `VerifyResponse` which you can then check yourself.

For more abstract usage, a
[`SimpleCaptchaVerifier`](https://pkg.go.dev/github.com/JOT85/captcha-go#SimpleCaptchaVerifier) can
be constructed. It contains expected values for things like `Hostname` and `Action`, which are
checked against responses. This means that the
[`Verify`](https://pkg.go.dev/github.com/JOT85/captcha-go#SimpleCaptchaVerifier.Verify) method
returns a `bool`, indicating if the verification succeeded and matched the expected values. More
details can be found in the API documentation.
