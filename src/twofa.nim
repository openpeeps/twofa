# A simple 2FA library supporting both TOTP (time-based)
# and HOTP (counter-based) One Time Passwords.
#
#     (c) 2026 George Lemon | MIT License
#               Made by Humans from OpenPeeps
#               https://github.com/openpeeps/twofa

## This module ties together OTP generation and QR code output.
##
## Use `initTotp` / `initHotp` from the `otp` module to create OTP instances,
## then call `provisioningUri` to get the `otpauth://` URI, and finally
## `saveQr` or `getQr` to produce a scannable QR code.
##
## Basic usage:
## ```nim
## let totp = initTotp("JBSWY3DPEHPK3PXP", issuer = "MyApp", accountName = "alice@example.com")
## totp.provisioningUri().saveQr("totp.svg")
##
## let hotp = initHotp("JBSWY3DPEHPK3PXP", issuer = "MyApp", accountName = "alice@example.com")
## hotp.provisioningUri(initialCount = 0).saveQr("hotp.svg")
## ```
import std/strutils
import pkg/qr

import ./twofa/[otp, base32]
export otp, base32, qr

type
  AuthURI* = string
    ## An `otpauth://` URI suitable for QR code provisioning.
    ## Produced by `HOTP.provisioningUri` or `TOTP.provisioningUri`.

proc saveQr*(uri: AuthURI, path: string) {.inline.} =
  ## Renders `uri` as an SVG QR code and writes it to `path`.
  qrSvgFile(uri, path)

proc getQr*(uri: AuthURI): string {.inline.} =
  ## Renders `uri` as an SVG QR code and returns the SVG string.
  qrSvg(uri)

when isMainModule:
  # TOTP example — compatible with Google Authenticator
  let totp = initTotp(
    secret      = base32.encode("loremipsum").toUpperAscii(),
    issuer      = "OpenPeeps",
    accountName = "MyLabel"
  )
  totp.provisioningUri().saveQr("test-totp.svg")

  # HOTP example — counter-based
  let hotp = initHotp(
    secret      = base32.encode("loremipsum").toUpperAscii(),
    issuer      = "OpenPeeps",
    accountName = "MyLabel",
    counter     = 1
  )
  hotp.provisioningUri(initialCount = 1).saveQr("test-hotp.svg")

  # Already-Base32 secret — pass directly, no re-encoding needed
  let hotpB32 = initHotp(
    secret      = "JBSWY3DPEHPK3PXP",
    issuer      = "OpenPeeps",
    accountName = "MyLabel",
    counter     = 1
  )
  echo hotpB32.provisioningUri(initialCount = 1).getQr()