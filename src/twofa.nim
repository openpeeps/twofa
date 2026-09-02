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
import std/[strutils, uri, syncio]
import openparser/qr

import ./twofa/[otp, base32]
export otp, base32, qr

type
  AuthURI* = string
    ## An `otpauth://` URI suitable for QR code provisioning.
    ## Produced by `HOTP.provisioningUri` or `TOTP.provisioningUri`.

proc saveQr*(
    uri: AuthURI,
    path: string,
    scale = 8,
    border = 4,
    dark = "#000000",
    light = "#ffffff",
    options = defaultQrEncodeOptions()
) {.inline.} =
  ## Renders `uri` as an SVG QR code and writes it to `path`.
  ## Optional rendering settings mirror `openparser/qr` `toSvg`:
  ## `scale` is the pixel size per module, `border` the quiet zone in modules,
  ## `dark`/`light` the module colors, and `options` the QR encode options
  ## (EC level, version bounds, mask, etc.).
  let m = encodeQr(uri, options)
  writeFile(path, m.toSvg(scale, border, dark, light))

proc getQr*(
    uri: AuthURI,
    scale = 8,
    border = 4,
    dark = "#000000",
    light = "#ffffff",
    options = defaultQrEncodeOptions()
): string {.inline.} =
  ## Renders `uri` as an SVG QR code and returns the SVG string.
  ## See `saveQr` for optional rendering/encoding settings.
  let m = encodeQr(uri, options)
  result = m.toSvg(scale, border, dark, light)

proc saveMatrix*(
    m: QrMatrix,
    path: string,
    scale = 8,
    border = 4,
    dark = "#000000",
    light = "#ffffff"
) {.inline.} =
  ## Renders an already-encoded `QrMatrix` as SVG and writes it to `path`.
  ## Useful when you have built the matrix via `encodeQr`, `encodeQrBytes`,
  ## or any other `openparser/qr` encoder and want direct SVG output
  ## without re-encoding the URI.
  writeFile(path, m.toSvg(scale, border, dark, light))

proc genTotpUri*(
    secret: string,
    label: string,
    issuer = "",
    interval = defaultInterval,
    digits: OTPDigits = defaultDigits,
    algorithm: OTPAlgorithm = algSHA1
): string =
  ## Convenience helper that builds an `otpauth://totp/` URI without
  ## requiring a `TOTP` instance.
  let encLabel = encodeUrl(label)
  let encIssuer = encodeUrl(issuer)
  let algo =
    case algorithm
    of algSHA1: "SHA1"
    of algSHA512: "SHA512"
  result = "otpauth://totp/" & encLabel &
           "?secret=" & secret &
           "&period=" & $interval &
           "&digits=" & $digits &
           "&algorithm=" & algo
  if issuer.len > 0:
    result &= "&issuer=" & encIssuer

proc genHotpUri*(
    secret: string,
    label: string,
    issuer = "",
    counter = 0,
    digits: OTPDigits = defaultDigits,
    algorithm: OTPAlgorithm = algSHA1
): string =
  ## Convenience helper that builds an `otpauth://hotp/` URI without
  ## requiring an `HOTP` instance.
  let encLabel = encodeUrl(label)
  let encIssuer = encodeUrl(issuer)
  let algo =
    case algorithm
    of algSHA1: "SHA1"
    of algSHA512: "SHA512"
  result = "otpauth://hotp/" & encLabel &
           "?secret=" & secret &
           "&counter=" & $counter &
           "&digits=" & $digits &
           "&algorithm=" & algo
  if issuer.len > 0:
    result &= "&issuer=" & encIssuer

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