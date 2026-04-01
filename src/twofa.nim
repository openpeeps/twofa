# A simple 2FA QR Code generator based on pkg/otp and pkg/qr,
# supporting both TOTP (time-based) and HOTP (counter-based) OTPs.
#
#     (c) 2026 George Lemon | MIT License
#               Made by Humans from OpenPeeps
#               https://github.com/openpeeps/2fa

import std/[strutils]
import pkg/[otp, qr, base32]

export otp, qr

## This module provides functions to generate otpauth URIs for TOTP and HOTP,
## which can be used to create QR codes for 2FA setup in authenticator apps.
## 
## The `genTotpUri` and `genHotpUri` procs generate the appropriate otpauth URI format
## based on the provided secret, label, issuer, and other parameters. The `saveQr`
## procedure takes an otpauth URI and saves a QR code representation of it to a specified file.
## 
## For more details regarding the QR code generation see [pkg/qr](https://github.com/ThomasTJdev/nim_qr) documentation,
## and for OTP generation and verification see [pkg/otp](https://github.com/OpenSystemsLab/otp.nim) documentation.

type
  OtpType* = enum
    ## The type of OTP to generate. Can be either
    ## `hotp` (counter-based) or `totp` (time-based)
    otpHotp = "hotp" # counter based OTP
    otpTotp = "totp" # time based OTP
  
  AuthURI* = string
    ## A URI that can be used to generate a QR
    ## code for 2FA setup in an authenticator app.

const
  otpauthTotp* = "otpauth://$1/$2?secret=$3&period=$4"
    ## The format string for generating a TOTP otpauth URI. It includes
    ## placeholders for the OTP type, label, secret, and interval (period)

  otpauthHotp* = "otpauth://$1/$2?secret=$3&counter=$4"
    ## The format string for generating an HOTP otpauth URI. It includes
    ## placeholders for the OTP type, label, secret, and counter value

proc normalizeOtpSecret(secret: string; isBase32: bool): string =
  ## Returns a URI-safe OTP secret in Base32 (uppercase, no padding).
  ## If `isBase32` is true, the input secret is treated as Base32 and validated,
  ## otherwise it is encoded to Base32. The resulting string is uppercase and has no padding.
  if isBase32:
    result = secret.strip().toUpperAscii().replace("=", "")
    for c in result:
      if not ((c >= 'A' and c <= 'Z') or (c >= '2' and c <= '7')):
        raise newException(ValueError, "Invalid Base32 secret")
  else:
    result = base32.encode(secret).toUpperAscii().replace("=", "")

proc genTotpUri*(secret, label: string, issuer: string = "",
            interval: uint = 30, isBase32 = false): AuthURI = 
  ## Generates a TOTP otpauth URI for a given secret, label, issuer, and interval.
  let otpSecret = normalizeOtpSecret(secret, isBase32)
  result = otpauthTotp % [$(OtpType.otpTotp), label, otpSecret, $interval]
  if issuer.len > 0:
    add result, "&issuer=" & issuer

proc genHotpUri*(secret, label: string, issuer: string = "",
            counter: uint64, isBase32 = false) : AuthURI =
  ## Generates an HOTP otpauth URI for a given secret, label, issuer, and counter value.
  let otpSecret = normalizeOtpSecret(secret, isBase32)
  result = otpauthHotp % [$(OtpType.otpHotp), label, otpSecret, $counter]
  if issuer.len > 0:
    add result, "&issuer=" & issuer

proc saveQr*(authUri: AuthURI, path: string) {.inline.} =
  ## Generates a QR code from the given AuthURI and saves it to the specified path.
  qrSvgFile(authUri, path)

proc getQR*(authUri: AuthURI): string {.inline.} =
  ## Generates a QR code SVG string from the given AuthURI.
  qrSvg(authUri)

when isMainModule:
  genTotpUri(secret = "loremipsum", label = "MyLabel",
    issuer = "OpenPeeps").saveQr("test-totp.svg")
  genHotpUri(secret = "loremipsum",  label = "MyLabel",
    issuer = "OpenPeeps", counter = 1).saveQr("test-hotp.svg")

  echo genHotpUri(secret = "jbswy3dpehpk3pxp==", label = "MyLabel",
    issuer = "OpenPeeps", counter = 1, isBase32 = true).getQR()
