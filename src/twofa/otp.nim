# A simple 2FA library supporting both TOTP (time-based)
# and HOTP (counter-based) One Time Passwords.
#
#     (c) 2026 George Lemon | MIT License
#               Made by Humans from OpenPeeps
#               https://github.com/openpeeps/twofa

## One Time Password (OTP) implementation following RFC 4226 (HOTP)
## and RFC 6238 (TOTP) specifications.
##
## Supported HMAC algorithms:
##   - `algSHA1`   — RFC 4226 standard, computed via `openssl` CLI
##   - `algSHA512` — Stronger alternative, computed via Monocypher
##
## Basic usage:
## ```nim
## # TOTP with SHA1 (compatible with Google Authenticator)
## let totp = initTotp("JBSWY3DPEHPK3PXP", issuer = "MyApp", accountName = "user@example.com")
## echo totp.now()
##
## # TOTP with SHA512
## let totp512 = initTotp("JBSWY3DPEHPK3PXP", algorithm = algSHA512)
## echo totp512.now()
##
## # HOTP (counter-based)
## let hotp = initHotp("JBSWY3DPEHPK3PXP", issuer = "MyApp", accountName = "user@example.com")
## echo hotp.at(0)
## ```

import std/[math, times, uri, osproc, strutils]

import ./base32
export base32

const
  secretSize* {.intDefine: "otp.secretSize".} = 128
    ## Maximum allowed secret length. Override at compile time
    ## with `-d:otp.secretSize=256`

  defaultDigits* = 6
    ## Standard OTP length per RFC 4226

  defaultInterval* = 30
    ## Default TOTP time step in seconds per RFC 6238

  defaultWindow* = 1
    ## Default verification window — number of time steps checked
    ## before and after the current one to tolerate clock drift

  hmacSha512OutputSize = 64
    ## HMAC-SHA512 output is always 64 bytes

  hmacSha1OutputSize = 20
    ## HMAC-SHA1 output is always 20 bytes

type
  OTPError* = object of CatchableError
    ## Raised for recoverable OTP errors (e.g. invalid secret length,
    ## openssl not found, unexpected openssl output)

  OTPDefect* = object of Defect
    ## Raised for unrecoverable OTP programming errors

  OTPDigits* = range[6..8]
    ## Valid OTP code lengths: 6, 7, or 8 digits per RFC 4226

  OTPAlgorithm* = enum
    ## Selects the HMAC hashing algorithm.
    ##
    ## `algSHA1`   — RFC 4226 standard; required for compatibility with
    ##               Google Authenticator and most TOTP apps.
    ##               Computed via the system `openssl` CLI.
    ##
    ## `algSHA512` — Stronger alternative per RFC 6238 §1.2.
    ##               Computed via Monocypher (no extra dependency).
    algSHA1
    algSHA512

  OneTimePassword {.pure.} = object of RootObj
    ## Base OTP object — not instantiated directly.
    ## Holds shared fields for both HOTP and TOTP.
    secret*:      string        ## Base32-encoded shared secret
    digits*:      OTPDigits     ## Number of digits in the generated code
    algorithm*:   OTPAlgorithm  ## HMAC algorithm to use
    issuer*:      string        ## Optional issuer name (shown in authenticator apps)
    accountName*: string        ## Account/user identifier

  HOTP* = object of OneTimePassword
    ## HMAC-based One Time Password (RFC 4226).
    ## Counter-based: each call to `at` uses a counter value.
    counter*: int               ## Current counter value

  TOTP* = object of OneTimePassword
    ## Time-based One Time Password (RFC 6238).
    ## Generates codes based on the current Unix timestamp.
    interval*: int              ## Time step in seconds (default: 30)

const
  copyHookMsg  = "Copying an OTP object is forbidden for security reasons — " &
                 "this prevents the secret from lingering in memory."
  secretSizeMsg = "Secret exceeds maximum allowed length (" & $secretSize & " chars). " &
                  "Use `-d:otp.secretSize=N` to increase the limit."

# Prevent accidental copies of OTP objects to avoid
# leaving secrets in memory longer than necessary.
when NimMajor >= 2:
  proc `=dup`(_: HOTP): HOTP {.error: copyHookMsg.}
  proc `=dup`(_: TOTP): TOTP {.error: copyHookMsg.}

proc `=copy`(a: var HOTP, b: HOTP) {.error: copyHookMsg.}
proc `=copy`(a: var TOTP, b: TOTP) {.error: copyHookMsg.}

#
# Internal helpers
#

proc validateSecret(secret: openArray[char]) {.inline.} =
  ## Raises `OTPError` if the secret exceeds `secretSize`.
  if secret.len > secretSize:
    raise (ref OTPError)(msg: secretSizeMsg)

proc copySecret(secret: openArray[char]): string {.inline.} =
  ## Copies `secret` char-by-char into a fresh string to avoid
  ## triggering the `=copy` hook on the enclosing OTP object.
  result = newString(secret.len)
  for i in 0 ..< secret.len:
    result[i] = secret[i]

proc intToBytestring(value: int, padding: int = 8): string {.inline.} =
  ## Encodes `value` as a big-endian byte string of exactly `padding` bytes.
  ## This is the counter/timecode representation required by RFC 4226 §5.3.
  var v = value
  var bytes: seq[char]
  while v != 0:
    bytes.add char(v and 0xFF)
    v = v shr 8
  while bytes.len < padding:
    bytes.add '\0'
  result = newString(bytes.len)
  for i in 0 ..< bytes.len:
    result[i] = bytes[bytes.len - i - 1]

proc toHexString(s: string): string {.inline.} =
  ## Converts a raw binary string to its lowercase hex representation.
  ## Used to pass the HMAC message to openssl as hex input.
  const hexChars = "0123456789abcdef"
  result = newString(s.len * 2)
  for i, c in s:
    result[i * 2]     = hexChars[(ord(c) shr 4) and 0xF]
    result[i * 2 + 1] = hexChars[ord(c) and 0xF]

proc parseHexNibble(c: char): uint8 {.inline.} =
  ## Parses a single hex character to its 4-bit value.
  case c
  of '0'..'9': result = uint8(ord(c) - ord('0'))
  of 'a'..'f': result = uint8(ord(c) - ord('a') + 10)
  of 'A'..'F': result = uint8(ord(c) - ord('A') + 10)
  else: raise (ref OTPError)(msg: "Unexpected hex character from openssl: '" & $c & "'")

proc parseHexBytes(hex: string): seq[uint8] {.inline.} =
  ## Converts a hex string (e.g. openssl output) to raw bytes.
  if hex.len mod 2 != 0:
    raise (ref OTPError)(msg: "Odd-length hex string from openssl: " & hex)
  result = newSeq[uint8](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = (parseHexNibble(hex[i * 2]) shl 4) or parseHexNibble(hex[i * 2 + 1])

#
# HMAC backends
#

proc hmacSha1(key: string, message: string): array[hmacSha1OutputSize, uint8] =
  ## Computes HMAC-SHA1 by shelling out to the system `openssl` CLI.
  ##
  ## Command used:
  ##   echo -n <msg_hex> | openssl dgst -sha1 -mac HMAC -macopt hexkey:<key_hex>
  ##
  ## Both key and message are passed as hex strings to avoid shell
  ## escaping issues with arbitrary binary data.
  ##
  ## Raises `OTPError` if openssl is not found or returns unexpected output.
  let keyHex = toHexString(key)
  let msgHex = toHexString(message)

  # pipe hex message through openssl; -mac HMAC with hexkey avoids
  # any shell quoting issues with raw binary data
  let cmd = "printf '%s' '" & msgHex & "' | xxd -r -p | " &
            "openssl dgst -sha1 -mac HMAC -macopt hexkey:" & keyHex

  let (output, exitCode) = execCmdEx(cmd)
  if exitCode != 0:
    raise (ref OTPError)(msg: "openssl HMAC-SHA1 failed (exit " & $exitCode & "): " & output.strip())

  # openssl output format: "HMAC-SHA1(stdin)= <hexdigest>\n"
  # or just "<hexdigest>\n" depending on version — find the last token
  let parts = output.strip().splitWhitespace()
  if parts.len == 0:
    raise (ref OTPError)(msg: "Empty output from openssl")

  let hexDigest = parts[^1]  ## last whitespace-separated token is always the digest
  if hexDigest.len != hmacSha1OutputSize * 2:
    raise (ref OTPError)(
      msg: "Unexpected HMAC-SHA1 digest length from openssl: got " &
           $hexDigest.len & " hex chars, expected " & $(hmacSha1OutputSize * 2))

  let raw = parseHexBytes(hexDigest)
  for i in 0 ..< hmacSha1OutputSize:
    result[i] = raw[i]

proc hmacSha512(key: string, message: string): array[hmacSha512OutputSize, uint8] =
  ## Computes HMAC-SHA512 by shelling out to the system `openssl` CLI.
  ## Both key and message are passed as hex strings to avoid shell
  ## escaping issues with arbitrary binary data.
  let keyHex = toHexString(key)
  let msgHex = toHexString(message)

  let cmd = "printf '%s' '" & msgHex & "' | xxd -r -p | " &
            "openssl dgst -sha512 -mac HMAC -macopt hexkey:" & keyHex

  let (output, exitCode) = execCmdEx(cmd)
  if exitCode != 0:
    raise (ref OTPError)(msg: "openssl HMAC-SHA512 failed (exit " & $exitCode & "): " & output.strip())

  # openssl output format: "HMAC-SHA512(stdin)= <hexdigest>\n" or "<hexdigest>\n"
  let parts = output.strip().splitWhitespace()
  if parts.len == 0:
    raise (ref OTPError)(msg: "Empty output from openssl")

  let hexDigest = parts[^1]
  if hexDigest.len != hmacSha512OutputSize * 2:
    raise (ref OTPError)(
      msg: "Unexpected HMAC-SHA512 digest length from openssl: got " &
           $hexDigest.len & " hex chars, expected " & $(hmacSha512OutputSize * 2))

  let raw = parseHexBytes(hexDigest)
  for i in 0 ..< hmacSha512OutputSize:
    result[i] = raw[i]

#
# Truncation & code generation
#

proc truncate(hmacHash: openArray[uint8], digits: OTPDigits): int {.inline.} =
  ## Applies RFC 4226 §5.3 dynamic truncation to the HMAC output,
  ## then reduces the result to `digits` decimal digits.
  ##
  ## The offset is taken from the low nibble of the last byte,
  ## which works correctly for any HMAC output >= 20 bytes.
  let offset = int(hmacHash[hmacHash.len - 1] and 0x0F)
  if offset + 3 >= hmacHash.len:
    raise (ref OTPDefect)(msg: "HMAC truncation offset out of range — output too short")
  let code =
    (int(hmacHash[offset])     and 0x7F) shl 24 or
    (int(hmacHash[offset + 1]) and 0xFF) shl 16 or
    (int(hmacHash[offset + 2]) and 0xFF) shl 8  or
    (int(hmacHash[offset + 3]) and 0xFF)
  result = code mod int(pow(10.0, float(digits)))

proc generateCode*(secret: string, input: int, digits: OTPDigits, algorithm: OTPAlgorithm): int {.inline.} =
  ## Decodes the Base32 secret, computes HMAC over the counter/timecode
  ## message using the selected algorithm, then truncates to `digits`.
  let key = base32.decode(secret)   ## raw key bytes (decoded from Base32)
  let msg = intToBytestring(input)  ## big-endian counter/timecode
  case algorithm
  of algSHA1:
    let hmac = hmacSha1(key, msg)
    result = truncate(hmac, digits)
  of algSHA512:
    let hmac = hmacSha512(key, msg)
    result = truncate(hmac, digits)

proc timecode*(interval: int, timestamp: int): int {.inline.} =
  ## Returns the TOTP time step index for the given Unix `timestamp`.
  result = timestamp div interval

#
# Constructors
#

proc initHotp*(
    secret:      openArray[char],
    digits:      OTPDigits     = defaultDigits,
    algorithm:   OTPAlgorithm  = algSHA1,
    issuer:      string        = "",
    accountName: string        = "",
    counter:     int           = 0
): HOTP =
  ## Creates an HOTP instance with a **runtime** secret.
  ## Raises `OTPError` if the secret exceeds `secretSize`.
  ##
  ## `secret`      — Base32-encoded shared secret
  ## `digits`      — Code length: 6, 7, or 8 (default: 6)
  ## `algorithm`   — `algSHA1` (default, RFC 4226) or `algSHA512`
  ## `issuer`      — Service name shown in authenticator apps
  ## `accountName` — User account identifier
  ## `counter`     — Initial counter value (default: 0)
  validateSecret(secret)
  result = HOTP(
    secret:      copySecret(secret),
    digits:      digits,
    algorithm:   algorithm,
    issuer:      issuer,
    accountName: accountName,
    counter:     counter
  )

proc initHotp*(
    secret:      static openArray[char],
    digits:      OTPDigits     = defaultDigits,
    algorithm:   OTPAlgorithm  = algSHA1,
    issuer:      string        = "",
    accountName: string        = "",
    counter:     int           = 0
): HOTP =
  ## Creates an HOTP instance with a **compile-time** secret.
  ## Emits a compile error if the secret exceeds `secretSize`.
  when secret.len > secretSize:
    {.error: "Secret too long. Use `-d:otp.secretSize=N` to increase the limit.".}
  result = HOTP(
    secret:      copySecret(secret),
    digits:      digits,
    algorithm:   algorithm,
    issuer:      issuer,
    accountName: accountName,
    counter:     counter
  )

proc initTotp*(
    secret:      openArray[char],
    digits:      OTPDigits     = defaultDigits,
    interval:    int           = defaultInterval,
    algorithm:   OTPAlgorithm  = algSHA1,
    issuer:      string        = "",
    accountName: string        = ""
): TOTP =
  ## Creates a TOTP instance with a **runtime** secret.
  ## Raises `OTPError` if the secret exceeds `secretSize`.
  ##
  ## `secret`      — Base32-encoded shared secret
  ## `digits`      — Code length: 6, 7, or 8 (default: 6)
  ## `interval`    — Time step in seconds (default: 30)
  ## `algorithm`   — `algSHA1` (default, RFC 4226) or `algSHA512`
  ## `issuer`      — Service name shown in authenticator apps
  ## `accountName` — User account identifier
  validateSecret(secret)
  result = TOTP(
    secret:      copySecret(secret),
    digits:      digits,
    interval:    interval,
    algorithm:   algorithm,
    issuer:      issuer,
    accountName: accountName
  )

proc initTotp*(
    secret:      static openArray[char],
    digits:      OTPDigits     = defaultDigits,
    interval:    int           = defaultInterval,
    algorithm:   OTPAlgorithm  = algSHA1,
    issuer:      string        = "",
    accountName: string        = ""
): TOTP =
  ## Creates a TOTP instance with a **compile-time** secret.
  ## Emits a compile error if the secret exceeds `secretSize`.
  when secret.len > secretSize:
    {.error: "Secret too long. Use `-d:otp.secretSize=N` to increase the limit.".}
  result = TOTP(
    secret:      copySecret(secret),
    digits:      digits,
    interval:    interval,
    algorithm:   algorithm,
    issuer:      issuer,
    accountName: accountName
  )

proc ensureWeCanCompile() {.used, gensym.} =
  discard initTotp("")
  discard initHotp("")

#
# Code generation
#

proc at*(self: HOTP, counter: int): int =
  ## Generates an HOTP code for the given `counter` value.
  result = generateCode(self.secret, counter, self.digits, self.algorithm)

proc next*(self: var HOTP): int =
  ## Generates the next HOTP code and advances the internal counter.
  ## Use this for sequential HOTP flows instead of `at`.
  result = self.at(self.counter)
  inc self.counter

proc at*(self: TOTP, timestamp: int): int =
  ## Generates a TOTP code for the given Unix `timestamp`.
  result = generateCode(self.secret, timecode(self.interval, timestamp), self.digits, self.algorithm)

proc now*(self: TOTP): int =
  ## Generates a TOTP code for the current system time.
  result = self.at(epochTime().int)

#
# Verification
#

proc verify*(self: HOTP, otp: int, counter: int = 0): bool =
  ## Verifies an HOTP `otp` against the given `counter` value.
  result = otp == self.at(counter)

proc verify*(self: TOTP, otp: int, timestamp: int = 0, window: int = defaultWindow): bool =
  ## Verifies a TOTP `otp` against a timestamp (defaults to now).
  ##
  ## `window` — number of time steps checked on either side of the
  ## current step to tolerate clock drift between client and server.
  ## A window of 1 accepts codes from the previous, current, and next interval.
  let ts   = if timestamp == 0: epochTime().int else: timestamp
  let step = timecode(self.interval, ts)
  for delta in -window .. window:
    if otp == generateCode(self.secret, step + delta, self.digits, self.algorithm):
      return true
  result = false

#
# Provisioning URI (otpauth://)
#

proc algorithmParam(algorithm: OTPAlgorithm): string {.inline.} =
  ## Returns the `algorithm=` URI parameter value per the Key Uri Format spec.
  case algorithm
  of algSHA1:   result = "SHA1"
  of algSHA512: result = "SHA512"

proc provisioningUri*(self: HOTP, initialCount: int = 0): string =
  ## Generates an `otpauth://hotp/` URI suitable for QR code provisioning.
  ## Follows the Google Authenticator Key Uri Format:
  ## https://github.com/google/google-authenticator/wiki/Key-Uri-Format
  let label =
    if self.issuer != "": encodeUrl(self.issuer) & ":" & encodeUrl(self.accountName)
    else: encodeUrl(self.accountName)

  result = "otpauth://hotp/" & label &
           "?secret="    & self.secret &
           "&counter="   & $initialCount &
           "&digits="    & $self.digits &
           "&algorithm=" & algorithmParam(self.algorithm)

  if self.issuer != "":
    result &= "&issuer=" & encodeUrl(self.issuer)

proc provisioningUri*(self: TOTP): string =
  ## Generates an `otpauth://totp/` URI suitable for QR code provisioning.
  ## Follows the Google Authenticator Key Uri Format:
  ## https://github.com/google/google-authenticator/wiki/Key-Uri-Format
  let label =
    if self.issuer != "": encodeUrl(self.issuer) & ":" & encodeUrl(self.accountName)
    else: encodeUrl(self.accountName)

  result = "otpauth://totp/" & label &
           "?secret="    & self.secret &
           "&digits="    & $self.digits &
           "&period="    & $self.interval &
           "&algorithm=" & algorithmParam(self.algorithm)

  if self.issuer != "":
    result &= "&issuer=" & encodeUrl(self.issuer)