<p align="center">
  A tiny package for generating 2FA QR codes and TOTP/HOTP codes in Nim
</p>

<p align="center">
  <code>nimble install twofa</code>
</p>

<p align="center">
  <a href="https://openpeeps.github.io/twofa">API reference</a><br>
  <img src="https://github.com/openpeeps/twofa/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/openpeeps/twofa/workflows/docs/badge.svg" alt="Github Actions">
</p>

## 😍 Key Features
- 🔐 TOTP (RFC 6238) and HOTP (RFC 4226) code generation and verification
- 🔑 SHA1 and SHA512 HMAC algorithms, configurable digits (6–8) and period/counter
- 🛡️ Verification with clock-drift window and constant-time secret handling
- 📱 QR code generation via [`openparser/qr`](https://github.com/openpeeps/openparser) - Model 2 (versions 1-40), all EC levels (L/M/Q/H)
- 🎨 Customizable SVG rendering: `scale`, `border`, `dark`/`light` colors, and `QrEncodeOptions`
- 🧩 Raw matrix support via `saveMatrix` for pre-encoded `QrMatrix` values
- 🔗 `otpauth://` provisioning URIs with `provisioningUri`, `genTotpUri` and `genHotpUri` helpers

> [!NOTE]
> This library is built on top of [`openparser/qr`](https://github.com/openpeeps/openparser) for QR code generation.

## Examples

Check out the [tests/*.nim](https://github.com/openpeeps/twofa/tree/main/tests) folder for more examples.

### TOTP and HOTP

```nim
import twofa

# TOTP with SHA1 (compatible with Google Authenticator)
let totp = initTotp("JBSWY3DPEHPK3PXP",
  issuer = "MyApp", accountName = "alice@example.com")

echo totp.now()              # code for current time
echo totp.at(1234567890)     # code for specific timestamp
echo totp.verify(123456, timestamp = 1234567890) # verification with window

# TOTP with SHA512 and custom period/digits
let totp512 = initTotp("JBSWY3DPEHPK3PXP",
  interval = 60, digits = 8, algorithm = algSHA512)

# HOTP (counter-based)
var hotp = initHotp("JBSWY3DPEHPK3PXP",
  issuer = "MyApp", accountName = "bob@example.com", counter = 0)

echo hotp.at(0)              # code for counter 0
echo hotp.next()             # next code and auto-increment counter
echo hotp.verify(755224, counter = 0)
```

### Provisioning URIs

```nim
import twofa

let totp = initTotp("JBSWY3DPEHPK3PXP",
  issuer = "OpenPeeps", accountName = "alice@example.com")

# From TOTP/HOTP instances (follows Google Authenticator Key Uri Format)
let totpUri = totp.provisioningUri()
let hotpUri = initHotp("JBSWY3DPEHPK3PXP",
  issuer = "OpenPeeps", accountName = "bob@example.com").provisioningUri(initialCount = 1)

# Standalone helpers without creating an instance
let uri1 = genTotpUri(secret = "JBSWY3DPEHPK3PXP",
  label = "alice@example.com", issuer = "MyApp", interval = 30)

let uri2 = genHotpUri(secret = "JBSWY3DPEHPK3PXP",
  label = "bob@example.com", issuer = "MyApp", counter = 42)
```

### QR Code Generation

```nim
import twofa

let totp = initTotp("JBSWY3DPEHPK3PXP",
  issuer = "MyApp", accountName = "alice@example.com")
let uri = totp.provisioningUri()

# Save to file (default rendering)
uri.saveQr("totp.svg")

# Get SVG as string
let svg = uri.getQr()
writeFile("totp.svg", svg)

# Custom rendering settings
uri.saveQr("totp-custom.svg",
  scale = 10,               # pixel size per module
  border = 2,               # quiet zone in modules
  dark = "#000000",
  light = "#ffffff")

# Custom error correction / version
import openparser/qr          # for QrEncodeOptions / ecHigh
uri.saveQr("totp-high-ec.svg",
  options = QrEncodeOptions(ecLevel: ecHigh))

let svgHigh = uri.getQr(
  scale = 8, border = 4,
  options = QrEncodeOptions(ecLevel: ecHigh))
```

### Raw Matrix with `saveMatrix`

Useful when you already have a `QrMatrix` from `openparser/qr`:

```nim
import twofa
import openparser/qr

let uri = genTotpUri(
  secret = "JBSWY3DPEHPK3PXP",
  label = "alice@example.com",
  issuer = "MyApp")

# Encode once, render multiple ways
let m = encodeQr(uri)                       # or encodeQrBytes, etc.
m.saveMatrix("matrix-default.svg")
m.saveMatrix("matrix-red.svg", scale = 6, dark = "#ff0000", light = "#ffffff")

# High error correction matrix
let m2 = encodeQr(uri, QrEncodeOptions(ecLevel: ecQuartile))
m2.saveMatrix("matrix-quartile.svg", scale = 8, border = 4)
```

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/openpeeps/twofa/issues)
- 👋 Wanna help? [Fork it!](https://github.com/openpeeps/twofa/fork)

### 🎩 License
MIT license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors - All rights reserved.
