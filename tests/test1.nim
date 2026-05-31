import std/[unittest, strutils]
import ../src/twofa
import ../src/twofa/base32

suite "otp":
  test "HOTP RFC4226 test vectors (SHA1)":
    # RFC4226 secret (ASCII) -> Base32
    let asciiSecret = "12345678901234567890"
    let b32 = base32.encode(asciiSecret).toUpperAscii().replace("=", "")
    let hotp = initHotp(b32, digits = 6, algorithm = algSHA1)

    let expected = @[
      "755224", "287082", "359152", "969429", "338314",
      "254676", "287922", "162583", "399871", "520489"
    ]

    for i in 0 ..< expected.len:
      check hotp.at(i) == parseInt(expected[i])

  test "TOTP RFC6238 test vector (SHA1, 8 digits)":
    # RFC6238 shared secret (same ASCII secret as RFC4226)
    let asciiSecret = "12345678901234567890"
    let b32 = base32.encode(asciiSecret).toUpperAscii().replace("=", "")
    let totp = initTotp(b32, digits = 8, interval = 30, algorithm = algSHA1)

    # (timestamp, expected_code) pairs from RFC6238 Appendix B
    let vectors = [
      (59,          "94287082"),
      (1111111109,  "07081804"),
      (1111111111,  "14050471"),
      (1234567890,  "89005924"),
      (2000000000,  "69279037"),
      (20000000000, "65353130")
    ]

    for (ts, expected) in vectors:
      check totp.at(ts) == parseInt(expected)

  test "HOTP.next advances counter and produces correct RFC vectors":
    let asciiSecret = "12345678901234567890"
    let b32 = base32.encode(asciiSecret).toUpperAscii().replace("=", "")
    var hotp = initHotp(b32, digits = 6, algorithm = algSHA1, counter = 0)

    # next() should produce the same sequence as at(0), at(1), at(2)...
    # and advance the internal counter each time
    let expected = @[755224, 287082, 359152, 969429, 338314]
    for i in 0 ..< expected.len:
      check hotp.next() == expected[i]

    # internal counter should now be at 5
    check hotp.counter == 5

    # verify works against an explicit counter value
    check hotp.verify(755224, counter = 0)   # correct code for counter 0
    check hotp.verify(287082, counter = 1)   # correct code for counter 1
    check not hotp.verify(000000, counter = 0) # wrong code

  test "TOTP verification window tolerates drift":
    let asciiSecret = "12345678901234567890"
    let b32 = base32.encode(asciiSecret).toUpperAscii().replace("=", "")
    let totp = initTotp(b32, digits = 6, interval = 30, algorithm = algSHA1)
    let now = 59 # known RFC vector time
    let code = generateCode(totp.secret, timecode(totp.interval, now), totp.digits, totp.algorithm)
    # window 0: exact match only
    check totp.verify(code, timestamp = now, window = 0)
    # window 1: code from step N is still valid one step later
    check totp.verify(code, timestamp = now + 30, window = 1)
    # window 0 at a different step must fail
    check not totp.verify(code, timestamp = now + 30, window = 0)

  test "SHA512 algorithm: generate & verify are consistent":
    let ascii512 = "12345678901234567890123456789012"
    let b32_512 = base32.encode(ascii512).toUpperAscii().replace("=", "")
    let totp512 = initTotp(b32_512, digits = 8, interval = 30, algorithm = algSHA512)
    let t = 1234567890
    let code = totp512.at(t)
    check totp512.verify(code, timestamp = t, window = 0)
    # different timestamp outside window must not verify
    check not totp512.verify(code, timestamp = t + 300, window = 0)

  test "provisioningUri contains algorithm and params":
    let asciiSecret = "foobar"
    let b32 = base32.encode(asciiSecret).toUpperAscii().replace("=", "")
    let hotp = initHotp(b32, algorithm = algSHA512, issuer = "Acme", accountName = "alice", counter = 7)
    let uri = hotp.provisioningUri(initialCount = 7)
    check uri.contains("algorithm=SHA512")
    check uri.contains("issuer=Acme")
    check uri.contains("counter=7")

    let totp = initTotp(b32, algorithm = algSHA1, issuer = "Acme", accountName = "bob", interval = 45)
    let turi = totp.provisioningUri()
    check turi.contains("algorithm=SHA1")
    check turi.contains("period=45")
    check turi.contains("issuer=Acme")

suite "twofa QR code generation":
  test "genTotpUri produces correct otpauth URI format":
    let uri = genTotpUri(secret = "mysecret", label = "MyLabel", issuer = "MyIssuer", interval = 60)
    check uri.startsWith("otpauth://totp/MyLabel?secret=")
    check uri.contains("issuer=MyIssuer")
    check uri.contains("period=60")
    
  test "genHotpUri produces correct otpauth URI format":
    let uri = genHotpUri(secret = "mysecret", label = "MyLabel", issuer = "MyIssuer", counter = 42)
    check uri.startsWith("otpauth://hotp/MyLabel?secret=")
    check uri.contains("issuer=MyIssuer")
    check uri.contains("counter=42")