import std/[unittest, os, strutils]
import pkg/base32
import ../src/twofa

suite "twofa":
  test "genTotpUri encodes raw secret to Base32":
    let uri = genTotpUri(
      secret = "loremipsum",
      label = "MyLabel",
      issuer = "OpenPeeps",
      interval = 30,
      isBase32 = false
    )
    let u = string(uri)
    let expected = base32.encode("loremipsum").toUpperAscii().replace("=", "")

    check u.startsWith("otpauth://totp/MyLabel?")
    check u.contains("secret=" & expected)
    check u.contains("&period=30")
    check u.contains("&issuer=OpenPeeps")

  test "genTotpUri accepts/normalizes Base32 input":
    let uri = genTotpUri(
      secret = "jbswy3dpehpk3pxp==",
      label = "MyLabel",
      isBase32 = true
    )
    check string(uri).contains("secret=JBSWY3DPEHPK3PXP")

  test "genTotpUri rejects invalid Base32 input":
    expect(ValueError):
      discard genTotpUri(
        secret = "abc-123",
        label = "MyLabel",
        isBase32 = true
      )

  test "genHotpUri uses counter and Base32-normalized secret":
    let uri = genHotpUri(
      secret = "loremipsum",
      label = "MyLabel",
      issuer = "OpenPeeps",
      counter = 5'u64,
      isBase32 = false
    )
    let u = string(uri)
    let expected = base32.encode("loremipsum").toUpperAscii().replace("=", "")

    check u.startsWith("otpauth://hotp/MyLabel?")
    check u.contains("secret=" & expected)
    check u.contains("&counter=5")
    check u.contains("&issuer=OpenPeeps")

  test "saveQr writes an svg file":
    let outFile = getTempDir() / "twofa_test.svg"
    if fileExists(outFile):
      removeFile(outFile)

    let uri = genTotpUri(secret = "loremipsum", label = "MyLabel")
    uri.saveQr(outFile)

    check fileExists(outFile)

    if fileExists(outFile):
      removeFile(outFile)