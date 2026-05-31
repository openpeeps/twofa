#
#          Nim's Unofficial Library
#        (c) Copyright 2015 Huy Doan
#        (c) 2026 George Lemon — fixes & hardening
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## Base32 encoder and decoder (RFC 4648).
##
## Alphabet: `A–Z` + `2–7`, with optional `=` padding.
## Both uppercase and lowercase are accepted on decode.

const
  VERSION* = "0.1.2"

  base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    ## 32-character alphabet per RFC 4648 §6 (no padding char here)

type
  Base32Error* = object of ValueError
    ## Raised when a non-base32 character is encountered during decode.

#
# Helpers
#

func encodedLen(rawLen: int, pad: bool): int {.inline.} =
  ## Returns the exact output length for a base32-encoded string.
  ## Uses integer arithmetic only — no float division.
  let groups = rawLen div 5          # full 5-byte groups → 8 chars each
  let remainder = rawLen mod 5       # leftover bytes
  result = groups * 8
  if remainder > 0:
    # remainder 1 → 2 chars, 2 → 4, 3 → 5, 4 → 7 (before padding)
    const extraChars = [0, 2, 4, 5, 7]
    result += extraChars[remainder]
    if pad:
      # round up to next multiple of 8
      result += (8 - result mod 8) mod 8

func decodedLen(s: openArray[char]): int {.inline.} =
  ## Returns the maximum decoded byte count (may be slightly over due to padding).
  ## Actual length is trimmed after decoding.
  result = (s.len * 5) div 8

func charToVal(ch: char): int {.inline.} =
  ## Maps a base32 character to its 5-bit value, or -1 if invalid.
  case ch
  of 'A'..'Z': result = ord(ch) - ord('A')        # 0–25
  of 'a'..'z': result = ord(ch) - ord('a')        # 0–25 (case-insensitive)
  of '2'..'7': result = ord(ch) - ord('2') + 26   # 26–31
  of '=':      result = -2                         # padding sentinel
  else:        result = -1                         # invalid

#
# Encode
#

proc encode*(s: openArray[char], pad = true): string =
  ## Encodes `s` to a base32 string.
  ## Set `pad = false` to omit trailing `=` padding characters.
  if s.len == 0:
    return ""

  result = newString(encodedLen(s.len, pad))
  var
    outIdx = 0
    buf    = 0   ## accumulator
    bits   = 0   ## bits currently in accumulator

  for ch in s:
    buf  = (buf shl 8) or ord(ch)
    bits += 8
    while bits >= 5:
      bits -= 5
      result[outIdx] = base32Alphabet[(buf shr bits) and 0x1F]
      inc outIdx

  # flush remaining bits (zero-padded on the right)
  if bits > 0:
    result[outIdx] = base32Alphabet[(buf shl (5 - bits)) and 0x1F]
    inc outIdx

  # append `=` padding to reach a multiple of 8
  if pad:
    while outIdx < result.len:
      result[outIdx] = '='
      inc outIdx
  else:
    result.setLen outIdx

#
# Decode
#

proc decode*(s: openArray[char]): string =
  ## Decodes a base32-encoded string.
  ## Accepts both uppercase and lowercase input.
  ## Ignores `=` padding characters.
  ## Raises `Base32Error` on any invalid character.
  if s.len == 0:
    return ""

  result = newString(decodedLen(s))
  var
    outIdx = 0
    buf    = 0   ## accumulator
    bits   = 0   ## bits currently in accumulator

  for i in 0 ..< s.len:
    let v = charToVal(s[i])
    if v == -2:
      break        ## padding reached — stop cleanly
    if v == -1:
      raise (ref Base32Error)(
        msg: "Invalid base32 character '" & $s[i] & "' at position " & $i)

    buf  = (buf shl 5) or v
    bits += 5

    if bits >= 8:
      bits -= 8
      result[outIdx] = char((buf shr bits) and 0xFF)
      inc outIdx

  result.setLen outIdx   ## trim to actual decoded length