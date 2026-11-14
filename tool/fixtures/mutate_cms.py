#!/usr/bin/env python3
"""Byte-level mutations of an OpenSSL-made CMS SignedData (DER, one SignerInfo, RSA).

Standard library only, no cryptography: re-signing is delegated to `openssl dgst`.
All mutations keep every length unchanged, so they patch bytes in place.

  mutate_cms.py tamper-content IN OUT
  mutate_cms.py wrong-digest   IN OUT KEY OPENSSL
  mutate_cms.py non-der-attrs  IN OUT KEY OPENSSL
"""
import subprocess
import sys


def tlv(buf, pos):
    """Return (tag, header_len, value_len) of the TLV at pos (definite length only)."""
    tag = buf[pos]
    b = buf[pos + 1]
    if b < 0x80:
        return tag, 2, b
    n = b & 0x7F
    if n == 0:
        raise SystemExit("indefinite length not supported (use DER output)")
    return tag, 2 + n, int.from_bytes(buf[pos + 2:pos + 2 + n], "big")


def children(buf, pos):
    tag, hl, vl = tlv(buf, pos)
    p, end = pos + hl, pos + hl + vl
    out = []
    while p < end:
        _, h, v = tlv(buf, p)
        out.append((p, h + v))
        p += h + v
    return out


def locate(buf):
    """Find eContent bytes and the SignerInfo parts. Returns a dict of (offset, total_len)."""
    ci = children(buf, 0)                      # OID, [0]
    sd = children(buf, children(buf, ci[1][0])[0][0])  # SignedData fields
    encap = children(buf, sd[2][0])            # eContentType, [0] eContent
    info = {}
    if len(encap) > 1:
        inner = children(buf, encap[1][0])[0]  # OCTET STRING
        _, h, v = tlv(buf, inner[0])
        info["content"] = (inner[0] + h, v)
    signer_infos = sd[-1]
    si = children(buf, children(buf, signer_infos[0])[0][0])
    attrs = next(c for c in si if buf[c[0]] == 0xA0)
    sig = si[-1]
    _, sh, sv = tlv(buf, sig[0])
    info["attrs"] = attrs
    info["sig"] = (sig[0] + sh, sv)
    return info


def resign(buf, info, key, openssl):
    start, total = info["attrs"]
    msg = b"\x31" + buf[start + 1:start + total]   # signature covers the SET OF, tag 0x31
    sig = subprocess.run([openssl, "dgst", "-sha256", "-sign", key],
                         input=bytes(msg), capture_output=True, check=True).stdout
    off, ln = info["sig"]
    if len(sig) != ln:
        raise SystemExit("signature length changed; RSA only")
    buf[off:off + ln] = sig


def main():
    mode, src, dst = sys.argv[1:4]
    buf = bytearray(open(src, "rb").read())
    info = locate(buf)
    if mode == "tamper-content":
        off, ln = info["content"]
        buf[off + ln - 1] ^= 0x01
    elif mode in ("wrong-digest", "non-der-attrs"):
        key, openssl = sys.argv[4:6]
        start, total = info["attrs"]
        _, h, _ = tlv(buf, start)
        attrs = children(buf, start)
        if mode == "wrong-digest":
            for p, ln in attrs:
                # messageDigest OID 1.2.840.113549.1.9.4 = 06 09 2A 86 48 86 F7 0D 01 09 04
                if bytes(buf[p:p + ln]).find(bytes.fromhex("06092a864886f70d010904")) >= 0:
                    buf[p + ln - 1] ^= 0x01   # last byte of the digest OCTET STRING
                    break
            else:
                raise SystemExit("messageDigest attribute not found")
        else:
            blobs = [bytes(buf[p:p + ln]) for p, ln in attrs]
            if len(blobs) < 2:
                raise SystemExit("need at least two attributes")
            # DER requires SET OF sorted by encoding; reverse order guarantees it is unsorted.
            ordered = sorted(blobs)[::-1]
            buf[start + h:start + total] = b"".join(ordered)
        resign(buf, info, key, openssl)
    else:
        raise SystemExit("unknown mode")
    open(dst, "wb").write(buf)


if __name__ == "__main__":
    main()
