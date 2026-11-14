# The core never touches a private key

No library in `ades` holds or uses private key material. Every signature value comes from a signing credential. In-memory keys (PKCS#12/PEM) live in a separate `ades_soft` package, documented as not hardened against side channels (it uses pointycastle with no guaranteed RSA blinding or constant-time ECDSA). It is meant for tests and low-risk server e-seals. Keeping keys out of the core keeps its security review to parsing and verification only.
