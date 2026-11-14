# Linux test environment for ades_pkcs11: official Dart image + SoftHSM2.
# opensc provides pkcs11-tool (used to import certificates into the token).
FROM dart:stable
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 opensc \
 && rm -rf /var/lib/apt/lists/*
