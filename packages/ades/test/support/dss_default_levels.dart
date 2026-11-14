/// DSS 6.5.1, `dss-policy-jaxb/src/main/resources/policy/constraint.xml`
/// (the default policy), element path below `ConstraintsParameters` ->
/// level. Copied by hand from that file; the VM-only root test
/// `test/dss_default_policy_test.dart` re-reads the committed copy of the XML
/// (`fixtures/dss/6.5.1/constraint.xml`) to check this table.
const dssDefaultLevels = <String, (String, String)>{
  'referenceDataExistence': (
    'SignatureConstraints/BasicSignatureConstraints/ReferenceDataExistence',
    'fail',
  ),
  'referenceDataIntact': (
    'SignatureConstraints/BasicSignatureConstraints/ReferenceDataIntact',
    'fail',
  ),
  'signatureIntact': (
    'SignatureConstraints/BasicSignatureConstraints/SignatureIntact',
    'fail',
  ),
  'prospectiveCertificateChain': (
    'SignatureConstraints/BasicSignatureConstraints/ProspectiveCertificateChain',
    'fail',
  ),
  'signingCertificateNotExpired': (
    'SignatureConstraints/BasicSignatureConstraints/SigningCertificate/NotExpired',
    'fail',
  ),
  'revocationDataAvailable': (
    'SignatureConstraints/BasicSignatureConstraints/SigningCertificate/RevocationDataAvailable',
    'fail',
  ),
  'signingCertificatePresent': (
    'SignatureConstraints/SignedAttributes/SigningCertificatePresent',
    'warn',
  ),
  'certDigestPresent': (
    'SignatureConstraints/SignedAttributes/CertDigestPresent',
    'fail',
  ),
  'certDigestMatch': (
    'SignatureConstraints/SignedAttributes/CertDigestMatch',
    'fail',
  ),
  'issuerSerialMatch': (
    'SignatureConstraints/SignedAttributes/IssuerSerialMatch',
    'warn',
  ),
  'signingTime': ('SignatureConstraints/SignedAttributes/SigningTime', 'fail'),
  'signingTimeInCertRange': (
    'SignatureConstraints/SignedAttributes/SigningTimeInCertRange',
    'fail',
  ),
  'caCertificateNotExpired': (
    'SignatureConstraints/BasicSignatureConstraints/CACertificate/NotExpired',
    'fail',
  ),
  'caCertificateCa': (
    'SignatureConstraints/BasicSignatureConstraints/CACertificate/CA',
    'fail',
  ),
  'caCertificateMaxPathLength': (
    'SignatureConstraints/BasicSignatureConstraints/CACertificate/MaxPathLength',
    'fail',
  ),
  'caCertificateKeyUsage': (
    'SignatureConstraints/BasicSignatureConstraints/CACertificate/KeyUsage',
    'fail',
  ),
  'cryptographic': ('Cryptographic', 'fail'),
  'algorithmExpiration': ('Cryptographic/AlgoExpirationDate', 'fail'),
};
