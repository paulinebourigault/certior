module CertiorCertificatesRegression {
  import opened C = CertiorCertificates

  method SmokeCertificateLifecycle()
  {
    var ca := new CertificateAuthority();
    var cert := ca.issue_certificate("cert-1", "thm", "hash", ["P1"], "z3", 10, 100);
    assert SignatureValid(cert);
    assert cert.id in ca.issued;

    ca.revoke("cert-1");
    assert cert.id !in ca.issued;
  }
}