module CertiorUrlFilterRegression {
  import opened U = CertiorUrlFilter

  method SmokeUrlFilterScenarios()
  {
    var cfg := UrlFilterConfig(
      [Prefix("https://")],
      [Suffix(".onion")],
      2
    );
    assert Matches("https://example.com", Prefix("https://"));
    assert IsAccept(FilterUrl("https://example.com", cfg));
    assert IsReject(FilterUrl("https://blocked.onion", cfg));
    assert IsReject(FilterUrl("http://example.com", cfg));
  }
}