module CertiorPathSafetyRegression {
  import opened P = CertiorPathSafety

  method SmokePathSafetyScenarios()
  {
    var cfg := PathSafetyConfig(
      "/tmp/certior_ws",
      {Ext(".txt"), Ext(".md")},
      {Ext(".env")},
      4096
    );
    assert IsAllow(CheckPathSafety("notes.txt", Ext(".txt"), 120, cfg));
    assert HasTraversal("../secret.txt");
    assert IsDeny(CheckPathSafety("../secret.txt", Ext(".txt"), 120, cfg));
    assert ExtensionBlocked(Ext(".env"), cfg);
    assert IsDeny(CheckPathSafety("config.env", Ext(".env"), 120, cfg));
  }
}