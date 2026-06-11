module CertiorCapabilityAttenuationRegression {
  import opened A = CertiorCapabilityAttenuation

  method SmokeCapabilityScenarios()
  {
    var root := CapabilityToken(
      "root",
      "orchestrator",
      ["filesystem:read"],
      100,
      100,
      "",
      0
    );
    assert TokenWellFormed(root);
    assert root.budget_remaining == 100;

    var att := Attenuate(
      root,
      "child",
      "worker",
      ["filesystem:read"],
      50
    );
    assert att.AttenuateOk?;
    var child := att.child;
    assert PermissionsSubset(child.permissions, root.permissions);

    var spent := SpendBudget(child, 20);
    assert spent.SpendOk?;
    assert spent.token.budget_remaining == 30;

    assert !HasPermission("filesystem:write", child.permissions);
  }
}