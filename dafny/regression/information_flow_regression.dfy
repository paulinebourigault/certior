module CertiorInformationFlowRegression {
  import opened F = CertiorInformationFlow

  method SmokeInformationFlowScenarios()
  {
    var src := SecurityLabel(Internal, {"phi"}, "db");
    var allowedTarget := SecurityLabel(Sensitive, {"phi", "audit"}, "");
    var deniedTarget := SecurityLabel(Public, {}, "");
    assert LabelCanFlowTo(src, allowedTarget);
    assert !LabelCanFlowTo(src, deniedTarget);
  }
}