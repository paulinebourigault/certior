module CertiorSeccompFilterExtendedRegression {
  import opened E = CertiorSeccompFilterExtended

  method SmokeSeccompExtendedChecks()
  {
    var constraints := [ArgumentConstraint(1, 0, [42, 99])];
    assert HasConstraintForSyscall(1, constraints);
    assert ArgValueAllowed(42, GetConstraintForSyscall(1, constraints));

    var allowed := FilterSyscallConstrained(1, 42, [1], constraints);
    assert IsAllow(allowed);

    var deniedArg := FilterSyscallConstrained(1, 7, [1], constraints);
    assert IsDeny(deniedArg);

    var deniedSyscall := FilterSyscallConstrained(2, 42, [1], constraints);
    assert IsDeny(deniedSyscall);
  }
}