module CertiorSeccompFilterRegression {
  import opened S = CertiorSeccompFilter

  method SmokeSeccompBaseChecks()
  {
    assert InSeq(1, [1, 2, 3]);
    assert NotInSeq(7, [1, 2, 3]);
    assert FilterSyscall(1, [1, 2, 3]) == Allow;
    assert IsDeny(FilterSyscall(7, [1, 2, 3]));
    assert FilterSyscall(2, Normalize([3, 2, 2, 1])) == Allow;
    assert CheckArchitecture(62, 62) == Allow;
  }
}