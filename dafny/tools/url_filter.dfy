// =============================================================================
// url_filter.dfy - Dafny-Verified URL Filter & Tool Enforcement (Phase B4)
// =============================================================================
//
// Proves critical safety properties for Certior's URL filtering subsystem,
// which gates every outbound HTTP request from agent tools (web_fetch, etc.).
//
//   P22 ALLOWLIST COMPLETENESS
//       filter_url(url) == Accept  ONLY IF  ∃ p ∈ allowlist: Matches(url, p).
//       No URL can be accepted without matching at least one allowlist entry.
//
//   P23 BLOCKLIST CORRECTNESS
//       ∃ p ∈ blocklist: Matches(url, p)  ==>  filter_url(url) == Reject.
//       Any URL matching a blocklist entry is unconditionally rejected.
//
//   P24 BLOCKLIST PRECEDENCE
//       If a URL matches BOTH an allowlist entry AND a blocklist entry,
//       the filter rejects it.  Blocklist always wins.
//
//   P25 FILTER DETERMINISM
//       For any given (url, config) pair, filter_url always returns the
//       same FilterDecision.  (Proved structurally - pure function.)
//
//   P26 EMPTY ALLOWLIST REJECTS ALL
//       If |allowlist| == 0, then ∀ url: filter_url(url) == Reject.
//       An empty allowlist admits nothing.
//
//   P27 EMPTY BLOCKLIST DEFERS TO ALLOWLIST
//       If |blocklist| == 0, then filter_url(url) == Accept  ⟺
//       ∃ p ∈ allowlist: Matches(url, p).  Blocklist vacuously passes.
//
//   P28 BLOCKLIST MONOTONICITY
//       If filter_url(url, config) == Accept and we add a new pattern to
//       the blocklist that does NOT match url, the result is still Accept.
//       Adding blocklist entries can only reduce accepted URLs.
//
//   P29 RATE LIMIT ENFORCEMENT
//       After check_rate_limit() returns Accept, request_count < max_rpm.
//       After it returns Reject, request_count >= max_rpm.
//       request_count is bounded: 0 <= request_count <= max_rpm.
//
//   P30 AUDIT COMPLETENESS
//       Every call to check_url appends exactly one entry to the audit log.
//       |audit_log| after check_url == |audit_log| before + 1.
//       The appended entry records the url, decision, and reason.
//
//   P31 FILTER INVARIANT PRESERVATION
//       Every public method preserves the class invariant Valid().
//       Valid() == (request_count <= max_requests_per_minute)
//                ∧ (|audit_log| >= 0)
//
//   P32 RATE LIMIT RESET CORRECTNESS
//       After reset_rate_limit(): request_count == 0.
//       All previously recorded audit entries are preserved.
//
//   P33 CONFIG IMMUTABILITY
//       The UrlFilterConfig (allowlist, blocklist, max_rpm) never changes
//       after construction.  Enforced by datatype immutability.
//
// Usage:
//   dafny verify dafny/tools/url_filter.dfy
//
// Verification target: Dafny 4.x
// =============================================================================

module CertiorUrlFilter {

  // =========================================================================
  // UrlPattern - abstract pattern representation
  // =========================================================================
  //
  // Real patterns are regexes; Dafny models them as tagged unions over
  // the four matching modes used in VERIFICATION.json:
  //   Prefix("https://")   - url starts with value
  //   Suffix(".onion")      - url ends with value
  //   Contains("localhost") - url contains value as substring
  //   Exact("http://x.com") - url equals value exactly
  //   Any                   - wildcard, matches everything
  //
  // This abstraction is sound because every production regex in
  // VERIFICATION.json maps to one of these modes.
  // =========================================================================

  datatype UrlPattern =
    | Prefix(value: string)
    | Suffix(value: string)
    | Contains(value: string)
    | Exact(value: string)
    | Any

  // ── String helpers (Dafny built-ins for seq<char>) ──────────

  predicate StartsWith(s: string, prefix: string)
  {
    |prefix| <= |s| && s[..|prefix|] == prefix
  }

  predicate EndsWith(s: string, suffix: string)
  {
    |suffix| <= |s| && s[|s| - |suffix|..] == suffix
  }

  predicate ContainsSubstring(s: string, sub: string)
  {
    exists i :: 0 <= i <= |s| - |sub| && s[i..i + |sub|] == sub
  }

  // ── Pattern matching ────────────────────────────────────────

  predicate Matches(url: string, pattern: UrlPattern)
  {
    match pattern
    case Prefix(v)   => StartsWith(url, v)
    case Suffix(v)   => EndsWith(url, v)
    case Contains(v) => ContainsSubstring(url, v)
    case Exact(v)    => url == v
    case Any         => true
  }

  // ── Sequence-level matching predicates ──────────────────────

  predicate MatchesAny(url: string, patterns: seq<UrlPattern>)
  {
    exists i :: 0 <= i < |patterns| && Matches(url, patterns[i])
  }

  predicate MatchesNone(url: string, patterns: seq<UrlPattern>)
  {
    forall i :: 0 <= i < |patterns| ==> !Matches(url, patterns[i])
  }

  // ── Fundamental relationship ────────────────────────────────

  lemma MatchesAnyEquivNotMatchesNone(url: string, patterns: seq<UrlPattern>)
    ensures MatchesAny(url, patterns) <==> !MatchesNone(url, patterns)
  {}

  // =========================================================================
  // FilterDecision - the verdict
  // =========================================================================

  datatype FilterDecision = Accept | Reject(reason: string)

  predicate IsAccept(d: FilterDecision)
  {
    d.Accept?
  }

  predicate IsReject(d: FilterDecision)
  {
    d.Reject?
  }

  // =========================================================================
  // UrlFilterConfig - immutable configuration (P33)
  // =========================================================================

  datatype UrlFilterConfig = UrlFilterConfig(
    allowlist: seq<UrlPattern>,
    blocklist: seq<UrlPattern>,
    max_requests_per_minute: nat
  )

  // =========================================================================
  // Pure filter function - the specification (P25 determinism)
  // =========================================================================
  //
  // This is the SPECIFICATION that all runtime code must implement.
  // Being a pure function, it is inherently deterministic (P25).
  // =========================================================================

  function FilterUrl(url: string, config: UrlFilterConfig): FilterDecision
  {
    if !MatchesAny(url, config.allowlist) then
      Reject("URL does not match any allowlist pattern")
    else if MatchesAny(url, config.blocklist) then
      Reject("URL matches blocklist pattern")
    else
      Accept
  }

  // =========================================================================
  // AuditEntry - immutable record of a filter decision
  // =========================================================================

  datatype AuditEntry = AuditEntry(
    url: string,
    decision: FilterDecision,
    request_number: nat
  )

  // =========================================================================
  // UrlFilter - stateful filter with rate limiting and audit (P31)
  // =========================================================================

  class UrlFilter {
    var config: UrlFilterConfig
    var request_count: nat
    var audit_log: seq<AuditEntry>

    // =====================================================================
    // CLASS INVARIANT (P31)
    //
    //   C1: request_count bounded by max_requests_per_minute
    //   C2: audit_log length is non-negative (trivially true for seq)
    //   C3: config immutability is enforced by never modifying it
    // =====================================================================
    ghost predicate Valid()
      reads this
    {
      && request_count <= config.max_requests_per_minute   // C1
    }

    // =====================================================================
    // CONSTRUCTOR - establishes Valid()
    // =====================================================================
    constructor(cfg: UrlFilterConfig)
      ensures Valid()
      ensures config == cfg
      ensures request_count == 0
      ensures audit_log == []
    {
      config := cfg;
      request_count := 0;
      audit_log := [];
    }

    // =====================================================================
    // check_url - main entry point (P22-P28, P30, P31)
    //
    // Combines URL filtering with rate limiting and audit logging.
    //
    // Postconditions prove:
    //   - Accept ⟹ allowlisted AND NOT blocklisted AND under rate limit (P22-P24, P29)
    //   - Reject ⟹ not allowlisted OR blocklisted OR over rate limit (P22-P24, P29)
    //   - Audit log grew by exactly 1 (P30)
    //   - Decision matches FilterUrl spec for non-rate-limited cases (P25)
    //   - Valid() preserved (P31)
    // =====================================================================
    method check_url(url: string) returns (decision: FilterDecision)
      requires Valid()
      modifies this
      ensures Valid()                                                    // P31
      ensures |audit_log| == |old(audit_log)| + 1                        // P30
      ensures audit_log[..|old(audit_log)|] == old(audit_log)            // P30: append-only
      ensures audit_log[|audit_log| - 1].url == url                      // P30: correct url
      ensures audit_log[|audit_log| - 1].decision == decision            // P30: correct decision
      // P29: Rate limit enforcement
      ensures old(request_count) >= config.max_requests_per_minute ==>
        IsReject(decision)
      // P22+P23+P24: Filter correctness (when not rate-limited)
      ensures old(request_count) < config.max_requests_per_minute ==>
        decision == FilterUrl(url, config)
      // P22: Accept requires allowlist match
      ensures IsAccept(decision) ==>
        MatchesAny(url, config.allowlist)
      // P23+P24: Blocklist match requires reject
      ensures MatchesAny(url, config.blocklist) ==>
        IsReject(decision)
      // P29: Accept means request_count was incremented
      ensures IsAccept(decision) ==>
        request_count == old(request_count) + 1
      // P29: Reject means request_count unchanged
      ensures IsReject(decision) ==>
        request_count == old(request_count)
      // Config unchanged (P33)
      ensures config == old(config)
    {
      // Rate limit check first (P29)
      if request_count >= config.max_requests_per_minute {
        decision := Reject("Rate limit exceeded");
        audit_log := audit_log + [AuditEntry(url, decision, request_count)];
        return;
      }

      // URL filter (P22-P24)
      decision := FilterUrl(url, config);

      if IsAccept(decision) {
        request_count := request_count + 1;
      }

      audit_log := audit_log + [AuditEntry(url, decision, request_count)];
    }

    // =====================================================================
    // reset_rate_limit - P32
    //
    // Resets the per-window request counter.  Audit log is preserved.
    // =====================================================================
    method reset_rate_limit()
      requires Valid()
      modifies this
      ensures Valid()                                    // P31
      ensures request_count == 0                          // P32
      ensures audit_log == old(audit_log)                 // audit preserved
      ensures config == old(config)                       // P33
    {
      request_count := 0;
    }

    // =====================================================================
    // get_audit_log - pure query, no side effects
    // =====================================================================
    method get_audit_log() returns (log: seq<AuditEntry>)
      requires Valid()
      ensures log == audit_log
    {
      log := audit_log;
    }

    // =====================================================================
    // get_request_count - pure query
    // =====================================================================
    method get_request_count() returns (count: nat)
      requires Valid()
      ensures count == request_count
    {
      count := request_count;
    }
  }

  // =========================================================================
  // LEMMAS - standalone proofs of safety properties
  // =========================================================================

  // ── P22: Allowlist completeness ───────────────────────────────

  lemma AllowlistCompleteness(url: string, config: UrlFilterConfig)
    ensures IsAccept(FilterUrl(url, config)) ==>
      MatchesAny(url, config.allowlist)
  {}

  lemma AllowlistNecessary(url: string, config: UrlFilterConfig)
    requires !MatchesAny(url, config.allowlist)
    ensures IsReject(FilterUrl(url, config))
  {}

  // ── P23: Blocklist correctness ────────────────────────────────

  lemma BlocklistCorrectness(url: string, config: UrlFilterConfig)
    requires MatchesAny(url, config.blocklist)
    ensures IsReject(FilterUrl(url, config))
  {}

  lemma BlocklistSufficient(url: string, config: UrlFilterConfig)
    ensures MatchesAny(url, config.blocklist) ==>
      IsReject(FilterUrl(url, config))
  {}

  // ── P24: Blocklist precedence over allowlist ──────────────────

  lemma BlocklistPrecedence(url: string, config: UrlFilterConfig)
    requires MatchesAny(url, config.allowlist)
    requires MatchesAny(url, config.blocklist)
    ensures IsReject(FilterUrl(url, config))
  {}

  lemma BlocklistAlwaysWins(
    url: string,
    allowlist: seq<UrlPattern>,
    blocklist: seq<UrlPattern>,
    max_rpm: nat
  )
    requires MatchesAny(url, blocklist)
    ensures IsReject(FilterUrl(url, UrlFilterConfig(allowlist, blocklist, max_rpm)))
  {}

  // ── P25: Determinism (structural - pure function) ─────────────

  lemma FilterDeterminism(
    url: string,
    config: UrlFilterConfig
  )
    ensures FilterUrl(url, config) == FilterUrl(url, config)
  {}

  // ── P26: Empty allowlist rejects all ──────────────────────────

  lemma EmptyAllowlistRejectsAll(url: string, config: UrlFilterConfig)
    requires config.allowlist == []
    ensures IsReject(FilterUrl(url, config))
  {
    // With an empty allowlist, MatchesAny(url, []) is false
    assert !MatchesAny(url, config.allowlist);
  }

  lemma EmptyAllowlistUniversalReject(
    blocklist: seq<UrlPattern>,
    max_rpm: nat
  )
    ensures forall url :: IsReject(
      FilterUrl(url, UrlFilterConfig([], blocklist, max_rpm))
    )
  {
    forall url
      ensures IsReject(FilterUrl(url, UrlFilterConfig([], blocklist, max_rpm)))
    {
      var cfg := UrlFilterConfig([], blocklist, max_rpm);
      assert !MatchesAny(url, cfg.allowlist);
    }
  }

  // ── P27: Empty blocklist defers to allowlist ──────────────────

  lemma EmptyBlocklistDefersToAllowlist(
    url: string,
    config: UrlFilterConfig
  )
    requires config.blocklist == []
    ensures IsAccept(FilterUrl(url, config)) <==>
      MatchesAny(url, config.allowlist)
  {
    assert !MatchesAny(url, config.blocklist);
  }

  lemma EmptyBlocklistEquivalence(
    url: string,
    allowlist: seq<UrlPattern>,
    max_rpm: nat
  )
    ensures var cfg := UrlFilterConfig(allowlist, [], max_rpm);
      IsAccept(FilterUrl(url, cfg)) <==>
        MatchesAny(url, allowlist)
  {
    var cfg := UrlFilterConfig(allowlist, [], max_rpm);
    assert !MatchesAny(url, cfg.blocklist);
  }

  // ── P28: Blocklist monotonicity ───────────────────────────────
  //
  // Adding a blocklist entry that does NOT match the url preserves Accept.
  //

  lemma BlocklistMonotonicity_Accept(
    url: string,
    allowlist: seq<UrlPattern>,
    blocklist: seq<UrlPattern>,
    new_pattern: UrlPattern,
    max_rpm: nat
  )
    requires !Matches(url, new_pattern)
    requires IsAccept(FilterUrl(url, UrlFilterConfig(allowlist, blocklist, max_rpm)))
    ensures IsAccept(FilterUrl(url, UrlFilterConfig(allowlist, blocklist + [new_pattern], max_rpm)))
  {
    var cfg_old := UrlFilterConfig(allowlist, blocklist, max_rpm);
    var cfg_new := UrlFilterConfig(allowlist, blocklist + [new_pattern], max_rpm);

    // url matched allowlist in old config
    assert MatchesAny(url, cfg_old.allowlist);
    assert MatchesAny(url, cfg_new.allowlist);

    // url did not match blocklist in old config
    assert !MatchesAny(url, cfg_old.blocklist);

    // new_pattern doesn't match url, so url still doesn't match extended blocklist
    assert !MatchesAny(url, cfg_new.blocklist);
  }

  // Adding a blocklist entry that DOES match the url turns Accept to Reject.

  lemma BlocklistMonotonicity_NewReject(
    url: string,
    allowlist: seq<UrlPattern>,
    blocklist: seq<UrlPattern>,
    new_pattern: UrlPattern,
    max_rpm: nat
  )
    requires Matches(url, new_pattern)
    requires IsAccept(FilterUrl(url, UrlFilterConfig(allowlist, blocklist, max_rpm)))
    ensures IsReject(FilterUrl(url, UrlFilterConfig(allowlist, blocklist + [new_pattern], max_rpm)))
  {
    var cfg_new := UrlFilterConfig(allowlist, blocklist + [new_pattern], max_rpm);
    // new_pattern matches, so MatchesAny is true for extended blocklist
    assert Matches(url, cfg_new.blocklist[|blocklist|]);
    assert MatchesAny(url, cfg_new.blocklist);
  }

  // ── P29: Rate limit enforcement ───────────────────────────────

  lemma RateLimitBlocks(
    filter_count: nat,
    max_rpm: nat
  )
    requires filter_count >= max_rpm
    ensures true  // At this point, check_url must return Reject
  {}

  // ── P30: Audit completeness (proved in check_url ensures) ─────

  lemma AuditAppendOnly(
    old_log: seq<AuditEntry>,
    new_log: seq<AuditEntry>,
    entry: AuditEntry
  )
    requires new_log == old_log + [entry]
    ensures |new_log| == |old_log| + 1
    ensures new_log[..|old_log|] == old_log
    ensures new_log[|new_log| - 1] == entry
  {}

  // ── Composite: Accept requires ALL conditions ─────────────────

  lemma AcceptRequiresAllConditions(
    url: string,
    config: UrlFilterConfig
  )
    ensures IsAccept(FilterUrl(url, config)) ==>
      && MatchesAny(url, config.allowlist)
      && !MatchesAny(url, config.blocklist)
  {}

  // ── Composite: Sufficient conditions for Accept ───────────────

  lemma SufficientForAccept(
    url: string,
    config: UrlFilterConfig
  )
    requires MatchesAny(url, config.allowlist)
    requires !MatchesAny(url, config.blocklist)
    ensures IsAccept(FilterUrl(url, config))
  {}

  // ── Allowlist monotonicity (dual of blocklist) ────────────────
  //
  // Adding an allowlist entry that matches url can turn Reject→Accept
  // (if not blocklisted).

  lemma AllowlistMonotonicity_NewAccept(
    url: string,
    allowlist: seq<UrlPattern>,
    blocklist: seq<UrlPattern>,
    new_pattern: UrlPattern,
    max_rpm: nat
  )
    requires Matches(url, new_pattern)
    requires !MatchesAny(url, blocklist)
    ensures IsAccept(FilterUrl(url, UrlFilterConfig(allowlist + [new_pattern], blocklist, max_rpm)))
  {
    var cfg := UrlFilterConfig(allowlist + [new_pattern], blocklist, max_rpm);
    assert Matches(url, cfg.allowlist[|allowlist|]);
    assert MatchesAny(url, cfg.allowlist);
  }

  // ── Pattern matching correctness lemmas ───────────────────────

  lemma PrefixMatchCorrect(url: string, prefix: string)
    requires StartsWith(url, prefix)
    ensures Matches(url, Prefix(prefix))
  {}

  lemma SuffixMatchCorrect(url: string, suffix: string)
    requires EndsWith(url, suffix)
    ensures Matches(url, Suffix(suffix))
  {}

  lemma ExactMatchCorrect(url: string, exact: string)
    requires url == exact
    ensures Matches(url, Exact(exact))
  {}

  lemma AnyMatchesEverything(url: string)
    ensures Matches(url, Any)
  {}

  // ── Prefix matching properties ────────────────────────────────

  lemma PrefixReflexive(s: string)
    ensures StartsWith(s, s)
  {}

  lemma PrefixEmpty(s: string)
    ensures StartsWith(s, "")
  {}

  lemma SuffixReflexive(s: string)
    ensures EndsWith(s, s)
  {}

  lemma SuffixEmpty(s: string)
    ensures EndsWith(s, "")
  {}

  // =========================================================================
  // INTEGRATION TESTS - full lifecycle verification
  // =========================================================================

  method TestBasicAllowlistAccept()
  {
    var cfg := UrlFilterConfig(
      [Prefix("https://")],
      [],
      60
    );
    var filter := new UrlFilter(cfg);
    assert filter.Valid();

    // HTTPS URL should be accepted
    var d := filter.check_url("https://example.com");
    assert IsAccept(d);
    assert filter.request_count == 1;
    assert |filter.audit_log| == 1;
  }

  method TestBlocklistRejects()
  {
    var cfg := UrlFilterConfig(
      [Prefix("https://")],
      [Suffix(".onion")],
      60
    );
    var filter := new UrlFilter(cfg);

    // .onion URL matches blocklist - must be rejected (P23, P24)
    var d := filter.check_url("https://evil.onion");
    assert IsReject(d);
    assert filter.request_count == 0;  // rejected, not counted
    assert |filter.audit_log| == 1;
  }

  method TestNotInAllowlist()
  {
    var cfg := UrlFilterConfig(
      [Prefix("https://")],
      [],
      60
    );
    var filter := new UrlFilter(cfg);

    // HTTP (not HTTPS) not in allowlist - must be rejected (P22)
    var d := filter.check_url("http://example.com");
    assert IsReject(d);
    assert filter.request_count == 0;
  }

  method TestEmptyAllowlist()
  {
    var cfg := UrlFilterConfig(
      [],
      [],
      60
    );
    var filter := new UrlFilter(cfg);

    // Empty allowlist - nothing passes (P26)
    var d := filter.check_url("https://example.com");
    assert IsReject(d);
  }

  method TestBlocklistPrecedence()
  {
    // URL matches BOTH allowlist (Prefix https://) AND blocklist (Suffix .gov)
    var cfg := UrlFilterConfig(
      [Prefix("https://")],
      [Suffix(".gov")],
      60
    );
    var filter := new UrlFilter(cfg);

    var d := filter.check_url("https://example.gov");
    assert IsReject(d);  // P24: blocklist wins
  }

  method TestRateLimiting()
  {
    // max 2 requests per minute
    var cfg := UrlFilterConfig(
      [Any],  // accept everything
      [],
      2
    );
    var filter := new UrlFilter(cfg);
    assert filter.Valid();

    var d1 := filter.check_url("https://a.com");
    assert IsAccept(d1);
    assert filter.request_count == 1;

    var d2 := filter.check_url("https://b.com");
    assert IsAccept(d2);
    assert filter.request_count == 2;

    // Third request exceeds limit (P29)
    var d3 := filter.check_url("https://c.com");
    assert IsReject(d3);
    assert filter.request_count == 2;  // unchanged on reject

    // After reset (P32)
    filter.reset_rate_limit();
    assert filter.request_count == 0;
    assert |filter.audit_log| == 3;  // audit preserved

    var d4 := filter.check_url("https://d.com");
    assert IsAccept(d4);
    assert filter.request_count == 1;
  }

  method TestAuditCompleteness()
  {
    var cfg := UrlFilterConfig(
      [Prefix("https://")],
      [Suffix(".onion")],
      60
    );
    var filter := new UrlFilter(cfg);

    // Three checks: accept, reject (blocklist), reject (not allowlisted)
    var d1 := filter.check_url("https://good.com");
    assert |filter.audit_log| == 1;
    assert filter.audit_log[0].url == "https://good.com";
    assert IsAccept(filter.audit_log[0].decision);

    var d2 := filter.check_url("https://evil.onion");
    assert |filter.audit_log| == 2;
    assert filter.audit_log[1].url == "https://evil.onion";
    assert IsReject(filter.audit_log[1].decision);

    var d3 := filter.check_url("ftp://files.com");
    assert |filter.audit_log| == 3;
    assert filter.audit_log[2].url == "ftp://files.com";
    assert IsReject(filter.audit_log[2].decision);

    // Previous entries unchanged (append-only, P30)
    assert filter.audit_log[0].url == "https://good.com";
    assert filter.audit_log[1].url == "https://evil.onion";
  }

  method TestMultiplePatterns()
  {
    var cfg := UrlFilterConfig(
      [Prefix("https://"), Prefix("http://localhost")],
      [Suffix(".onion"), Suffix(".mil")],
      60
    );
    var filter := new UrlFilter(cfg);

    // HTTPS - accepted via first allowlist pattern
    var d1 := filter.check_url("https://example.com");
    assert IsAccept(d1);

    // localhost - accepted via second allowlist pattern
    var d2 := filter.check_url("http://localhost:8080");
    assert IsAccept(d2);

    // .mil - rejected via second blocklist pattern
    var d3 := filter.check_url("https://secret.mil");
    assert IsReject(d3);

    // .onion - rejected via first blocklist pattern
    var d4 := filter.check_url("https://hidden.onion");
    assert IsReject(d4);
  }

  method TestExactMatch()
  {
    var cfg := UrlFilterConfig(
      [Exact("https://api.example.com/v1")],
      [],
      60
    );
    var filter := new UrlFilter(cfg);

    // Exact match - accepted
    var d1 := filter.check_url("https://api.example.com/v1");
    assert IsAccept(d1);

    // Different URL - rejected (P22)
    var d2 := filter.check_url("https://api.example.com/v2");
    assert IsReject(d2);
  }

  method TestConfigImmutability()
  {
    // P33: config never changes
    var cfg := UrlFilterConfig(
      [Prefix("https://")],
      [Suffix(".onion")],
      10
    );
    var filter := new UrlFilter(cfg);

    var _ := filter.check_url("https://a.com");
    assert filter.config == cfg;

    var _ := filter.check_url("https://evil.onion");
    assert filter.config == cfg;

    filter.reset_rate_limit();
    assert filter.config == cfg;
  }

  method TestFullLifecycle()
  {
    // Comprehensive lifecycle matching VERIFICATION.json spec for web_browsing
    var cfg := UrlFilterConfig(
      [Prefix("https://"), Prefix("http://localhost")],
      [Suffix(".onion"), Suffix(".gov"), Suffix(".mil")],
      60
    );
    var filter := new UrlFilter(cfg);
    assert filter.Valid() && filter.request_count == 0 && filter.audit_log == [];

    // ── Allowed URLs ──────────────────────────────────────────
    var a1 := filter.check_url("https://example.com");
    assert IsAccept(a1);

    var a2 := filter.check_url("https://api.service.io/data");
    assert IsAccept(a2);

    var a3 := filter.check_url("http://localhost:3000/api");
    assert IsAccept(a3);

    assert filter.request_count == 3;

    // ── Blocked by blocklist (P23, P24) ───────────────────────
    var b1 := filter.check_url("https://hidden.onion");
    assert IsReject(b1);

    var b2 := filter.check_url("https://secret.gov");
    assert IsReject(b2);

    var b3 := filter.check_url("https://classified.mil");
    assert IsReject(b3);

    assert filter.request_count == 3;  // rejects don't increment

    // ── Blocked by missing allowlist (P22) ────────────────────
    var c1 := filter.check_url("ftp://files.com");
    assert IsReject(c1);

    var c2 := filter.check_url("http://insecure.com");
    assert IsReject(c2);

    assert filter.request_count == 3;

    // ── Audit trail complete (P30) ────────────────────────────
    assert |filter.audit_log| == 8;

    // ── Invariant holds throughout (P31) ──────────────────────
    assert filter.Valid();
  }
}
