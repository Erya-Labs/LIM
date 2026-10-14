# Changelog

All notable changes to **LIM** — the client library for Local Identity Management — are recorded
in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
library intends [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Read the first entry as "what this release contains" rather than "what changed", and the reason
deserves a paragraph instead of a footnote: 1.0.0 is the first release anyone could resolve.**
Before it, the only tag here was `0.1.0`, never published, and the only artifact anywhere was a
`mavenLocal` build that the sibling vault app compiled against. So there was no predecessor release
to diff against and nobody in the field holding an older one — which is why the 1.0.0 entry
describes the surface rather than listing changes. The next entry will be an ordinary changelog.

`ChangelogTest` keeps this file honest in both directions. Forwards: every published function and
constant on `Utils`, every published type in `dev.eryalabs.lim`, and both published top-level
members of `Redaction.kt` must be named below, and every published function must lead a bullet —
alone or beside its siblings, as many do. "Below" is any `## ` section, the `## Unreleased` one
included, because a member added since the last release is described there until a release
heading takes it over. Backwards: every name this file cites in a code span
must either name something this library publishes or be recorded in the test as a name it does not
publish, which is where `Parcelable`, `SecureRandom` and `SHA256withRSA` live. So a bullet left behind
by a rename reddens a test rather than quietly becoming a lie.

What that census does *not* reach is the members of the data types — `Entry`'s properties,
`FieldType`'s eight constants, `StatementVerdict`'s seven verdicts: those are described here in
prose, checked only in the backwards direction, and pinned member-by-member by `PublicApiAuditTest`
and by `LIM/api/lim.api`, which is the record of the binary surface and the right place to read a
diff.

## Unreleased

No version number yet: which release this becomes, and when it is tagged and published, is a human
decision. Everything below is additive — `LIM/api/lim.api` gains lines and loses none.

### Share (sign-up): required and optional fields

A sign-up can now say which of its fields the user may leave blank, a vault can say what it
applied, and both sides share one definition of blank.

- `EXTRA_OPTIONAL_FIELDS` — on a share request, a JSON array naming the entry's fields the user
  may leave blank. **Every declared field not named is required.** Read strictly: anything but one
  flat array of strings means nothing is optional, and nothing is salvaged.
- `EXTRA_APPLIED_OPTIONAL_FIELDS` — on a successful share result only, the optional set the vault
  applied: its acknowledgement. A different key from the request's on purpose, so a vault that
  answers by echoing the request back can never forge it.
- `createShareIntent` — a fourth overload, taking the request code, a set of optional field
  names and the vault's package, with no defaults at all, so no call with fewer arguments can
  reach it. Names that are not fields of the entry as it is sent are not sent either, so a
  misspelt one leaves its field required. The 1.0.0 overloads are unchanged and declare nothing
  optional, so on a vault that implements this every field they send is required.
- `FieldRequirements` — the declared field names, the optional subset and the required rest, and
  the one definition of blank: absent, `null`, or whitespace only. `missingRequired`,
  `isSatisfiedBy` and `committed` — the map to keep, `null` exactly when a required field is
  missing, with blank optional fields dropped. A plain class rather than a data class, and its
  `toString` prints counts only.
- `FieldRequirementsVerdict` — `HONOURED`, `MISMATCHED`, `NOT_ACKNOWLEDGED`, `INCOMPLETE` and
  `VIOLATED`. The first three mean every required field arrived non-blank and the last two mean
  one did not, so the verdict splits exactly on what `committed` says. Callers should keep a
  fallback branch: a later release may add a verdict.
- `parseFieldRequirements` — the vault's side: the entry's field names and the declared optional
  set, read off a share request. `null` exactly when `parseShareRequest` is, and every field
  required when the declaration is absent or unreadable.
- `parseAppliedOptionalFields` — the client's raw reading of the acknowledgement; `null` for none.
- `checkFieldRequirements` — the client's verdict on a sign-up's answer against what it declared.
  Named "check" because nothing in a share result is signed; the acknowledgement is as
  trustworthy as the vault that sent it.
- `createShareResultIntent` — an overload taking the declared `FieldRequirements`, which writes
  the acknowledgement only when the payload satisfies them and otherwise omits it rather than
  throwing. A vault therefore never makes a claim its own answer contradicts.

### Vault behaviour you will see

A vault that implements this requires every field a sign-up declares unless the sign-up named it
optional — **including for an app built against 1.0.0**, which can name none. Users can no longer
skip a field such an app asked for; they fill it in or back out. `parseShareResult` returns the
same `ShareResult` with or without the acknowledgement, so such an app reads the answer exactly as
before.

### Compatibility

- `LIM/api/lim.api` gains 29 lines and loses or changes none. Every existing call resolves as it
  did, in Kotlin and in Java: the 1.0.0 positional trap on `createShareIntent` included, and a
  four-argument call whose fourth argument the compiler has to infer — a literal null, or a
  mocking library's any() — because the new overload has five parameters and no shorter form.
- Two new wire keys; no existing key, action or encoding changes.
- `PROTOCOL_VERSION` stays 2. Every vault echoes the version of the library it was built on, so the
  number cannot say whether a vault implements this; the acknowledgement is the signal instead,
  and the version keeps meaning what it meant to the query and login flows.

## 1.0.0 — 2026-10-10

**Released on Maven Central as `dev.eryalabs.lim:lim:1.0.0`, signed, with sources and javadoc.**
The date is the one Central itself records for the publication, in UTC. Tag `1.0.0` marks the
commit it was built from. `ChangelogTest` ties the two together: a version heading carries a date
exactly when a git tag of that version exists, and says `unreleased` exactly when one does not — so
the next version's heading starts out `unreleased` and cannot be dated before it is cut. The
version number itself is read out of `LIM/build.gradle.kts`'s `coordinates(...)` call, so a bump
there reddens this file as well as `docs/INTEGRATION.md`.

The protocol generation is `PROTOCOL_VERSION` = 2. Version 1 is the implicit legacy protocol:
nothing on the wire ever says "1" — absence says it instead.

### The shared vocabulary

- `Entry` — the `Parcelable` profile a client pushes to a vault: an id, a public key, and a map of
  named `TypedField` values. Its `toString()` prints the *shape* of the data rather than the data.
- `TypedField` — one value plus the datatype it claims, so a client can tell a date from a string
  without guessing.
- `FieldType` — the eight datatype names a `TypedField` may claim (`STRING`, `EMAIL`, `PHONE`,
  `DATE`, `INTEGER`, `DECIMAL`, `BOOLEAN`, `URL`), the `FieldType.KNOWN` set, and `normalize` for
  folding an unrecognised or differently-cased claim to a known one. An unknown type is not an
  error: the protocol carries it through.
- `encodeFields` / `decodeFields` — the JSON codec for a `Map<String, TypedField>` as it travels on
  an intent extra. `decodeFields` is a trust boundary: Gson builds objects through `Unsafe` without
  running the Kotlin constructor, so it repairs what a hostile or buggy peer sends instead of
  handing back an object that throws when read.
- `decodeEntry` — the same guarantee for an `Entry` arriving as JSON. Use it rather than a raw
  `fromJson` on `EXTRA_ENTRY_JSON`.
- `validateEntry` — the human-readable problem list for an `Entry` about to be shared: a missing
  or blank id, a public key that is absent or is not parseable Base64 or is not an RSA key, empty
  fields, and a field whose name is blank. A list, not a boolean, because an integrator has to be
  told which.
- `PROTOCOL_VERSION` and `EXTRA_PROTOCOL_VERSION` — the version a client declares on every outgoing
  request and the key it travels under. A vault that understands it echoes its own version into the
  result; one that does not echoes nothing, and parses as the legacy vault it is rather than as a
  modern one by default.
- `DEFAULT_ENDEAVOR_PACKAGE` — Endeavor's package name, the `targetPackage` default of every request
  builder. A default, not a hardcoding: any vault that speaks the protocol can be addressed by
  passing its own package. Both action strings are built from it, so a client and a vault that
  disagree about the package disagree about the action too.
- `matchesRequestCode` and `EXTRA_SHARE_REQUEST_CODE` — the client-chosen correlation token, echoed
  by the vault in every result. Compare with the function and not by hand: a blank must never match,
  and "nothing equals nothing" is what pairs a client with the answer to somebody else's request.
- `EXTRA_PUBLIC_KEY` — the Base64 X.509 RSA key a flow is about, and the account identifier the
  whole design rests on. Carried on a query request, a sign-challenge request, a share result and a
  query result; **not** on a sign-challenge result, where the proof is the signature checked against
  the key the client already stores.

### Share (sign-up)

The client hands a vault a new profile and gets back the public key it was stored under.

- `shareDataAction` — the action string for the share and query flows, scoped to the target package.
- `createShareIntent` — builds the request, carrying the `Entry` as JSON under `EXTRA_ENTRY_JSON`,
  with an optional correlation token.
- `shareEntry` — build-and-start in one call. Returns `false` when nothing handled the intent; that
  `false` cannot distinguish "no vault installed" from "not allowed to look", because Android 11+
  package visibility is the caller's manifest to declare.
- `parseShareRequest` — the vault's side, returning a `ShareRequest` (the entry, the correlation
  token, the client's declared protocol version). The *presence* of `EXTRA_ENTRY_JSON` is also how a
  vault routes: share and query travel under one action, and an intent carrying that extra is a
  share.
- `parseShareResult` — the client's side, returning a `ShareResult`. The value to keep off it is the
  public key: that is the handle this profile is queried and authenticated by from now on.

### Query

The client asks for specific fields of a profile it already has a key for. Nothing in a query is
signed; it is a disclosure, under per-disclosure user consent at the vault.

- `createQueryIntent` — the request, carrying the public key and a correlation token, under the same
  action as a share and deliberately without an entry.
- `parseQueryRequest` — returns a `QueryRequest`, and refuses an intent that carries
  `EXTRA_ENTRY_JSON` — that one is a share.
- `parseQueryResult` — returns a `QueryResult`, whose fields arrive under
  `EXTRA_QUERY_RESULT_FIELDS`. That key is deliberately not `EXTRA_FIELDS_JSON`: reading either from
  either flow would let an unsigned query answer be presented as a disclosure that came with a
  signature.

### Sign-challenge (login)

The client proves the user still holds the private key behind a public key it stored earlier, by
having the vault sign a nonce.

- `generateNonce` — an 8-byte big-endian millisecond timestamp followed by 32 random bytes. Both
  the clock and the `SecureRandom` are injected parameters, so a test can pin them. The random half
  makes the challenge unguessable; the timestamp half is what lets it expire.
- `isNonceFresh` — expires a nonce by reading the timestamp out of the nonce itself, so a client
  stores no state to replay-protect a login.
- `nonceTimestamp` — the timestamp alone, for a peer that wants to read the header.
- `EXTRA_NONCE_FORMAT` and `NONCE_FORMAT_TIMESTAMPED` — an optional declaration that the nonce has
  `generateNonce`'s layout. It exists for the vault's benefit: a vault cannot enforce freshness
  across the board without breaking every client whose hand-rolled nonce carries no timestamp, and a
  client that declares its format volunteers exactly the fact the vault is missing. Declare it only
  for a nonce that genuinely has that shape.
- `createSignChallengeIntent` and `signChallengeAction` — the request and its action string,
  carrying the challenge under `EXTRA_NONCE`.
- `parseSignChallengeRequest` — returns a `SignChallengeRequest`: the key, the nonce bytes, the
  declared nonce format, the correlation token.
- `parseSignChallengeResult` — returns a `SignChallengeResult`, carrying the signature from
  `EXTRA_SIGNATURE` and the disclosed fields from `EXTRA_FIELDS_JSON`. **Parsed is not
  authenticated.**
- `SignChallengeResult.isVerified` and `verifySignature` — the verification the library's security
  rests on, `SHA256withRSA` over the nonce bytes against the stored key. `verifySignature` returns
  `false` for every malformed *value* — a key that is not Base64, a key that is not RSA, a
  signature over the wrong bytes — rather than throwing. Its three parameters are declared
  non-null, though, so a Java caller handing it the `null` an absent extra reads as gets a
  `NullPointerException` instead of a fail-closed `false`: null-check the extra.
- `EXTRA_ALGORITHM` — what the vault says it signed with. **Informational only**: nothing here
  honours it, because taking the verification algorithm from the sender is algorithm confusion. A
  declaration of `MD5withRSA` changes no outcome, and neither does a correct one. For the same
  reason this library publishes no algorithm constant to put there.
- `isStatementPreImage` — **a vault must call this on an incoming nonce and refuse a match.** The
  sign-challenge flow signs arbitrary caller-supplied bytes with a profile's key, and those bytes
  could be a signed statement's pre-image — a rotation authorizing an attacker's key, obtained under
  a consent dialog that said "prove your identity". The signing device is the only place that check
  can be made; no verifier can tell the two signatures apart afterwards. A nonce from
  `generateNonce` never matches.

### Result building (the vault side)

Six functions for the half of the wire format that previously existed only as the expectations of
the three result parsers above, so every vault hand-assembled its result intents.

- `createShareResultIntent`, `createQueryResultIntent`, `createSignChallengeResultIntent` — each in
  two forms: one taking the values directly, one taking the parsed request so the correlation token
  is carried across for you.
- Three rules they enforce, each one a thing a hand-written `putExtra` gets wrong eventually. A
  result carries no action and no package, because it is `setResult`'s payload. A blank value is
  omitted rather than written, because `putExtra(key, null as String?)` leaves the extra *present*.
  And the protocol-version echo is unconditional, so a vault using these cannot forget the one
  thing that tells a client its request was understood.
- **The request is read, never retained.** The only value the request-answering forms take off a
  request is the correlation token — not its public key, not its entry, not its field names. A query
  request's key is the key the *caller* chose to ask about; the key a result must name is the one the
  *vault* holds.

### Statements and migration

Signed statements are how a public key stops being permanent: a key can be rotated, a recovery key
authorized, and an authorization revoked, each as a self-contained signed document a service can
verify offline with no call to the vault.

- `RotationStatement`, `RecoveryAuthorization`, `Revocation` — the three documents, and
  `SignedStatement` — the sealed envelope type a parse returns, as `SignedStatement.Rotate`,
  `SignedStatement.Recover` or `SignedStatement.Revoke`.
- `rotationStatementBytes`, `recoveryAuthorizationBytes`, `revocationBytes` — the canonical
  pre-image a signature is computed over. Domain-separated by `STATEMENT_DOMAIN_V1` and then by
  `STATEMENT_ROTATE_V1`, `STATEMENT_RECOVER_V1` or `STATEMENT_REVOKE_V1`, so a signature over one
  kind of statement can never be replayed as another.
- `verifyRotationStatement`, `verifyRecoveryAuthorization`, `verifyRevocation` — verification
  returning a `StatementVerdict` rather than a boolean: `VALID`, `SIGNATURE_INVALID`, `SAME_KEY`,
  `NEW_KEY_UNUSABLE`, `EXPIRED`, `NOT_YET_VALID`, `WRONG_SUBJECT`. A service that only logged
  "invalid" would lose the one distinction that tells a configuration mistake from an attack.
  `verifyRotationStatement` takes the clock as a parameter so expiry is testable.
- `isRevoked` and `liveAuthorizations` — the revocation check for one authorization and the filter
  for a list of them. A revocation cancels an authorization only when its own sequence number is
  **strictly greater** than the authorization's: that is what lets a revoked device be
  re-authorized at a higher sequence, and what makes a captured older revocation useless against a
  newer authorization.
- `encodeRotationStatement`, `encodeRecoveryAuthorization`, `encodeRevocation` and
  `parseSignedStatement` — the transport envelope, versioned by `STATEMENT_ENVELOPE_V1`: a text
  form a statement can travel in over any channel, with `parseSignedStatement` returning `null` for
  anything malformed.

### Diagnostics

- `describeIntent` — a one-line, redaction-safe summary of a LIM intent: which extras are present,
  which flows it could be, and nothing a log reader could act on. It accepts `null`, because the
  moment you want it is the moment something has gone wrong.
- `previewedPublicKey` and `PUBLIC_KEY_PREVIEW_CHARS` (top-level in `Redaction.kt`) — a public key
  truncated but still identifiable in a log line, and the width it is truncated to. Published so the
  vault app can render a key the same way the client does; two copies of a format is one copy that
  drifts. The first 44 characters of a 2048-bit X.509 RSA key in Base64 are a fixed DER header,
  identical for every user on earth, which is why the width is 64 and not a token 8.

### Java interop

Every defaulted function on `Utils` except one carries `@JvmOverloads`, so a Java caller writes the
short forms rather than passing defaults by hand. `Utils` is a Kotlin `object`, so Java reaches it
through `Utils.INSTANCE`; it is deliberately **not** `@JvmStatic`, because on a named object that
annotation replaces the instance method instead of adding to it and would break every already
compiled consumer.

### Not in this release

- `EXTRA_ALGORITHM` is written and read but never honoured; which signature algorithms to accept is
  a deliberate decision about an allow-list and has not been made.
- There is no vault discovery. A client addresses a vault by package name, defaulting to Endeavor;
  finding every installed app that handles the share action needs a manifest change.
- This entry is not a comparison against an earlier release, because 1.0.0 is the first. See
  `LIM/api/lim.api` for the surface as it stands at this commit.
