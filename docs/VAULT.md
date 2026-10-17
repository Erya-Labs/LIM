# Writing a vault

This page is for the other half of the wire. If you are integrating LIM into an app that *asks*
for someone's details, [INTEGRATION.md](INTEGRATION.md) is your page; this one is for an app that
**holds** them and answers those requests.

A vault is the app the data never leaves. It keeps the profile encrypted on the device, it mints
and keeps the keypair, and it decides — with the user in front of it — what to disclose and what
to sign. Everything it receives arrives as an `Intent` from another app on the same device, which
means every byte of it is hostile input: any installed app can fire an intent at an exported
activity, and nothing on the way in has been authenticated by anybody.

So this page starts with reading. The three functions below are a vault's entire entry point —
`parseShareRequest`, `parseQueryRequest` and `parseSignChallengeRequest` — and the reason to call
them instead of reading extras by hand is that they are the same code the client half is pinned
against. A vault that hand-reads `extra_entry_json` has made a private copy of the wire format,
and private copies drift.

**Every Kotlin block on this page is lifted verbatim out of a test that runs.** The HTML comment
above each block names the region it came from, in `VaultGuideExamplesTest`, and `GuideSnippetTest`
fails if the two ever drift — or if the region is not inside a function JUnit executes. So nothing
here is prose that compiled once.

This page covers a vault's whole turn: reading a request, answering it, refusing — and then the
things a vault has to *do*, which *What a vault must do* collects at the end. Every one of those
obligations was published before this page existed — in the KDoc of the functions above, in
`CHANGELOG.md`, or in the client's guide; what that section adds is having them in one place, each
beside a test that would notice if a vault here stopped honouring it.

---

## What a vault answers for

Three flows reach a vault, and they are not variations on one thing. Each has a different question
for the user and a different thing at stake.

**Sign-up (share).** A client pushes a profile template — field names and declared types, with the
values left empty — and asks the user to fill it in. The vault stores what the user typed, mints
the keypair for that profile, and answers with the public key. *That key is the account*, for ever
after: the client has nothing else to identify the profile by, and nothing else it is allowed to
use. The private half stays in the vault and is never part of any answer.

**Query.** A client names a public key it already holds and asks for fields of that profile. This
is the flow the whole design exists for — a service that needs an email address for one message
asks for an email address, once, and gets exactly that. A query request is **not an entitlement**:
it says somebody asked, and what is disclosed is the user's consent decision, made in the vault's
own UI. Refusal is a first-class answer, not an error.

**Login (sign-challenge).** A client sends a nonce it generated and asks the vault to sign it with
the private key of a named profile. A signature over fresh bytes proves the holder of that key is
present on this device right now, which is what logging in means in this protocol. It is also the
one flow where a careless vault can do real harm: whatever bytes arrive are bytes the vault is
being asked to sign with a key that authorises things, so what is signed and what is refused are
decisions the vault owns.

What is common to all three is the shape of the answer: the vault sets a result code and a result
intent, and the client reads it back with this same library. What is common to all three *requests*
is that the vault must assume nothing about who sent them.

---

## Routing an incoming request

Read the action first. It is the only thing that separates a login from the other two, and it is
the cheapest check available — a request whose action is not one of yours was not addressed to you.

Both actions are derived from a package name rather than fixed, so a client and a vault that
disagree about which package the vault is installed under resolve nothing at all. Pass your own
package name in; do not write the string out.

<!-- snippet: VaultGuideExamplesTest.kt#vault-routing -->
```kotlin
// A request reaches a vault as an `Intent` on an exported activity, and the action is the
// first thing to read. Exactly two actions address a vault, and both are scoped to the
// vault's own package name — a client that disagrees about the package resolves nothing,
// so pass your own package and never a hard-coded string.
fun flowOf(incoming: Intent, myPackage: String): String = when (incoming.action) {
    // Sign-up and query both travel under this one. The action does not tell them apart;
    // the payload does, and reading it is the next step.
    Utils.shareDataAction(myPackage) -> "a share or a query"
    // Login carries one flow only, so this arm needs no further disambiguation.
    Utils.signChallengeAction(myPackage) -> "a sign-challenge"
    // Anything else was not addressed to this vault. Answer nothing.
    else -> "not ours"
}
```

That leaves one ambiguity, and it is deliberate: **a share and a query travel under the same
action.** They are told apart by their payload. An intent carrying an entry payload is a share; an
intent carrying a public key and no entry payload is a query.

Do not read that payload yourself. The two parsers already encode the rule, in both directions —
`parseQueryRequest` refuses an intent that carries an entry payload for exactly this reason — so
no intent can parse as both, and asking both of them is the disambiguation.

<!-- snippet: VaultGuideExamplesTest.kt#vault-share-or-query -->
```kotlin
// A share and a query arrive under the same action, so what tells them apart is the
// payload — never a hand-read extra, and never the order they happened to arrive in.
// Hand the intent to both parsers: no intent parses as both, because one carrying an
// entry payload is a share and `parseQueryRequest` refuses it for exactly that reason.
val share = Utils.parseShareRequest(incoming)
val query = Utils.parseQueryRequest(incoming)
// Both `null` is the fail-closed arm, and it is the common one: a missing or malformed
// entry payload, a blank public key, an entry whose identity `decodeEntry` refused. Any
// app on the device can fire an intent at an exported activity, so there is nothing here
// to show a user or to ask them to consent to. Answer nothing.
```

Both `null` is not a rare case to handle for completeness. It is what a vault sees when an app
fires a malformed intent at it, and the correct response is to show the user nothing and answer
nothing. A parser here never throws, so there is no exception to swallow and no reason to catch.

The sign-challenge arm has its own parser, `parseSignChallengeRequest`, which also does the Base64
nonce decoding that every vault used to do by hand — including refusing a nonce that decodes to
zero bytes, which Android's decoder will happily produce out of junk rather than rejecting it.

---

## Reading a share request

`parseShareRequest` is where a sign-up becomes something a vault can put on screen. What it returns
is already safe: the entry inside it went through `decodeEntry`, which repairs the shapes that can
be repaired and refuses the ones that cannot. So `fields` is never `null` on a parsed request, and
an entry with no identity — or a blank one — never reaches you at all.

That refusal is worth being precise about, because it is the hazard this library exists to close.
Gson builds objects through `Unsafe` without running the Kotlin constructor, so a payload of `{}`
decodes to an `Entry` whose `id`, `fields` and `publicKey` are all genuinely `null` at runtime
despite being declared non-null — and Kotlin inserts no check when reading its own non-null
property. A vault that calls `Gson().fromJson` itself gets that object and crashes on first use.
A vault that calls `parseShareRequest` gets `null` and shows nothing.

<!-- snippet: VaultGuideExamplesTest.kt#vault-share-request -->
```kotlin
// `parseShareRequest` is a vault's whole entry point for a sign-up, and it is the only
// hostile-input handling there is to write: it returns `null` instead of throwing, and
// what it does return is safe to dereference. Gson builds an entry without running the
// Kotlin constructor, so a payload of `{}` decodes to one whose three non-null
// properties are all null at runtime — `decodeEntry` refuses that outright, and repairs
// the shapes that can be repaired, so `fields` here is never null.
fun fieldsToAskFor(incoming: Intent): List<String>? {
    val request = Utils.parseShareRequest(incoming) ?: return null
    // `requestCode` is the correlation token to echo back in the result; `null` means the
    // client attached none. `protocolVersion` is `null` when the client declared nothing
    // usable, which means "it did not say" and never "version 1 confirmed".
    return request.entry.fields.keys.toList()
}
```

Three things on the parsed request are the vault's to use and not to trust:

- **`entry.fields`** is the form to show — one row per key, in the order the client sent, each with
  a declared type the vault may use to pick a keyboard or a date picker. The *values* a client
  sends on a sign-up are empty; the user types them.
- **`entry.publicKey`** is a placeholder on a first sign-up. The real key is the one the vault
  mints and returns. Do not store the client's.
- **`requestCode`** is an opaque correlation token. Echo it back in the result so the client can
  tell which request this answers; `null` means the client attached none. It is correlation and
  never authentication — any app can write that extra.

A fourth, `protocolVersion`, is what the client *declared*. `null` means it declared nothing
usable, which is what an older client sends; it never means "version 1 confirmed".

### Which fields the user may leave blank

A client may mark some sign-up fields optional. Every field it does not mark is required, and
`parseFieldRequirements` is how a vault reads that declaration — answered off the same parse, so a
declaration can never be attached to an entry it did not arrive with.

<!-- snippet: VaultGuideExamplesTest.kt#vault-field-requirements -->
```kotlin
// Which rows the user may leave blank is the client's declaration, and
// `parseFieldRequirements` is the way to read it. It answers off the same parse
// `parseShareRequest` makes, so a declaration can never be paired with an entry it did
// not travel with, and it is `null` in exactly the cases that parser is — there is no
// share request to read requirements off.
val requirements = Utils.parseFieldRequirements(incoming)
// One form row per `fieldNames`, in the entry's own order; `requiredFields` are the ones
// that block Save. A declaration that is absent, blank, malformed or wrong-typed reads as
// **every field required** — the same answer an app built before this extra existed gets
// — so there is no "the client said nothing, so anything goes" arm to write.
val rows = requirements?.fieldNames.orEmpty()
val blocking = requirements?.requiredFields.orEmpty()
```

**The direction of the default is the thing to get right.** Absent, blank, malformed, wrong-typed
and unreadable all mean *every field is required* — the same answer a client built before the
declaration existed gets. A vault that read an unreadable declaration as "nothing is required"
would let the user save an empty profile and then answer a client that had asked for a full one,
which is a false claim on the wire rather than a lenient one.

Two more properties of the declaration, both of which mean a vault has less to defend against than
it might expect: names the entry does not itself declare are dropped, so a client cannot mark a
field optional that it never asked for; and nothing in this library bounds the declaration's size,
because only the entry's own field names survive reading it.

`FieldRequirements` is the same object the client built, so `missingRequired` is literally the same
Save gate on both sides of the wire rather than two implementations that have to agree.

---

## Answering a request

An answer is two things: a **result code** and a **result intent**. `RESULT_OK` with an intent the
client can read is an answer; `RESULT_CANCELED` is a refusal. Nothing in the payload says which one
it is, so a vault that forgot the result code has sent an answer the client is right to throw away.

Each flow has its own builder, and they are **not interchangeable**. A sign-up answer carries its
fields under `extra_fields_json`; a query answer carries its disclosure under
`extra_query_result_fields`. Answer a query with the share builder and the client's
`parseQueryResult` finds no fields at all — a disclosure that reads as "nothing released" —
because those two keys are separate points in the protocol on purpose. `ResultBuilderTest > a
result built for one flow discloses no fields to the other` pins the separation in both
directions; choosing between the two by hand is the mistake these functions exist to remove.

Each of the three has an overload that takes the **parsed request**, and that is the one to call. It
carries the correlation token across for you — the one value it reads off the request — so the
token cannot be mistyped or dropped. Everything else stays explicit, and that is a rule rather
than an oversight: the key and the fields in an answer are the *vault's*, and a builder that
echoed the request's own would let the calling app decide what its answer says about it.

<!-- snippet: VaultGuideExamplesTest.kt#vault-answer-share -->
```kotlin
// The answer to a sign-up is the key this vault minted for the new profile and the
// fields it stored. Hand the parsed request to the overload that takes one: it carries
// the correlation token across, which is the only value it reads off the request. The
// key and the fields stay explicit because they are the vault's — a builder that echoed
// the request's own would let the client decide what its answer says.
val answer = Utils.createShareResultIntent(
    request,
    publicKey = storedKey,
    fields = heldProfile,
)
// Then `setResult(Activity.RESULT_OK, answer)` and finish. The result code is what makes
// this an answer rather than a refusal; nothing in the payload says which it is.
```

The key in that answer *is* the account, from here on. The client has nothing else to identify the
profile by, so a vault that answered with the placeholder key from the request would hand the
client an identifier it cannot authenticate against later.

A query answer is the disclosure the user consented to, which may be a subset of what the vault
holds — consent is per disclosure in this protocol, so one field of three is a complete answer.

<!-- snippet: VaultGuideExamplesTest.kt#vault-answer-query -->
```kotlin
// A query is answered with what the user released at the consent dialog, which may be
// less than the profile holds: consent is per disclosure, so one field of three is a
// complete answer rather than a partial one. An empty map is a legitimate answer too —
// "nothing disclosed" is not the same as not answering.
val answer = Utils.createQueryResultIntent(request, publicKey = storedKey, fields = released)
// The key is still passed explicitly, and this is the flow that rule exists for: the
// request's own key is the one the *caller* chose to ask about, so echoing it would let
// the caller name the profile its own disclosure claims to come from.
```

A login answer is a signature, and it is the one answer with cryptography in it. The bytes to sign
are the nonce the request carried, read off the parsed request rather than off the extras; the key
is the private half the vault minted for that profile. **This library never holds a private key,
never sees one and signs nothing** — the builder writes what the vault says it signed, and the
client's own verification is what decides whether that is true.

<!-- snippet: VaultGuideExamplesTest.kt#vault-answer-login -->
```kotlin
// A login is answered with a signature over the nonce the request carried. The bytes to
// sign come off the parsed request; the key is the one this vault minted for the named
// profile — a Keystore handle in a real vault, and never anything this library holds.
fun answerLogin(incoming: Intent, profileKey: PrivateKey): Intent? {
    val request = Utils.parseSignChallengeRequest(incoming) ?: return null
    // The check a signing device owes every signature it makes, and the reason this is
    // not a two-line function: these bytes are whatever the caller chose, and they could
    // be the pre-image of a statement this key authorises rather than a login challenge.
    // Get one signed under a "prove your identity" dialog and the answer is a valid key
    // rotation. Only this side can tell the two apart, and nothing in LIM refuses on a
    // vault's behalf — the parser hands the bytes over and this is the call that stops.
    if (Utils.isStatementPreImage(request.nonce)) return null
    val algorithm = "SHA256withRSA"
    val signature = Signature.getInstance(algorithm).run {
        initSign(profileKey)
        update(request.nonce)
        sign()
    }
    // `algorithm` is informational and is honoured by nothing: the client's verification
    // hardcodes `SHA256withRSA`, because taking the algorithm from the sender is how
    // algorithm confusion gets in. Declare it for a reader, not for a verifier.
    return Utils.createSignChallengeResultIntent(request, signature, heldProfile, algorithm)
}
```

The field payload rides along with the proof, under the share flow's key. It is always written,
even empty: a vault cannot opt out by omission, so disclosing nothing on a login means sending an
empty payload rather than no payload.

**The refusal in the middle of that function is not optional.** A nonce is caller-chosen bytes,
and the pre-image of a signed statement — a key rotation, a recovery authorization, a revocation —
is exactly such bytes. A vault that signs one has answered a "prove your identity" dialog with a
valid rotation of the user's key. `Utils.isStatementPreImage` is published for this and for
nothing else, and **nothing in this library refuses such a nonce on your behalf**:
`parseSignChallengeRequest` hands the bytes over, the obligation is the protocol's and the
enforcement is yours. `ClientIntegrationExampleTest > the vault refuses to sign a statement
pre-image handed to it as a challenge` is the same property over a different vault, with the
attack written out.

### Acknowledging the optional-fields declaration

A vault that enforces the declaration it read with `parseFieldRequirements` says so — on the
answer, and only there. There is nothing on the request to echo: the acknowledgement is a claim
about what this vault did, which is why the builder writes it only when the payload satisfies the
declaration.

<!-- snippet: VaultGuideExamplesTest.kt#vault-answer-optional -->
```kotlin
// A vault that enforces the optional-fields declaration says what it enforced, and says
// it on the answer only — there is no extra on the request to echo back. `committed` is
// the Save gate and the payload in one: it is `null` exactly while a required row is
// still blank, and it drops the optional rows the user left empty rather than storing
// them as blank values.
val stored = declared.committed(draft)
// The acknowledgement rides on this overload, which has no request-taking sibling — pass
// the token off the parsed request yourself. It writes the acknowledgement only when the
// payload satisfies the declaration, so the answer can never claim more than it carries.
val answer = stored?.let {
    Utils.createShareResultIntent(storedKey, it, request.requestCode, declared)
}
```

This is the one builder with no request-taking sibling, so the correlation token is passed by
hand — off the parsed request, not re-typed. What the client makes of the acknowledgement is
`checkFieldRequirements`, which answers `HONOURED` for the answer above and `NOT_ACKNOWLEDGED` for
an equally complete answer carrying no acknowledgement. Neither reading is an error: a vault that
ignores the declaration and requires every field is a correct vault, and the client's verdict
exists to tell the two apart rather than to grade them.

---

## Refusing

Refusal is a first-class answer. The user declined, or this vault holds no such profile, or the
request named a key it does not have — and in every one of those cases the answer is
`RESULT_CANCELED` with the correlation token echoed back, and nothing else.

<!-- snippet: VaultGuideExamplesTest.kt#vault-refusal -->
```kotlin
// Refusal is a first-class answer — the user declined, or this vault holds no such
// profile — and it is the one answer no builder here mints. Two lines: the result code,
// and the correlation token echoed back. Not an empty intent, because correlation has to
// survive a refusal or the client cannot tell which request was refused.
val refusalCode = Activity.RESULT_CANCELED
val refusal = Intent().apply {
    request.requestCode?.let { putExtra(Utils.EXTRA_SHARE_REQUEST_CODE, it) }
}
// `setResult(refusalCode, refusal)` and finish. Attach nothing else: no reason, no
// status, no version echo. A refusal that said why would also be saying that something
// on this side understood the request, and that is a disclosure of its own.
```

**The token is the one thing a refusal must carry.** Drop it and the client is holding a refusal it
cannot attribute to a request, which is worse than it sounds: correlation is what stops a handler
acting on an answer meant for a different request.

**There is no refusal builder, and that is deliberate for now rather than settled.** Every result
builder in this library attaches `extra_protocol_version` unconditionally — the echo is the point
of them, since it is what lets a client tell a current vault from a legacy one that ignored what it
did not understand. A refusal honoured nothing, so routing one through a builder would attach a
version to it, which changes what a refusal says on the wire: it would tell the caller that
something on this side understood the request. Whether that bit is worth paying for — and whether
LIM should publish a `createDeclinedResultIntent` so the shape is built rather than hand-written —
is an open protocol question, recorded for a human alongside the broader question of whether a
refusal may carry a *reason* at all. This page describes today's shape and does not pre-empt that
decision.

Say nothing more than the code. A refusal that distinguished "the user declined" from "no such
profile" would tell every caller that a profile exists for every key it is *not* told that about,
which is the disclosure the client's own guide warns integrators not to read into a refusal.

**The limit of everything in this section.** What is above is the *shape* of an answer, not a
vault's policy. What the user is asked, what is stored, what is disclosed and when a refusal is the
right answer are decisions this library has no part in and cannot check — the tests behind these
blocks hold a fixture vault to them, and nothing here can hold a vault in the field to anything.

---

## What a vault must do

Everything above is *shape*: which function to call, what comes back, what an answer looks like on
the wire. This section is the other kind of statement — the things a correct vault has to do, none
of which any function in this library can perform for you.

None of them is new here. Each one is already published in the KDoc of the function it belongs to,
or in `CHANGELOG.md`, or in the client's guide; what was missing was a single place to read them,
so a vault author had to find nine sentences across four source files to learn the first one below.

**Each bullet names a `@Test`, and that is what stops this list becoming decoration.**
`GuideSnippetTest` resolves every citation here by reflection: a bullet citing a test that does not
exist reddens, and a bullet citing nothing at all reddens. So an obligation cannot outlive its
evidence, and one cannot be added without somebody pointing at a test that would notice.

- **Call `Utils.isStatementPreImage` on every nonce before signing it, and refuse a match.** A
  nonce is caller-chosen bytes, and the pre-image of a signed statement — a key rotation, a
  recovery authorization, a revocation — is exactly such bytes. Sign one and you have answered a
  "prove your identity" dialog with a valid rotation of the user's key. The signing device is the
  only place this check can be made: afterwards no verifier can tell the two signatures apart,
  because the same key signed the same bytes. **Nothing in this library refuses such a nonce on
  your behalf.** `parseSignChallengeRequest` hands the bytes over deliberately — they are
  legitimate input to *look* at — and whether that parser should itself refuse them is a narrowing
  of the protocol drafted for a human and still open, so do not read this bullet as saying LIM
  enforces it. Pinned by `VaultGuideExamplesTest > a login answer is a signature the client
  verifies against the key it already holds`, and over a second fixture by
  `ClientIntegrationExampleTest > the vault refuses to sign a statement pre-image handed to it as
  a challenge`.
- **Treat every incoming intent as hostile, and answer a `null` parse with nothing at all.** Any
  installed app can fire an intent at an exported activity, and nothing on the way in has been
  authenticated by anybody. The parsers fail closed rather than throwing, so a `null` is not an
  error to report: there is no user to show it to and no request to consent to. Show nothing,
  answer nothing. That the parsers refuse rather than throw is pinned by
  `VaultGuideExamplesTest > a share and a query are told apart by their payload, and neither parses
  as both`; that a vault *answers* such an intent with a refusal carrying no payload at all — not
  an error, not even a correlation token, because the token is read off a parse that did not
  happen — is pinned by `VaultGuideExamplesTest > a refusal for a key this vault does not hold is
  the refusal for a consent the user withheld`.
- **A parsed request is not an entitlement.** A non-null return says somebody asked about a key —
  no more. What is disclosed, and whether to sign at all, is the user's consent decision made in
  your own UI, and consent in this protocol is **per disclosure**: one field of three is a complete
  answer, and an empty disclosure is a legitimate one. Pinned by
  `VaultGuideExamplesTest > a query answer discloses only what was released, under the query flow's
  own field key`.
- **Answer with the key the vault holds, never the key the request named.** A query's `publicKey`
  is the key the *caller* chose to ask about, and a sign-up's is a placeholder; the key an answer
  carries must be the one this vault minted and stored, because that key *is* the account from
  there on. This is why the request-taking builders take the key explicitly instead of echoing the
  request's — a builder that echoed it would let the calling app decide what its own answer says
  about it. Pinned by `VaultGuideExamplesTest > a share answer carries the key the vault minted and
  the token the request came with`.
- **Every field is required unless the client marked it optional, and an unreadable declaration is
  not a licence.** Absent, blank, malformed, wrong-typed and unreadable all mean *every field is
  required* — the same answer a client built before the declaration existed gets. The quiet
  direction of that mistake is a vault saving an empty profile and then answering a client that
  asked for a full one, which is a false claim on the wire rather than a lenient one. Pinned by
  `VaultGuideExamplesTest > an absent or unreadable optional-fields declaration leaves every field
  required`.
- **Echo the correlation token on every answer and on every refusal, and never treat it as
  authentication.** It is the one extra that has to survive a refusal: without it the client holds
  an answer it cannot attribute to a request, and the accident that follows is not a crash — it is
  a handler acting on a disclosure meant for something else. It travels in an extra any app can
  write, so a match says "this is the result I was waiting for" and never "this result is genuine".
  Pinned by `VaultGuideExamplesTest > a refusal is a result code and the echoed token, and a
  builder would say more than that`.
- **A refusal must not say which of its reasons it is.** "The user declined" and "this vault holds
  no such profile" are one answer, deliberately: a vault that distinguished them would be telling
  every caller that a profile exists for every key it is *not* told that about, which turns a
  refusal into a disclosure about the key. So both go out as `RESULT_CANCELED` with the echoed
  token and nothing else — no reason, no status, no version echo. Pinned by
  `VaultGuideExamplesTest > a refusal for a key this vault does not hold is the refusal for a
  consent the user withheld`.
- **The private half of a profile's keypair never leaves the vault.** It is not part of any answer,
  it is not a field, and it is not something this library will ever ask you for: LIM holds no
  private key, sees none and signs nothing. `createSignChallengeResultIntent` writes what you say
  you signed, and the client's own verification is what decides whether that is true. Pinned by
  `NoNetworkLegTest > no class compiled into the library holds or names a private key` — **and
  that citation is the one limit worth reading twice.** It holds *this library* to its half of the
  sentence, by reading the compiled bytecode. Your Keystore discipline is yours, and nothing here
  measures it.

**The limit of this whole section, which is the same limit the page has drawn twice already.**
Every citation above but one holds a **fixture** vault — one written in this repository, in a test
method — to the obligation beside it. The obligations are the protocol's; the enforcement is yours.
A vault in the field is another application in another repository, and no assertion here can reach
it. (The exception is the last bullet, whose citation reads this library's own compiled bytecode
and involves no vault at all; that bullet says so where it stands.) What the citations do buy is
that this page cannot state an obligation nothing in this repository has ever executed, and that
the list cannot keep claiming one after the test demonstrating it was renamed away.

---

## Where to look next

- `VaultGuideExamplesTest` — the source of every block on this page.
- `ClientIntegrationExampleTest` — sign-up, query, login and refusal as one runnable sequence
  against one profile, with a fixture vault answering. The closest thing here to a whole vault,
  and the file that writes out the statement pre-image attack a signing vault must refuse.
- `RequestParsingTest` — the three parsers, field by field, over hostile input.
- `ResultBuilderTest` — the three result builders from the other side: which extra each one
  writes, and what a result built for one flow discloses to the other.
- `IntentBuilderTest` — the wire format as literals. This is the contract between the two apps.
- [INTEGRATION.md](INTEGRATION.md) — the client's half, which is what your vault is answering.
