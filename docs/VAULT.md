# Writing a vault

This page is for the other half of the wire. If you are integrating LIM into an app that *asks*
for someone's details, [INTEGRATION.md](INTEGRATION.md) is your page; this one is for an app that
**holds** them and answers those requests.

A vault is the app the data never leaves. It keeps the profile encrypted on the device, it mints
and keeps the keypair, and it decides — with the user in front of it — what to disclose and what
to sign. Everything it receives arrives as an `Intent` from another app on the same device, which
means every byte of it is hostile input: any installed app can fire an intent at an exported
activity, and nothing on the way in has been authenticated by anybody.

So this page is mostly about reading. The three functions below are a vault's entire entry point —
`parseShareRequest`, `parseQueryRequest` and `parseSignChallengeRequest` — and the reason to call
them instead of reading extras by hand is that they are the same code the client half is pinned
against. A vault that hand-reads `extra_entry_json` has made a private copy of the wire format,
and private copies drift.

**Every Kotlin block on this page is lifted verbatim out of a test that runs.** The HTML comment
above each block names the region it came from, in `VaultGuideExamplesTest`, and `GuideSnippetTest`
fails if the two ever drift — or if the region is not inside a function JUnit executes. So nothing
here is prose that compiled once.

This page covers **reading** a request. Answering one, and the obligations a vault owes the
protocol, are not on it yet.

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

## Where to look next

- `VaultGuideExamplesTest` — the source of every block on this page.
- `ClientIntegrationExampleTest` — sign-up, query, login and refusal as one runnable sequence
  against one profile, with a fixture vault answering. The closest thing here to a whole vault.
- `RequestParsingTest` — the three parsers, field by field, over hostile input.
- `IntentBuilderTest` — the wire format as literals. This is the contract between the two apps.
- [INTEGRATION.md](INTEGRATION.md) — the client's half, which is what your vault is answering.
