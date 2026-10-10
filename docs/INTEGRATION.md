# Integrating LIM

LIM lets your app ask for a person's details without ever holding them. Their data stays
encrypted on their device inside a vault app; your service receives an RSA public key, and that
key *is* the account. Individual fields are disclosed per request, with the user's consent, and
the user proves they are present by having the vault sign a challenge you generated.

The payoff is what a breach of your service leaks: a list of public keys, and nothing else.

Everything crosses app boundaries as an `Intent`, so every integration is the same four moves —
send a request, get a result in `onActivityResult`, parse it with this library, and act on it. All
four are below.

**Every Kotlin block on this page is lifted verbatim out of a test that runs.** The HTML comment
above each block names the region it came from, `GuideSnippetTest` fails if the two ever drift, and
it also fails unless each region sits inside a function annotated `@Test`. So nothing here is
pasted prose that compiled once: it is a line JUnit executed to get the suite green.

---

## Setup

The coordinate this library will publish under is:

```gradle
dependencies {
    implementation("dev.eryalabs.lim:lim:1.0.0")
}
```

**It is not resolvable yet, as of this commit.** No release has been cut from this repository: the
only git tag here is `0.1.0`, and `LIM/build.gradle.kts` declares Central publishing
(`publishToMavenCentral()`, `signAllPublications()`) for a version that has never been published.
Cutting it is a human step, tracked in the maintainers' release queue as *"Cut the first public
release on JitPack as `1.0.0` (human only)"* alongside a release checklist. When it lands, the
block above starts working and this section loses this paragraph. That last part is the one claim
here that was not checked against a repository — nothing in this repository reaches the network —
so if the coordinate above resolves for you, the release has happened and this paragraph is stale.

LIM needs `minSdk 24`. Its only runtime dependency is Gson.

### Until then: build from source

Clone this repository and run `./gradlew :LIM:assembleRelease`. The artifact lands at
`LIM/build/outputs/aar/LIM-release.aar`. Copy it into your project's `libs/` directory and declare
it — an AAR carries no dependency metadata, so LIM's one runtime dependency is yours to add:

```gradle
// app/build.gradle.kts
dependencies {
    implementation(files("libs/LIM-release.aar"))
    implementation("com.google.code.gson:gson:2.13.2")
}
```

**This is the one block on the page whose mechanics no test here checks**, because nothing in this
repository can execute a consumer project's build. Every *name* in it is pinned — the project path
comes from `settings.gradle.kts`, the artifact from the module name, the Gson coordinate from the
module's own dependency block — so it cannot silently fall out of step with the library. How your
build consumes a local AAR is still your build's business.

Do not add this module to your own build with `include(...)`: it resolves its plugins and test
dependencies through *this* repository's version catalog, which yours does not have.

Swap all of it for the coordinate above once the release is cut.

---

## Before you start: is there a vault?

Every block below assumes a vault that answers. The device may not have one, and that is the first
wall a real app hits — before sign-up, not after it. `Utils.shareEntry` is the one function in this
library whose return value tells you: it dispatches a fire-and-forget share and reports whether
anything received it.

<!-- snippet: GuideExamplesTest.kt#vault-present -->
```kotlin
// A device may have no vault on it at all, and that is the first wall an integration
// hits. `shareEntry` dispatches the sign-up and its return value is the answer: `false`
// means nothing received the intent, so no consent dialog opened and nothing is coming.
fun signUpIfAVaultIsInstalled(context: Context, entry: Entry): Boolean {
    if (Utils.shareEntry(context, entry)) return true
    // Nothing handled it. Offer to install a vault — but declare the vault in your own
    // manifest's `<queries>` element first, or on Android 11+ a `false` here also means
    // "this app was not allowed to look", and you would be telling the user to install
    // an app they already have.
    // promptToInstallAVault()
    return false
}
```

That last part is a precondition, not a footnote. On Android 11+ an app sees only the packages it
declares, and `setPackage` does not exempt it, so without the element below an installed vault
resolves to nothing and `false` means "invisible" rather than "absent". The element goes in **your**
manifest — this library ships none, because a manifest change here is a human decision:

```xml
<!-- your own AndroidManifest.xml, not this library's -->
<queries>
    <package android:name="com.github.adaydreamaway.endeavor" />
</queries>
```

That package name is `Utils.DEFAULT_ENDEAVOR_PACKAGE`, the vault every call in this guide defaults
to. If you pass `targetPackage` to address a different vault, declare that one instead.

One case is not a return value: if a vault matches but *refuses* the launch — an activity that is
not exported, or one behind a permission you do not hold — `shareEntry` throws `SecurityException`
rather than returning `false`. That is deliberate, because reporting it as `false` would have you
tell the user to install an app they already have. It is a misconfiguration on one side or the
other, so catch it where you report bugs, not where you prompt for an install.

Use `shareEntry` only for this check and for a share you do not need an answer to. Sign-up proper
wants the result, which is the next section.

---

## Sign-up (share)

Sign-up is one round trip. You send an `Entry` naming the fields you want and the type you expect
for each; the vault shows the user what is being asked for, fills the values from its own stored
profile, mints a keypair, and answers with the public half.

<!-- snippet: GuideExamplesTest.kt#signup-request -->
```kotlin
// The fields your service needs, each with the type you expect. You supply no values —
// the user fills those in the vault's own form. `publicKey` is a slot the vault fills,
// so send a placeholder: a blank one is encoded here and then refused on arrival.
val entry = Entry(
    id = "signup-form",
    fields = linkedMapOf(
        "name" to TypedField(value = "", type = FieldType.STRING),
        "email" to TypedField(value = "", type = FieldType.EMAIL),
    ),
    publicKey = "no-key-yet",
)
// Pass `requestCode` **by name**. The positional three-argument call resolves to the
// `targetPackage` overload instead, addressing the intent at a package named
// "signup-1", and nothing ever answers it.
val request = Utils.createShareIntent(context, entry, requestCode = SIGN_UP_REQUEST)
// startActivityForResult(request, VAULT_RESULT)
```

The answer arrives in `onActivityResult`:

<!-- snippet: GuideExamplesTest.kt#signup-result -->
```kotlin
// In onActivityResult, once `resultCode` is RESULT_OK.
val result = Utils.parseShareResult(data)
// The handle to keep is the key the *result* carried. The vault mints the keypair, so
// whatever you put in the slot on the way out was never an identifier.
val accountKey = result?.publicKey
```

Store `accountKey`. It is the account. See **Rules you must not break** for the two ways storing
it goes wrong.

---

## Query

A query asks an existing profile for its fields again — after a sign-up, or any time later. The
vault decides what to disclose and asks the user; you get back whatever they consented to.

<!-- snippet: GuideExamplesTest.kt#query-request -->
```kotlin
// A query asks about one profile, by the key you stored at sign-up. The vault decides
// what it discloses. The request code is yours: it is what tells answers apart when
// more than one request is in flight.
val request = Utils.createQueryIntent(context, accountKey, QUERY_REQUEST)
// startActivityForResult(request, VAULT_RESULT)
```

<!-- snippet: GuideExamplesTest.kt#query-result -->
```kotlin
// In onActivityResult. Check the correlation first — this answer may belong to a
// different request you still have outstanding.
val mine = Utils.matchesRequestCode(data, QUERY_REQUEST)
val disclosure =
    if (mine && resultCode == Activity.RESULT_OK) Utils.parseQueryResult(data) else null
val email = disclosure?.fields?.get("email")?.value
// A disclosure is not a login. Nothing in a query answer is signed, so this says "the
// vault told us this", never "the holder of the key is here".
```

---

## Login (sign-challenge)

Login is the one flow that proves something. You generate a random challenge, the vault signs it
with the profile's private key, and you verify the signature against the public key you already
hold. Nothing leaves the device but a signature.

The order is the whole lesson: generate, keep, verify against what you already had.

<!-- snippet: GuideExamplesTest.kt#login-request -->
```kotlin
// Mint the challenge and keep it. It carries its own timestamp, so there is no
// server-side state to expire; declaring the format is what lets a vault read that
// timestamp and apply a freshness policy of its own.
val nonce = Utils.generateNonce()
val request = Utils.createSignChallengeIntent(
    context,
    storedPublicKey,
    nonce,
    LOGIN_REQUEST,
    nonceFormat = Utils.NONCE_FORMAT_TIMESTAMPED,
)
// startActivityForResult(request, VAULT_RESULT)
```

<!-- snippet: GuideExamplesTest.kt#login-result -->
```kotlin
// In onActivityResult. Verify against the key your account table already holds and the
// nonce you generated — never against either one read back out of the result, or the
// sender gets to choose both sides of the proof.
val result = Utils.parseSignChallengeResult(data)
val loggedIn = resultCode == Activity.RESULT_OK &&
    Utils.matchesRequestCode(data, LOGIN_REQUEST) &&
    Utils.isNonceFresh(nonce, maxAgeMillis = 60_000L) &&
    result?.isVerified(storedPublicKey, nonce) == true
```

Freshness and authenticity are separate questions, and the four clauses above are in the order that
makes each one cheap to reason about: the right request, inside its window, signed by the right key
over the right bytes.

---

## When the user says no

Consent can be refused, and an integration that has not handled it has not been written. A refusal
today is `RESULT_CANCELED` carrying the request code you sent and nothing else.

<!-- snippet: GuideExamplesTest.kt#declined -->
```kotlin
// Branch on the result code, never on the parse. A refused query parses into a
// perfectly good QueryResult with no fields — exactly what a vault that consented and
// disclosed nothing returns — so the parse cannot tell you which of the two happened.
val declined = resultCode != Activity.RESULT_OK
// Correlation survives a refusal: the echoed request code is the one thing a declining
// vault still sends, so you know which request the user said no to.
val whichRequest = Utils.matchesRequestCode(data, QUERY_REQUEST)
// There is no structured reason to show the user. A refusal is deliberately
// uninformative; tell them nothing was sent and let them ask again.
```

A refused *login* answers the same way, so the same rule covers it: no result code, no
authentication.

---

## Rules you must not break

Three of them. Each one is a way an integration can be entirely working and still wrong.

### The public key is the account identifier

Never key an account on a disclosed field. Email is the one that tempts everybody, and it is the
one that breaks.

<!-- snippet: GuideExamplesTest.kt#rules-account-key -->
```kotlin
// `accounts` is your own table and the public key is its key. Key on a disclosed field
// instead — email above all — and two people who happen to share an address land on one
// row, each able to read the other's disclosures, with nothing in the protocol able to
// object. The user can also change an email, and the vault may decline to disclose it
// next time; neither is true of the key.
fun signUp(data: Intent?): String? {
    val key = Utils.parseShareResult(data)?.publicKey ?: return null
    return accounts.getOrPut(key) { "account-${accounts.size + 1}" }
}
```

A disclosed field is the user's data that they let you see once. It is not your handle on them.

### Parsed is not authenticated

`parseSignChallengeResult` returning a result means the bytes were well formed. It means nothing
about who produced them. `SignChallengeResult.isVerified` is the only success signal this library
offers, and it deliberately takes no zero-argument form — it cannot answer without the key and the
nonce that *you* chose.

<!-- snippet: GuideExamplesTest.kt#rules-not-authenticated -->
```kotlin
// Parsing says the bytes were well formed. It says nothing about who made them:
// anything on the device can put a signature-shaped extra in an intent, and it parses
// exactly as well as a genuine answer does. `isVerified`, against your own stored key
// and your own nonce, is the only success signal this library offers.
fun authenticated(data: Intent?, storedKey: String, challenge: ByteArray): Boolean =
    Utils.parseSignChallengeResult(data)?.isVerified(storedKey, challenge) == true
```

### Store the exact key string you verified

<!-- snippet: GuideExamplesTest.kt#rules-exact-key -->
```kotlin
// Store the exact string you verified, character for character. Base64 decoding skips
// characters outside its alphabet, so `key` and `key + "\n"` decode to the same bytes
// and verify the same signatures — but a profile is looked up by the key *string*, so
// the two are different account identifiers. Trim, re-wrap or re-encode a key you have
// already stored and the account it names can never be reached again.
val verifiedKey = storedPublicKey        // exactly as the sign-up result spelled it
val account = accounts[verifiedKey]      // and exactly what you look it up by
```

This is the rule with the sharpest edge, because the failure is silent and permanent: a key stored
with a stray newline authenticates perfectly for ever and matches no profile, so the account it
names can never be moved or recovered.

---

## Where to look next

- `ClientIntegrationExampleTest` — sign-up, query, login and refusal as one runnable sequence,
  against one profile, with a fixture vault answering. Read this if you are writing a vault: it
  runs both halves of the wire.
- `GuideExamplesTest` — the source of every block on this page.
- `IntentBuilderTest` — the wire format as literals. This is the contract between the two apps.
