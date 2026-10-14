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

LIM is published on Maven Central:

```gradle
dependencies {
    implementation("dev.eryalabs.lim:lim:1.0.0")
}
```

It resolves from `mavenCentral()`, which a new Android project already declares in
`settings.gradle.kts` — there is nothing else to configure. The version printed above is checked
against this repository's build file, so it cannot drift from the release it names.

LIM needs `minSdk 24`. Its only runtime dependency is Gson.

### Building from source

Only for trying a change that has not been released yet. Clone this repository and run
`./gradlew :LIM:assembleRelease`. The artifact lands at
`LIM/build/outputs/aar/LIM-release.aar`. Copy it into your project's `libs/` directory and declare
it — an AAR carries no dependency metadata, so LIM's one runtime dependency is yours to add:

```gradle
// app/build.gradle.kts
dependencies {
    implementation(files("libs/LIM-release.aar"))
    implementation("com.google.code.gson:gson:2.13.2")
}
```

**No test here checks this block's mechanics**, because nothing in this repository can execute a
consumer project's build — and it is not the only block on the page in that position. The keep rules
in the next section are in it too, for a reason that section states, and so is the `<queries>`
element further down. Every *name* in this one is pinned — the project path comes from
`settings.gradle.kts`, the artifact from the module name, the Gson coordinate from the module's own
dependency block — so it cannot silently fall out of step with the library. How your build consumes
a local AAR is still your build's business.

Do not add this module to your own build with `include(...)`: it resolves its plugins and test
dependencies through *this* repository's version catalog, which yours does not have.

For anything else, use the Maven Central coordinate above.

---

## If you minify your app

Five of this library's fields are read by name rather than by code: they **are** the five JSON keys
the two apps exchange. R8 renames and removes what it believes nothing reads, so a release build with
`isMinifyEnabled = true` needs keep rules for them. This library carries its own in
`consumer-rules.pro`, which AGP packages into the AAR for consumers who resolve it as a dependency.

**If you vendored the AAR into `libs/` — the only install path this guide can offer today — copy the
rules into your own ProGuard file.** Whether AGP hands a *file* dependency's packaged `proguard.txt`
to R8 is not a question this repository can answer, because nothing here builds a consumer project;
rather than guess either way, copy them. A rule that arrives twice costs nothing, and the failure if
none arrives is silent.

Nor does any test here show that these rules *work*. This library builds with
`isMinifyEnabled = false` — correct for a library, because R8 runs in your build and never in ours —
so no gate in this repository has ever run R8 over these classes. What *is* checked is that the block
below holds every directive line that file ships, in the same order — the comments around them are
each document's own:

```proguard
# The five JSON keys the two apps exchange are these five fields, each named by its own
# @SerializedName. `-keep` rather than `-keepclassmembernames`: a names-only rule forbids
# renaming but still permits removal, and a field R8 removed has no key at all.
-keep class dev.eryalabs.lim.Entry {
    java.lang.String id;
    java.util.Map fields;
    java.lang.String publicKey;
}
-keep class dev.eryalabs.lim.TypedField {
    java.lang.String value;
    java.lang.String type;
}

# Gson reads @SerializedName reflectively, so an erased annotation is an ignored one. The
# Map<String, TypedField> type argument exists at runtime only in the generic signature of an
# anonymous TypeToken, which R8's full mode would otherwise strip along with the subclass.
-keepattributes Signature
-keepattributes *Annotation*
-keep class * extends com.google.gson.reflect.TypeToken

# Both types are Parcelable too, and @Parcelize generates a CREATOR field the platform looks up
# by name. AGP's default proguard-android-optimize.txt keeps every CREATOR — this does not
# assume you kept that file in your own proguardFiles.
-keepclassmembers class dev.eryalabs.lim.Entry {
    public static final android.os.Parcelable$Creator CREATOR;
}
-keepclassmembers class dev.eryalabs.lim.TypedField {
    public static final android.os.Parcelable$Creator CREATOR;
}
```

Know the failure by sight, because neither app logs a reason for it: **sign-up opens no consent
dialog at all.** The minified payload is keyed `"a"`, `"b"`, `"c"`; the vault reads `id` and
`publicKey` as absent, `Utils.decodeEntry` answers `null`, and the request is dropped on arrival.

Nothing here switches obfuscation off, and you should not add `-dontobfuscate` on this library's
account. These rules name exactly what has to survive it and leave every other decision about your
app to you.

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

That package name is `Utils.DEFAULT_ENDEAVOR_PACKAGE`, the vault every call in this guide addresses.
If you pass `targetPackage` to address a different vault, declare that one instead.

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
for each; the vault shows the user what is being asked for, lets them type a value for each, mints
a keypair, and answers with the public half.

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

### Required and optional fields

**This needs the release after 1.0.0** — the version Setup prints does not have it — and a vault
built on that release to honour it.

A vault that implements required fields treats **every field you declare as required**: the user
cannot save the sign-up while one of them is blank, and if they will not fill it in they back out,
which reaches you as `RESULT_CANCELED` like any other refusal. That holds for an app that has never
heard of this, too. To let the user leave some fields empty, name them:

<!-- snippet: GuideExamplesTest.kt#signup-optional-request -->
```kotlin
// Every field you declare is required unless you name it here. Names match exactly, so
// a misspelt name is simply not sent and that field stays required. All five arguments
// are needed, the vault's package included: with no defaults, no shorter call can
// resolve to this overload, so every call written before it still means what it did.
val entry = Entry(
    id = "signup-form",
    fields = linkedMapOf(
        "name" to TypedField(value = "", type = FieldType.STRING),
        "email" to TypedField(value = "", type = FieldType.EMAIL),
        "phone" to TypedField(value = "", type = FieldType.PHONE),
    ),
    publicKey = "no-key-yet",
)
val requirements = FieldRequirements(entry.fields.keys, setOf("phone"))
val request = Utils.createShareIntent(
    context,
    entry,
    SIGN_UP_REQUEST,
    requirements.optionalFields,
    Utils.DEFAULT_ENDEAVOR_PACKAGE,
)
// startActivityForResult(request, VAULT_RESULT)
```

On such a vault, a field you named and the user left blank is dropped: it is absent from the
answer, never sent as `""`. The answer also carries the vault's acknowledgement of what it applied,
which `Utils.checkFieldRequirements` reads against what you declared:

<!-- snippet: GuideExamplesTest.kt#signup-optional-result -->
```kotlin
// In onActivityResult, once `resultCode` is RESULT_OK and the request code matches.
fun onSignUpAnswer(data: Intent?) {
    val result = Utils.parseShareResult(data) ?: return
    // Keep the key whatever follows: the profile now exists in the vault, bound to you.
    val accountKey = result.publicKey ?: return
    // Gate on the data, never on a version number. `committed` is null exactly when a
    // required field is missing or blank. It drops a blank optional field too, whether
    // the vault left it out or, as an older vault may, sent it as an empty value.
    val profile = requirements.committed(result.fields)
    when (Utils.checkFieldRequirements(requirements, data)) {
        FieldRequirementsVerdict.HONOURED,
        FieldRequirementsVerdict.MISMATCHED,
        FieldRequirementsVerdict.NOT_ACKNOWLEDGED -> createAccount(accountKey, profile!!)
        FieldRequirementsVerdict.INCOMPLETE ->
            accountIncomplete(accountKey, requirements.missingRequired(result.fields))
        else -> reportVault(accountKey) // VIOLATED, and any verdict a later release adds
    }
}
```

The verdicts split on one question you can answer without trusting the vault — did every required
field arrive with something in it? `FieldRequirements.committed` is that answer, and it is what to
create the account from.

- `HONOURED` — the vault acknowledged exactly your optional set, and the data is complete. That is
  the vault's claim, not a check of every value: an acknowledgement written by hand can sit beside
  a blank optional value, which `committed` drops.
- `MISMATCHED` — it acknowledged a different set, and the data is complete. The usual cause is a
  declaration it could not read, so it asked the user for everything.
- `NOT_ACKNOWLEDGED` — no acknowledgement, and the data is complete. A vault that predates this
  release, which may have made the user fill in fields you marked optional, or one that answered
  without acknowledging.
- `INCOMPLETE` — no acknowledgement, and a required field is missing. An older vault let the user
  skip it, or a vault on this release answered without acknowledging — through the builder that
  writes none, or over a payload that fell short, where the requirements-aware builder omits it.
  `FieldRequirements.missingRequired` names what is missing.
- `VIOLATED` — an acknowledgement over a missing required field. This library's builder never
  writes one, so the vault is writing it by hand or is broken — unless you required a field you
  never sent. A field whose `TypedField` is null in your `Entry`, as Java code or a template Gson
  built can leave one, is not encoded, so build your requirements from the keys whose value is
  not null.

Keep an `else` branch, as the handler above does: a later release may add a verdict.

What to know before relying on it:

- **A vault built before this release ignores your declaration.** It may let the user skip any
  field, required ones included, or — like the interim Endeavor build — make them fill in every
  field, optional ones included, and the only sign of either is `NOT_ACKNOWLEDGED` or
  `INCOMPLETE`. Keep the key even when the data is incomplete — the profile exists and is bound to
  it. There is no protocol path to fill a skipped field in later, and signing up again mints a
  second profile.
- **Required is not validation.** A required field holds *something*: `"x"` passes, and so does a
  zero-width space. Check the value yourself.
- **Blank is defined once**, by `FieldRequirements`, and the vault and your handler use the same
  definition: a field that is absent, or whose value is empty or whitespace only. This library
  never trims or rewrites a value.
- **What Endeavor, the reference vault, does once it is built on this release.** Every yes/no field
  starts as "Not answered", and an unanswered one is blank on the definition above whether it is
  absent or an empty value — a required one blocks Save, an optional one is dropped — so a "No" the
  user never chose is never sent. A required date must be picked, and an optional date that was
  never picked is dropped; no date format is promised. If every field is optional and the user
  leaves all of them blank, Endeavor creates a profile that is a key and nothing else: the answer
  carries the key, an empty field map and the acknowledgement, and the verdict is `HONOURED`.
- **The verdict is not authentication.** The acknowledgement is an unsigned extra, exactly as
  trustworthy as the vault you addressed.
- **The version number cannot tell you either.** `PROTOCOL_VERSION` stays 2. A vault echoes the
  version of the library it was built on, which says what vocabulary it speaks and not whether it
  implements this; the acknowledgement is the signal, and only a vault's answer carries it.

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

Four of them. Each one is a way an integration can be entirely working and still wrong.

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

### Gate on the data, never on the version

Whether a sign-up gave you what you need is a fact about the fields that arrived, and
`FieldRequirements.committed` reads it straight off them — the handler under **Required and
optional fields** creates an account only from what that returns. Never infer it from
`vaultProtocolVersion`, or from any other number a vault echoes: a vault built on this library
echoes the library's version whether or not it does what that release made possible.

---

## Testing your integration without a vault

The first hour of an integration is the request. The second is a test that proves the
`onActivityResult` half works — and on a build machine there is no vault installed to answer it.

You do not need one. The three result builders a vault calls on the way out —
`createShareResultIntent`, `createQueryResultIntent` and `createSignChallengeResultIntent` — are
published here too, so your own test can mint the answer your handler will be handed.
`GuideExamplesTest`'s own fixture vault — the thing that answers the round trips above — is built
on exactly these three.

<!-- snippet: GuideExamplesTest.kt#testing-your-handler -->
```kotlin
// Factor the `onActivityResult` half into something a unit test can call. This library's
// own result builders mint the answer, so the test needs no vault, no device and no
// keystore — but it does need Robolectric: `Intent` is an unimplemented stub in a plain
// JVM unit test, and constructing one there throws rather than failing an assertion.
fun onVaultAnswer(resultCode: Int, data: Intent?): String? {
    if (resultCode != Activity.RESULT_OK) return null
    if (!Utils.matchesRequestCode(data, SIGN_UP_REQUEST)) return null
    return Utils.parseShareResult(data)?.publicKey
}

// The answer a consenting vault sends after a sign-up.
val answer = Utils.createShareResultIntent(
    publicKey = FAKE_PUBLIC_KEY,
    fields = linkedMapOf(
        "email" to TypedField(value = FAKE_EMAIL, type = FieldType.EMAIL),
    ),
    requestCode = SIGN_UP_REQUEST,
)
val accountKey = onVaultAnswer(Activity.RESULT_OK, answer)
```

**Robolectric is the one prerequisite**, and it is a test-only dependency of your app rather than a
runtime dependency of this library. `Intent`, `Context` and `android.util.Base64` are unimplemented
stubs in a plain JVM unit test, so a test that builds an intent throws on the first line instead of
failing an assertion. This repository's own suite runs on Robolectric for exactly that reason.

**This is a recipe, and the shape of the call is not what makes it correct.** A hand-built
`Intent().putExtra(...)` carrying the same extras would behave identically here, and no test in
this repository would notice the difference. What ties the recipe to the protocol is that
`createShareResultIntent` is the function `ResultBuilderTest` pins extra by extra and the one the
reference vault calls to answer a real sign-up — so an answer built this way cannot drift from the
answer a vault sends. That is the claim; the section makes no larger one.

A sign-up that declares optional fields is tested the same way, with the vault-side half this
library also publishes: `Utils.parseFieldRequirements` reads your request as a vault does, and the
`createShareResultIntent` overload that takes those requirements writes the acknowledgement — but
only when the payload beside it satisfies them, so the verdict your test sees is the one a real
vault produces.

<!-- snippet: GuideExamplesTest.kt#testing-optional-fields -->
```kotlin
// A vault that implements required fields reads your declaration off the request, stores
// what the user filled in, and acknowledges the declaration only when what it stored
// satisfies it. Build that answer and your handler meets the verdict it will really get:
// here the user filled in both required fields and left the optional "phone" blank.
val declared = Utils.parseFieldRequirements(request)!!
val answer = Utils.createShareResultIntent(
    FAKE_PUBLIC_KEY,
    linkedMapOf(
        "name" to TypedField(value = "Ada", type = FieldType.STRING),
        "email" to TypedField(value = FAKE_EMAIL, type = FieldType.EMAIL),
    ),
    SIGN_UP_REQUEST,
    declared,
)
val verdict = Utils.checkFieldRequirements(requirements, answer)
// The optional set the vault says it applied. `null` means the answer acknowledges
// nothing: a vault older than this release, one answering through the builder that
// writes none, or one whose payload did not satisfy your declaration, with a required
// field missing or a blank value left in.
val applied = Utils.parseAppliedOptionalFields(answer)
```

A login test is the one case that still needs real cryptography: a signature has to be made with a
private key before `isVerified` can be true of it. `ClientIntegrationExampleTest` is the file to
read for that, and it generates its own keypair.

When a parse comes back `null`, `describeIntent` is the next step rather than a guess:

<!-- snippet: GuideExamplesTest.kt#testing-diagnosis -->
```kotlin
// When a parse returns null and it is not obvious why, describe the intent rather than
// guess. One line: the action, the package, the state of every extra the protocol
// defines, and last the flows this library's own parsers accept it as.
val proof = Utils.parseSignChallengeResult(answer)
if (proof == null) {
    Log.w("MyApp", Utils.describeIntent(answer))
    // `shareResult` is in that `flows=[…]` set and `signChallengeResult` is not: this is
    // a share answer, nothing signed it, and the login parser was never going to read
    // it. Route on the parser that returned the null — never on this wording, which is
    // prose for a human and is not wire format.
}
// Safe to log, with one limit worth knowing. The keys that carry a user's data are
// reduced — a field payload to a count, a nonce and a signature to byte lengths — and the
// public key is truncated rather than hidden, because it is the handle this design hands
// out freely. But the four protocol tokens the line quotes are printed as the sender
// wrote them, so a peer that files personal data under one of those puts it on your line.
// That is the peer's bug; `describeIntent`'s own KDoc says so and caps the width.
```

The usual answers are all on that line: an extra reads `blank` rather than `absent`, the field
payload sits under the key the other flow's parser reads, or `package` reads `"signup-1"` because a
request code was passed positionally to `createShareIntent`. An empty `flows=[]` means no parser
here would accept the intent as anything at all.

---

## Where to look next

- `ClientIntegrationExampleTest` — sign-up, query, login and refusal as one runnable sequence,
  against one profile, with a fixture vault answering. Read this if you are writing a vault: it
  runs both halves of the wire.
- `RequirementsCompatibilityMatrixTest` — an app on 1.0.0 or on the release after it, against a
  vault from before required fields, the interim one that required everything, and one that
  implements them: what the user is asked for, what comes back, and the verdict, in every pairing.
- `GuideExamplesTest` — the source of every block on this page.
- `IntentBuilderTest` — the wire format as literals. This is the contract between the two apps.
