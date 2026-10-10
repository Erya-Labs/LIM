# ---------------------------------------------------------------------------------------
# Consumer R8 / ProGuard rules for dev.eryalabs.lim:lim.
#
# AGP packages this file into the AAR (`consumerProguardFiles` in LIM/build.gradle.kts), so
# every consumer who sets `isMinifyEnabled = true` applies these rules to their own release
# build. Until the commit that wrote this file it was the 0-byte Android Studio template,
# and so was the artifact AGP had already built from it
# (LIM/build/intermediates/merged_consumer_proguard_file/release/.../proguard.txt). The
# published AAR therefore told every minifying consumer's R8 to keep nothing in this library.
#
# WHY A LIBRARY THAT IS NOT ITSELF MINIFIED NEEDS THIS. This module builds with
# `isMinifyEnabled = false`, which is correct for a library: R8 runs in the *consumer's*
# build, over this library's classes, with the consumer's rules plus these. That also means
# no gate in this repository runs R8 over these classes, so "R8 would rename these fields"
# is CONFIGURATION REASONING, NOT A MEASUREMENT, and is labelled as such here and in
# ConsumerRulesTest.
#
# WHAT *IS* MEASURED is the half that can be: the five JSON keys the two apps exchange are
# the five keys Gson actually emits, and ConsumerRulesTest asserts that by reflection,
# comparing declaredFields against the keys Gson().toJson writes. The directives below name
# fields, so that assertion is what says they still name the things the wire is made of —
# and it is what reddens if they stop. That is what makes this a wire-format file rather
# than a packaging nicety.
#
# WHAT NAMES THOSE KEYS CHANGED, AND THESE RULES ARE STILL REQUIRED. When this file was
# written the keys *were* the JVM field names, with nothing between them: Gson reflected
# over the fields and there was no @SerializedName and no field-naming policy anywhere in
# the library. The five properties now carry @SerializedName naming the same five strings
# (WireKeyAnnotationTest reads them back off the backing fields), so a key no longer moves
# when a Kotlin identifier does — renaming `publicKey` to `key` now reddens ConsumerRulesTest
# rule 3 instead of moving the payload. That does NOT retire these rules, for two reasons:
#
#   * An annotation only helps if it survives, which is `-keepattributes *Annotation*`
#     below — a line that was forward-looking when it was written and is load-bearing now.
#   * A field R8 *removed* has no name to serialise under at all, annotated or not, and a
#     field only ever written reflectively looks unused to R8. That is why the rules below
#     are `-keep` rather than `-keepclassmembernames`.
#
# So the two mechanisms are complementary: the annotation pins the key to a string, these
# rules keep the field (and its annotation) in the consumer's release build to be read.
#
# WHAT GOES WRONG WITHOUT THE RULES. A minifying consumer sends a payload keyed "a", "b",
# "c"; the vault reads `id` and `publicKey` as absent, Utils.decodeEntry answers null, the
# sign-up is dropped, no consent dialog opens, and neither app logs a reason.
#
# WHAT IS DELIBERATELY NOT HERE. No -dontobfuscate, and no -dontwarn for this library's own
# packages. Whether to obfuscate is the consumer's decision about the consumer's app, and a
# library that switches it off from inside an AAR has overridden a choice that was never its
# own. These rules therefore name exactly what must survive obfuscation and leave every
# other decision to the consumer. ConsumerRulesTest refuses -dontobfuscate by name rather
# than only in this comment.
#
# The signed-statement classes — RotationStatement, Revocation, RecoveryAuthorization,
# SignedStatement and the rest — get no rules ON PURPOSE. Their pre-images are hand-encoded
# field by field and never travel through Gson (see the note at RotationStatement.kt:33), and
# none of them is Parcelable, so no reflective name of theirs is load-bearing. Do not add
# rules for them by cargo cult.
#
# Gson may well ship keep rules of its own. That could not be checked from here — reading
# the Gradle cache's jars is refused by this environment's permission system, and that was
# not routed around — so the rules below stand alone. Duplicating a rule Gson also ships
# costs nothing, and no rule Gson ships could name *this* library's fields in any case.
# ---------------------------------------------------------------------------------------

# Entry's three fields carry three of the five JSON keys the two apps exchange, each named by
# its own @SerializedName: `Gson().toJson(entry)` at Utils.kt:306 writes them into
# EXTRA_ENTRY_JSON, and `fromJson(json, Entry::class.java)` at Utils.kt:2855
# (Utils.decodeEntry) reads them back. `-keep` rather than `-keepclassmembernames`: a
# names-only rule forbids renaming but still permits REMOVAL, and a field only ever written
# reflectively looks unused to R8 — a removed field has no key, however it is annotated.
-keep class dev.eryalabs.lim.Entry {
    java.lang.String id;
    java.util.Map fields;
    java.lang.String publicKey;
}

# TypedField's two fields carry the other two keys, likewise by @SerializedName, reached
# through the Map<String, TypedField> TypeToken at Utils.kt:204 by Utils.encodeFields
# (Utils.kt:2784) and Utils.decodeFields (Utils.kt:2808). Same form, same reason.
-keep class dev.eryalabs.lim.TypedField {
    java.lang.String value;
    java.lang.String type;
}

# Utils.decodeFields (Utils.kt:2808) deserialises into Map<String, TypedField>, and that
# type argument exists at runtime only in the generic signature of the anonymous TypeToken
# at Utils.kt:204. Strip Signature and Gson sees a raw Map: every value comes back as a
# LinkedTreeMap and the first use of it fails with a ClassCastException.
-keepattributes Signature

# Gson reads its annotations reflectively at runtime, so an erased annotation is an ignored
# annotation. This line was written forward-looking and is now LOAD-BEARING: the five
# @SerializedName annotations on Entry and TypedField are what name the five JSON keys, and
# R8 stripping RuntimeVisibleAnnotations in a consumer's release build would hand Gson five
# fields with no declared key and send it back to the field names this file keeps.
-keepattributes *Annotation*

# The TypeToken at Utils.kt:204 is an anonymous subclass whose only purpose is to carry a
# generic signature. R8 in full mode strips such subclasses, which takes the signature with
# them however well `-keepattributes Signature` above is spelled.
-keep class * extends com.google.gson.reflect.TypeToken

# JSON is not the only cross-process path these two types take: both are @Parcelize
# Parcelable, and the Parcelable encoding is published, consumer-visible behaviour
# (EntryParcelTest pins it). @Parcelize generates a static CREATOR field that the platform
# looks up REFLECTIVELY, by name, so it looks unused to R8 exactly as the JSON fields do.
# AGP's default proguard-android-optimize.txt keeps every CREATOR, which is why this is
# rarely written down — but that holds only while a consumer keeps the default file in their
# own proguardFiles, and that is configuration reasoning about somebody else's build rather
# than a measurement. Written out rather than assumed; duplicating AGP's rule costs nothing.
# Named class by class rather than as `class * implements android.os.Parcelable`: the wildcard
# form would reach every Parcelable in the CONSUMER's app, and this file does not get to make
# decisions about code it knows nothing about.
-keepclassmembers class dev.eryalabs.lim.Entry {
    public static final android.os.Parcelable$Creator CREATOR;
}

# The same, for the other published Parcelable. These two are the only @Parcelize classes in
# the library — the signed-statement types are plain data classes.
-keepclassmembers class dev.eryalabs.lim.TypedField {
    public static final android.os.Parcelable$Creator CREATOR;
}
