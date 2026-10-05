package dev.eryalabs.lim

import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.util.Random

/**
 * What a relay actually carries: envelopes that are structurally perfect and **genuinely signed**,
 * with exactly one thing wrong.
 *
 * Every fuzz arm in `DecoderFuzzTest` feeds a JSON-shaped corpus, and its own
 * `parseSignedStatement` arm says so in as many words — "the corpus is JSON-shaped, so almost none
 * of it survives the framing". So the inputs that matter most for migration are the ones nothing
 * generates: not noise that dies at the first Base64 character, but a real signature over a real
 * pre-image with one byte, one component, one kind tag or one section out of place.
 *
 * `StatementEnvelopeTest` pins that family by hand, and the scope this file adds to rather than
 * repeats is worth stating exactly: it edits each of the five *rotation* components in turn, pins a
 * non-canonical rotation pre-image, and pins a framing tag disagreeing with the signed one in both
 * directions — the component edits on the rotation kind alone, the tag disagreement on exactly one
 * of the six ordered kind pairs, all of it at component granularity, and none of it with damage
 * *below* a component. The three things missing are therefore byte-level damage, the other two
 * kinds, and the six pairs swept rather than sampled. That is what the four arms here are:
 *
 * - **(a) bytes** — the decoded pre-image section flipped, truncated, appended to, its length
 *   prefixes and long fields overwritten, its components swapped, and re-framed intact.
 * - **(b) components** — one component replaced and the pre-image re-encoded, carrying the
 *   **genuine** signature.
 * - **(c) kinds** — all six ordered kind pairs, both as one kind's signed bytes under another's
 *   framing tag and as one kind's signature on another's genuine envelope.
 * - **(d) framing** — damage to the marker, to the section count, and to each Base64 section.
 *
 * **Three properties.** Nothing throws (`Throwable`, not `Exception`: the `StackOverflowError`
 * lesson T8 recorded, and `Utils`'s own `catch (_: Exception)` sites keep it live). No mutant ever
 * verifies `VALID` against the real stored key at a clock inside the genuine window. And every
 * mutant that *parses* satisfies the envelope's central promise — re-encoding the returned
 * statement reproduces the pre-image the text carried — which asserts over a thousand damaged
 * inputs what `Utils.parseSignedStatement` checks internally on one.
 *
 * **A mutant that is not actually a mutant must not be judged as one, and the criterion is per-arm.**
 * A single global criterion either lets a `VALID` through or silently deletes two of the four arms:
 *
 * 1. Arms (a) and (b) change the pre-image, and a generated replacement can equal the one it
 *    replaces — the same value drawn twice from a small pool, the same timestamp. Such a "mutant"
 *    *is* the genuine envelope, parses, and verifies `VALID` entirely legitimately. Their criterion
 *    is therefore the decoded pre-image bytes, and the skips are counted. Both pools carry the
 *    identity value deliberately, so the guard is exercised rather than hoped for.
 * 2. Arm (c) and the marker/section-count half of (d) leave the pre-image byte-identical **by
 *    design** — that is what they are testing — so a pre-image criterion would skip every one of
 *    them and this file would pass having swept none of the six kind pairs. Their criterion is the
 *    envelope *text*, which always differs, and they are never skipped.
 * 3. The Base64 half of (d) needs the **pair**. `Utils.parseSignedStatement`'s KDoc and
 *    `StatementEnvelopeTest`'s `distinct envelope strings can carry the identical statement` both
 *    record that the envelope text is not canonical: dropping padding or respelling the last
 *    quantum decodes to the *identical* pre-image and signature, so a text difference there is not
 *    a difference at all, and such a mutant verifies `VALID` legitimately. So the decoded pair is
 *    compared against the genuine pair and, when it is equal, `VALID` is **asserted rather than
 *    skipped** — the trap turned into a control, and the documented property ("unboundedly many
 *    distinct strings parse to the identical statement and signature") asserted where a fuzzer
 *    actually produces it.
 *
 * Judged mutants are counted **per arm with a floor per arm**, not globally: a global counter stays
 * non-zero on (a) and (b) alone, which is exactly how two deleted arms would go unnoticed.
 *
 * The corpus lives in its own file and its own [ENVELOPE_CORPUS_DIGEST] so that
 * `DecoderFuzzTest`'s `CORPUS_DIGEST` cannot move. What that digest pins is the **damage plan** —
 * every arm, label, kind and drawn parameter, except that a replacement drawn from a *key* is
 * digested by its length rather than its value, since the key itself is fresh each run — and not
 * the envelope strings, for the same reason: the keypair is generated per run and a committed
 * private key is not something this repository will carry. The plan is what has to be reproducible for a failure report to be actionable, and the
 * offsets in it are drawn modulo pre-image sizes that are themselves fixed (an X.509 RSA-2048
 * public key is always 294 bytes, so always 392 Base64 characters), so the plan really is identical
 * on every run and on every machine. The sizes are digested alongside it, so a toolchain that
 * changed them is a digest failure rather than a silently different corpus.
 *
 * **Runtime, and the honest version of it. ~0.35-0.5s of actual work, ~2.9-3.2s if it draws the
 * short straw on ordering.** The seven tests here measured 0.346s in a full
 * `:LIM:testDebugUnitTest --rerun-tasks` run timestamped 2026-10-05T16:17Z (486 tests, 0 failures,
 * 0 skipped, ~15.4s summed from the per-class `time` attributes in
 * `LIM/build/test-results/testDebugUnitTest/`), 0.431s and 0.508s in the reviewer's own two runs,
 * and 2.958s in a run where this class happened to go first in the JVM and so paid the one-time
 * Robolectric and JIT bootstrap. `DecoderFuzzTest` is 4.06-4.36s across those runs. Both figures
 * are stated because quoting only the cold one invites the next round to "fix" a regression that is
 * JVM ordering — the `PreImageCorpusTest` lesson. The 2048-bit keygen in [generateKeys] is this
 * file's one fixed cost and an RSA verification is its per-mutant one; a fuzz suite that doubles
 * the module's test time is one that stops being run.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SignedStatementFuzzTest {

    // ── The fixtures and their layout ────────────────────────────────────

    /** The three statement kinds, each with its kind tag spelled out rather than referenced. */
    private enum class Kind(val tag: String, val texts: Int) {
        ROTATE("lim.rotate.v1", 3),
        RECOVER("lim.recover.v1", 3),
        REVOKE("lim.revoke.v1", 2),
    }

    /** One genuine statement, its canonical pre-image, its genuine signature and its envelope. */
    private class Fixture(
        val kind: Kind,
        val texts: List<String>,
        val longs: List<Long>,
        val preImage: ByteArray,
        val signature: ByteArray,
        val envelope: String,
    )

    /**
     * Where everything sits inside a genuine pre-image, so a byte-level mutator can aim at a
     * length prefix, a long field or the inside of a multi-byte sequence rather than only at a
     * uniformly random offset.
     *
     * Computed from the component strings and the documented layout, then checked against the
     * encoder's own output: a mismatch throws here rather than producing a corpus that quietly
     * aims at the wrong bytes.
     */
    private class Layout(
        val textPrefixAt: List<Int>,
        val textAt: List<Int>,
        val textLen: List<Int>,
        val longAt: List<Int>,
        /** `(index of the lead byte, byte length)` per multi-byte UTF-8 sequence in a component. */
        val multiByteSeqs: List<Pair<Int, Int>>,
    )

    private fun layoutOf(fixture: Fixture): Layout {
        var at = DOMAIN_BYTES + LENGTH_PREFIX_BYTES + fixture.kind.tag.toByteArray(Charsets.UTF_8).size
        val prefixAt = ArrayList<Int>()
        val contentAt = ArrayList<Int>()
        val contentLen = ArrayList<Int>()
        val sequences = ArrayList<Pair<Int, Int>>()
        fixture.texts.forEach { text ->
            val bytes = text.toByteArray(Charsets.UTF_8)
            prefixAt += at
            at += LENGTH_PREFIX_BYTES
            contentAt += at
            contentLen += bytes.size
            var i = 0
            while (i < bytes.size) {
                val lead = bytes[i].toInt() and 0xFF
                val width = when {
                    lead < 0x80 -> 1
                    lead < 0xE0 -> 2
                    lead < 0xF0 -> 3
                    else -> 4
                }
                if (width > 1) sequences += (at + i) to width
                i += width
            }
            at += bytes.size
        }
        val longAt = fixture.longs.indices.map { at + it * STATEMENT_LONG_BYTES }
        at += fixture.longs.size * STATEMENT_LONG_BYTES
        if (at != fixture.preImage.size) {
            throw AssertionError(
                "the layout this file aims at is not the layout the encoder produced for " +
                    "${fixture.kind}: computed $at bytes, got ${fixture.preImage.size}. Every " +
                    "byte-level mutation below would be pointing at the wrong offsets",
            )
        }
        return Layout(prefixAt, contentAt, contentLen, longAt, sequences)
    }

    // ── The corpus ───────────────────────────────────────────────────────

    private enum class Arm { BYTES, COMPONENTS, KINDS, FRAMING }

    private enum class ByteDamage(val label: String) {
        FLIP("one byte flipped"),
        FLIP_UTF8_TAIL("the tail byte of a multi-byte sequence flipped to ASCII"),
        TRUNCATE("the pre-image truncated"),
        APPEND("bytes appended to the pre-image"),
        LENGTH_PREFIX("a component length prefix overwritten"),
        LONG_FIELD("the eight bytes of a long overwritten"),
        SWAP("two components' bytes swapped"),
    }

    private enum class FramingDamage(val label: String) {
        MARKER("the framing marker damaged"),
        KIND_TAG("the framing kind tag damaged"),
        SECTION_COUNT("the section count damaged"),
        PRE_IMAGE_SECTION("the pre-image section's Base64 damaged"),
        SIGNATURE_SECTION("the signature section's Base64 damaged"),
    }

    /**
     * One planned mutant.
     *
     * [detail] carries only *planned* parameters — offsets, pool names, drawn numbers — and never a
     * byte of the fresh keypair, because it is digested. The original byte a flip overwrote is
     * recoverable from the fixture and deliberately absent here. [classes] is the generator's own
     * record of which named classes a draw belongs to, which is what the generator floors count;
     * naming them at generation time beats parsing [detail] back apart afterwards.
     *
     * [preImage] is the bytes the text is *meant* to carry, or `null` for arm (d), where the damage
     * is to the framing and the text's own section is the only authority on what it carries.
     */
    private class Mutant(
        val arm: Arm,
        val label: String,
        val kind: Kind,
        val detail: String,
        val text: String,
        val preImage: ByteArray?,
        val classes: Set<String> = emptySet(),
    )

    private fun mutants(): List<Mutant> {
        val rnd = Random(CORPUS_SEED)
        val out = ArrayList<Mutant>(BYTE_MUTANTS + COMPONENT_MUTANTS + 12 + FRAMING_MUTANTS)
        out += byteMutants(rnd)
        out += componentMutants(rnd)
        out += kindMutants()
        out += framingMutants(rnd)
        return out
    }

    /**
     * Arm (a): damage *below* a component, with the framing left perfect.
     *
     * The decoded pre-image section is damaged and re-Base64'd under the genuine kind tag and the
     * genuine signature, so every one of these is an envelope a relay would pass on without
     * noticing anything.
     *
     * [ByteDamage.FLIP_UTF8_TAIL] is not decoration and is the one sub-kind a uniformly random
     * flip would reach only by luck: see
     * `a flip inside a four-byte sequence keeps the pre-image length and breaks canonicality` for
     * what it is for.
     */
    private fun byteMutants(rnd: Random): List<Mutant> {
        val out = ArrayList<Mutant>(BYTE_MUTANTS)
        repeat(BYTE_MUTANTS) {
            val kind = drawKind(rnd)
            val fixture = fixture(kind)
            val layout = layoutOf(fixture)
            val genuine = fixture.preImage
            val damage = ByteDamage.values()[rnd.nextInt(ByteDamage.values().size)]
            val classes = HashSet<String>()
            val detail: String
            val bytes: ByteArray

            when (damage) {
                ByteDamage.FLIP -> {
                    val at = rnd.nextInt(genuine.size)
                    val value = BYTE_POOL[rnd.nextInt(BYTE_POOL.size)]
                    bytes = genuine.copyOf().also { it[at] = value }
                    detail = "at=$at value=0x${hex(byteArrayOf(value))}"
                    if (value.toInt() and 0xFF < 0x80) classes += CLASS_ASCII_FLIP
                }

                ByteDamage.FLIP_UTF8_TAIL -> {
                    val (lead, width) = layout.multiByteSeqs[rnd.nextInt(layout.multiByteSeqs.size)]
                    val at = lead + width - 1
                    val value = ASCII_POOL[rnd.nextInt(ASCII_POOL.size)]
                    bytes = genuine.copyOf().also { it[at] = value }
                    detail = "seqAt=$lead seqWidth=$width at=$at value=0x${hex(byteArrayOf(value))}"
                    classes += CLASS_ASCII_FLIP
                    if (width == 4) classes += CLASS_FOUR_BYTE_TAIL_FLIP
                }

                ByteDamage.TRUNCATE -> {
                    // `nextInt(size)` and not `nextInt(size + 1)`: a cut at the end is no cut at
                    // all, and would be skipped as "not actually a mutant" for no reason.
                    val keep = rnd.nextInt(genuine.size)
                    bytes = genuine.copyOf(keep)
                    detail = "keep=$keep"
                }

                ByteDamage.APPEND -> {
                    val count = 1 + rnd.nextInt(4)
                    val tail = ByteArray(count) { BYTE_POOL[rnd.nextInt(BYTE_POOL.size)] }
                    bytes = genuine + tail
                    detail = "appended=${hex(tail)}"
                }

                ByteDamage.LENGTH_PREFIX -> {
                    val index = rnd.nextInt(layout.textPrefixAt.size)
                    val length = layout.textLen[index]
                    val claim = when (rnd.nextInt(6)) {
                        0 -> 0L
                        1 -> 1L
                        2 -> (length - 1).toLong()
                        3 -> (length + 1).toLong()
                        4 -> 0x7FFF_FFFFL
                        else -> 0xFFFF_FFFFL
                    }
                    bytes = genuine.copyOf()
                    writeBigEndian(bytes, layout.textPrefixAt[index], claim, LENGTH_PREFIX_BYTES)
                    detail = "text=$index claim=$claim"
                }

                ByteDamage.LONG_FIELD -> {
                    val index = rnd.nextInt(layout.longAt.size)
                    val value = LONG_POOL[rnd.nextInt(LONG_POOL.size)]
                    bytes = genuine.copyOf()
                    writeBigEndian(bytes, layout.longAt[index], value, STATEMENT_LONG_BYTES)
                    detail = "long=$index value=$value"
                }

                ByteDamage.SWAP -> {
                    // Only equal-length regions can be swapped without relaying the whole
                    // pre-image out, and that is the interesting case anyway: the result is a
                    // perfectly *canonical* pre-image of a different statement, so it parses and
                    // has to be stopped by the signature rather than by the reader.
                    val pairs = equalLengthTextPairs(layout)
                    if (pairs.isEmpty() || rnd.nextInt(2) == 0) {
                        bytes = genuine.copyOf()
                        swap(bytes, layout.longAt[0], layout.longAt[1], STATEMENT_LONG_BYTES)
                        detail = "longs 0<->1"
                        classes += CLASS_SWAPPED_LONGS
                    } else {
                        val (i, j) = pairs[rnd.nextInt(pairs.size)]
                        bytes = genuine.copyOf()
                        swap(bytes, layout.textAt[i], layout.textAt[j], layout.textLen[i])
                        detail = "texts $i<->$j"
                        classes += CLASS_SWAPPED_TEXTS
                    }
                }
            }

            out += Mutant(
                arm = Arm.BYTES,
                label = damage.label,
                kind = kind,
                detail = detail,
                text = framed(kind, bytes, fixture.signature),
                preImage = bytes,
                classes = classes,
            )
        }
        return out
    }

    /**
     * Arm (b): exactly one component replaced, the pre-image re-encoded through the production
     * encoder, and the **genuine** signature kept.
     *
     * These are the mutants that must *survive* the parse to prove anything — a re-encoded
     * pre-image is canonical by construction — so the parsed counter below is what says this arm
     * did its job.
     */
    private fun componentMutants(rnd: Random): List<Mutant> {
        val out = ArrayList<Mutant>(COMPONENT_MUTANTS)
        repeat(COMPONENT_MUTANTS) {
            val kind = drawKind(rnd)
            val fixture = fixture(kind)
            val slot = rnd.nextInt(kind.texts + fixture.longs.size)
            var texts = fixture.texts
            var longs = fixture.longs
            val classes = HashSet<String>()
            val detail: String

            if (slot < kind.texts) {
                val (name, value) = TEXT_REPLACEMENTS[rnd.nextInt(TEXT_REPLACEMENTS.size)]
                val replacement = value(texts[slot])
                texts = texts.toMutableList().also { it[slot] = replacement }
                // The replacement's *length* and not the replacement: a key is 392 characters on
                // every run, but which 392 is drawn fresh each time, and this string is digested.
                detail = "text[$slot] := $name (len=${replacement.length})"
                if (texts == fixture.texts) classes += CLASS_IDENTITY_REPLACEMENT
            } else {
                val index = slot - kind.texts
                val (name, value) = LONG_REPLACEMENTS[rnd.nextInt(LONG_REPLACEMENTS.size)]
                val replacement = value(longs[index], rnd)
                longs = longs.toMutableList().also { it[index] = replacement }
                // A 64-bit component carries no key bytes, so the value itself goes in — which is
                // what makes an edit to `"a drawn value"` move the digest.
                detail = "long[$index] := $name ($replacement)"
                if (longs == fixture.longs) classes += CLASS_IDENTITY_REPLACEMENT
            }

            out += Mutant(
                arm = Arm.COMPONENTS,
                label = "one component replaced",
                kind = kind,
                detail = detail,
                text = encode(kind, texts, longs, fixture.signature),
                preImage = preImageOf(kind, texts, longs),
                classes = classes,
            )
        }
        return out
    }

    /**
     * Arm (c): all six ordered kind pairs, swept rather than sampled.
     *
     * The kind tag is the only thing standing between "authorized to replace this key today" and
     * "authorized to replace it for ever" (T16's words), and `StatementEnvelopeTest` pins exactly
     * one of the six pairs. Two mutants per pair, which are different attacks: the first presents
     * one kind's signed bytes under another's framing tag, the second lifts one kind's genuine
     * signature onto another's genuine envelope.
     *
     * Both leave a pre-image that is byte-identical to something genuinely signed, which is why
     * their criterion is the text and they are never skipped.
     */
    private fun kindMutants(): List<Mutant> {
        val out = ArrayList<Mutant>(12)
        Kind.values().forEach { from ->
            Kind.values().filter { it != from }.forEach { to ->
                val source = fixture(from)
                val target = fixture(to)
                out += Mutant(
                    arm = Arm.KINDS,
                    label = "signed bytes under another kind's framing tag",
                    kind = to,
                    detail = "${from.tag} pre-image and signature framed as ${to.tag}",
                    text = framed(to, source.preImage, source.signature),
                    preImage = source.preImage,
                )
                out += Mutant(
                    arm = Arm.KINDS,
                    label = "another kind's signature on a genuine envelope",
                    kind = to,
                    detail = "${from.tag} signature on the genuine ${to.tag} envelope",
                    text = framed(to, target.preImage, source.signature),
                    preImage = target.preImage,
                )
            }
        }
        return out
    }

    /** Arm (d): the framing itself — marker, kind tag, section count, and each Base64 section. */
    private fun framingMutants(rnd: Random): List<Mutant> {
        val out = ArrayList<Mutant>(FRAMING_MUTANTS)
        repeat(FRAMING_MUTANTS) {
            val kind = drawKind(rnd)
            val fixture = fixture(kind)
            val sections = listOf(
                ENVELOPE_MARKER,
                kind.tag,
                Base64.encodeToString(fixture.preImage, Base64.NO_WRAP),
                Base64.encodeToString(fixture.signature, Base64.NO_WRAP),
            )
            val damage = FramingDamage.values()[rnd.nextInt(FramingDamage.values().size)]
            val classes = HashSet<String>()
            val detail: String
            val text: String

            // Every `detail` below carries the damaged *value* and not only the pool entry's name,
            // because the name alone is what the digest would then pin: rewriting
            // `"a later framing version" to "lim.env.v2"` as `… to "lim.env.v1"` would otherwise
            // turn that mutant into the genuine envelope and move no digest. These three sections
            // are literal text with no key bytes in them, so quoting them keeps the plan
            // reproducible.
            when (damage) {
                FramingDamage.MARKER -> {
                    val (name, value) = MARKERS[rnd.nextInt(MARKERS.size)]
                    detail = "marker := $name (\"$value\")"
                    text = sections.toMutableList().also { it[0] = value }.joinToString(":")
                }

                FramingDamage.KIND_TAG -> {
                    val (name, value) = KIND_TAGS[rnd.nextInt(KIND_TAGS.size)]
                    val tag = value(kind.tag)
                    detail = "kind tag := $name (\"$tag\")"
                    text = sections.toMutableList().also { it[1] = tag }.joinToString(":")
                }

                FramingDamage.SECTION_COUNT -> {
                    val (name, value) = SECTION_SHAPES[rnd.nextInt(SECTION_SHAPES.size)]
                    text = value(sections)
                    detail = "sections := $name (${text.split(':').size} sections)"
                }

                FramingDamage.PRE_IMAGE_SECTION, FramingDamage.SIGNATURE_SECTION -> {
                    val index = if (damage == FramingDamage.PRE_IMAGE_SECTION) 2 else 3
                    val applied = base64Damage(rnd, sections[index])
                    detail = "section[$index] := ${applied.detail}"
                    text = sections.toMutableList().also { it[index] = applied.section }
                        .joinToString(":")
                    classes += applied.name
                }
            }

            out += Mutant(
                arm = Arm.FRAMING,
                label = damage.label,
                kind = kind,
                detail = detail,
                text = text,
                preImage = null,
                classes = classes,
            )
        }
        return out
    }

    /** One damaged section: the class it belongs to, the drawn parameters, and the result. */
    private class Damage(val name: String, val detail: String, val section: String)

    /**
     * Damage to one Base64 section.
     *
     * Three options are in the pool *because* they decode to the identical bytes —
     * `Utils.parseSignedStatement` strips whitespace, accepts an unpadded tail, and throws away the
     * ignored bits of the last quantum — and they are where the "an equal pair must still verify"
     * control comes from.
     *
     * **Two more can decode identically too, and saying so is the honest version of that claim:**
     * dropping exactly the padding characters is also what `the section truncated` does when its
     * draw happens to match the padding length, and substituting an alphabet character into the
     * last quantum can land on a bit the decoder discards. Those are not mislabelled as
     * respellings: the main arm counts an equal pair under the class that produced it and floors
     * the three documented ones by name, so the tally shows which is which.
     *
     * What no option may produce is the genuine envelope **verbatim** — their criterion is the
     * envelope text, so a "mutant" identical to the original is one the main arm would judge while
     * demanding it fail to verify. The alphabet substitution is the one draw that could, so it
     * steps along the alphabet when it redraws the character already there.
     *
     * Each option that cannot apply falls through to one that always can, so the draw stays a pure
     * function of the seed rather than of a padding length. Both fallbacks are unreachable with
     * today's fixtures — every section ends in `=` — and are kept so the function stays total if a
     * fixture changes size.
     */
    private fun base64Damage(rnd: Random, section: String): Damage {
        val padding = section.takeLastWhile { it == '=' }.length
        return when (rnd.nextInt(8)) {
            0 -> if (padding > 0) {
                Damage(
                    "the padding dropped",
                    "the padding dropped (-$padding chars)",
                    section.dropLast(padding),
                )
            } else {
                newlineDamage(rnd, section)
            }

            1 -> newlineDamage(rnd, section)

            2 -> respellLastQuantum(section)?.let {
                Damage("the last quantum respelled", "the last quantum respelled", it)
            } ?: newlineDamage(rnd, section)

            3 -> {
                val at = rnd.nextInt(section.length - padding)
                val pick = rnd.nextInt(BASE64_ALPHABET.length)
                // Stepped rather than redrawn: the *drawn* parameters stay independent of the
                // fresh key's bytes, which is what keeps the digested plan reproducible, while the
                // produced character is still never the one it replaced.
                val replacement = BASE64_ALPHABET[
                    if (BASE64_ALPHABET[pick] == section[at]) {
                        (pick + 1) % BASE64_ALPHABET.length
                    } else {
                        pick
                    },
                ]
                Damage(
                    "an alphabet character substituted",
                    "an alphabet character substituted at=$at pick=$pick",
                    section.replaceRange(at, at + 1, replacement.toString()),
                )
            }

            4 -> {
                val at = rnd.nextInt(section.length)
                val pick = rnd.nextInt(NON_ALPHABET.length)
                Damage(
                    "a non-alphabet character substituted",
                    "a non-alphabet character substituted at=$at pick=$pick",
                    section.replaceRange(at, at + 1, NON_ALPHABET[pick].toString()),
                )
            }

            5 -> {
                val cut = 1 + rnd.nextInt(3)
                Damage(
                    "the section truncated",
                    "the section truncated (-$cut chars)",
                    section.dropLast(cut),
                )
            }

            6 -> {
                val pick = rnd.nextInt(APPENDAGES.size)
                Damage(
                    "characters appended",
                    "characters appended (\"${APPENDAGES[pick]}\")",
                    section + APPENDAGES[pick],
                )
            }

            else -> Damage("the section emptied", "the section emptied", "")
        }
    }

    private fun newlineDamage(rnd: Random, section: String): Damage {
        val at = 1 + rnd.nextInt(maxOf(1, section.length - 1))
        return Damage(
            "a newline inserted",
            "a newline inserted at=$at",
            section.substring(0, at) + "\n" + section.substring(at),
        )
    }

    /**
     * The last Base64 quantum respelled so that it decodes to the identical bytes.
     *
     * Two padding characters mean the final quantum encodes one byte in two characters, so the
     * second character's low four bits are thrown away; one padding character means two bytes in
     * three, so the third character's low two bits are. Flipping exactly those bits is a different
     * string carrying the same statement — which is the property this is here to produce.
     *
     * `null` when the section carries no padding and there is nothing ignorable to flip.
     */
    private fun respellLastQuantum(section: String): String? {
        val padding = section.takeLastWhile { it == '=' }.length
        if (padding == 0) return null
        val ignored = if (padding == 2) 0x0F else 0x03
        val at = section.length - padding - 1
        val value = BASE64_ALPHABET.indexOf(section[at])
        if (value < 0) return null
        val respelled = BASE64_ALPHABET[(value and ignored.inv()) or (value.inv() and ignored)]
        if (respelled == section[at]) return null
        return section.replaceRange(at, at + 1, respelled.toString())
    }

    private fun equalLengthTextPairs(layout: Layout): List<Pair<Int, Int>> =
        layout.textLen.indices.flatMap { i ->
            ((i + 1) until layout.textLen.size)
                .filter { layout.textLen[i] == layout.textLen[it] }
                .map { i to it }
        }

    // ── The three properties ─────────────────────────────────────────────

    /**
     * The main arm. Nothing throws; no mutant verifies; everything that parses re-encodes to the
     * bytes its envelope carried.
     *
     * Failure messages are built inside failure branches rather than handed to an `assertX`, which
     * would format a report for every one of a thousand passing mutants — the `DecoderFuzzTest`
     * convention, and the reason this file finishes in about a second.
     */
    @Test
    fun `no damaged envelope ever verifies, and none of them throws`() {
        val corpus = mutants()
        val judged = HashMap<Arm, Int>()
        val skipped = HashMap<Arm, Int>()
        var refusedAtParse = 0
        var parsed = 0
        var signatureInvalid = 0
        var otherVerdict = 0
        var canonicalRespellings = 0
        val respelledBy = HashMap<String, Int>()

        corpus.forEachIndexed { index, mutant ->
            fun bail(what: String, cause: Throwable? = null): Nothing =
                throw AssertionError(report(what, index, corpus.size, mutant), cause)

            val genuine = fixture(mutant.kind)

            // (i) Arms (a) and (b): a replacement that happens to equal what it replaced is the
            // genuine envelope, not a mutant, and judging it would demand that a genuine
            // statement fail to verify.
            //
            // (ii) The criterion is gated on the arm rather than on "the pre-image is unchanged",
            // and that gate is the whole of what the per-arm rule buys. Arm (c) carries a
            // byte-identical pre-image **by design** — presenting genuinely signed bytes under
            // another kind's framing tag, or another kind's signature over them, is exactly what
            // it tests — so an ungated criterion would skip all twelve of its mutants and this
            // file would pass having swept none of the six kind pairs.
            val skippable = mutant.arm == Arm.BYTES || mutant.arm == Arm.COMPONENTS
            if (skippable) {
                val damaged = mutant.preImage
                    ?: bail("arms (a) and (b) must report the pre-image bytes they built")
                if (damaged.contentEquals(genuine.preImage)) {
                    skipped.merge(mutant.arm, 1, Int::plus)
                    return@forEachIndexed
                }
            }

            // Whatever the arm, what is judged below must not be an envelope anyone genuinely
            // produced. Arms (c) and (d) are never skipped, so a pool entry edited into the
            // original — `"a later framing version" to "lim.env.v1"`, an alphabet substitution that
            // redrew the character already there — would be judged as a mutant while being the
            // real thing, and the "never VALID" property would then be demanding that a genuine
            // statement fail. Checked against all three fixtures, not just this mutant's own kind.
            if (Kind.values().any { mutant.text == fixture(it).envelope }) {
                bail("a mutant is byte-identical to a genuine envelope, so it is not a mutant")
            }

            val result = try {
                Utils.parseSignedStatement(mutant.text)
            } catch (t: Throwable) {
                bail("parseSignedStatement threw ${t.javaClass.name}", t)
            }
            judged.merge(mutant.arm, 1, Int::plus)

            if (result == null) {
                refusedAtParse++
                return@forEachIndexed
            }
            parsed++

            // Property three, over every damaged input that got this far rather than over the one
            // case `Utils.parseSignedStatement` checks it on internally.
            val carried = carriedPreImage(mutant.text)
                ?: bail("an envelope parsed but its pre-image section does not decode")
            if (mutant.preImage != null && !mutant.preImage.contentEquals(carried)) {
                bail(
                    "the generator's own bytes are not what the envelope carries, so this arm is " +
                        "damaging something other than what it reports",
                )
            }
            if (!reEncode(result).contentEquals(carried)) {
                bail(
                    "a parsed statement does not re-encode to the pre-image its envelope carried, " +
                        "so a verifier would check a signature against bytes the relay never sent",
                )
            }

            val verdict = try {
                verify(result)
            } catch (t: Throwable) {
                bail("the verifier threw ${t.javaClass.name}", t)
            }

            // (iii) The Base64 half of arm (d): the envelope text is not canonical, so a
            // respelling that decodes to the genuine pair must still verify. Asserting that rather
            // than skipping it turns the trap into a control.
            if (carriesGenuinePair(result, genuine)) {
                if (mutant.arm != Arm.FRAMING) {
                    bail("only arm (d) may re-spell its way back to the genuine pair")
                }
                canonicalRespellings++
                // Counted under the class that produced it, which is what makes the floors below
                // able to say *which* non-canonical spelling still decodes to the genuine pair. A
                // lumped counter would stay comfortably non-zero if `respellLastQuantum`'s ignored
                // -bit mask regressed and its mutants quietly became ordinary damage.
                mutant.classes.forEach { respelledBy.merge(it, 1, Int::plus) }
                if (verdict != StatementVerdict.VALID) {
                    bail(
                        "an envelope that decodes to the genuine statement and signature must " +
                            "still verify; got $verdict",
                    )
                }
                return@forEachIndexed
            }

            if (verdict == StatementVerdict.VALID) {
                bail("a damaged envelope was ACCEPTED as a genuine statement")
            }
            // Reported, deliberately not asserted at zero. A damaged statement earning some
            // verdict *other* than SIGNATURE_INVALID would mean the signature was not checked
            // first — a real property, and one `RotationVerificationTest` already owns with five
            // tests that redden when the window is moved ahead of the signature. Pinning check
            // order a second time here would duplicate it, and the duplicate is the copy that
            // drifts.
            if (verdict == StatementVerdict.SIGNATURE_INVALID) signatureInvalid++ else otherVerdict++
        }

        val tally = "mutants=${corpus.size} judged=${tallyOf(judged)} " +
            "skipped=${tallyOf(skipped)} refusedAtParse=$refusedAtParse parsed=$parsed " +
            "signatureInvalid=$signatureInvalid otherVerdict=$otherVerdict " +
            "canonicalRespellings=$canonicalRespellings by=$respelledBy"
        println("signed-statement fuzz: $tally")

        // A floor per arm, not one global counter: a global one stays non-zero on (a) and (b)
        // alone, so two deleted arms would leave it green.
        MINIMUM_JUDGED.forEach { (arm, minimum) ->
            assertTrue(
                "arm $arm judged ${judged[arm] ?: 0} mutants, below its floor of $minimum — that " +
                    "arm is not being swept at all. $tally",
                (judged[arm] ?: 0) >= minimum,
            )
        }

        // Each of the three properties is vacuous without one of these three.
        assertTrue(
            "no mutant was refused at the parse, so the framing rules checked nothing. $tally",
            refusedAtParse > 0,
        )
        assertTrue(
            "no mutant survived the parse, so the re-encode and verdict properties never ran — " +
                "and arm (b) in particular proves nothing unless it parses. $tally",
            parsed > 0,
        )
        assertTrue(
            "nothing came back SIGNATURE_INVALID, so no damaged statement was ever actually " +
                "verified against the stored key. $tally",
            signatureInvalid > 0,
        )
        assertTrue(
            "no envelope re-spelled its way back to the genuine pair, so the one control that " +
                "says the envelope text is non-canonical never ran. $tally",
            canonicalRespellings > 0,
        )
        // Per class, not just in total. Each of these three is a *separate* way the envelope text
        // fails to be canonical, and each has its own way of silently stopping: a dropped-padding
        // rule the decoder started rejecting, an insertion the whitespace filter stopped
        // stripping, or an ignored-bit mask the wrong way round. Any one of them would leave the
        // lumped counter above untouched, because the other two keep producing.
        listOf("the padding dropped", "a newline inserted", "the last quantum respelled")
            .forEach { how ->
                assertTrue(
                    "`$how` never decoded back to the genuine statement and signature, so that " +
                        "spelling of the envelope has stopped being non-canonical — or stopped " +
                        "being produced. $tally",
                    (respelledBy[how] ?: 0) > 0,
                )
            }
        assertTrue(
            "no mutant was skipped as unchanged, so the guard against judging the genuine " +
                "envelope as a mutant is dead code. $tally",
            skipped.values.sum() > 0,
        )
    }

    // ── Negative controls ────────────────────────────────────────────────

    /**
     * The accept-one-genuine floor, **per kind**: without it this file passes against a parser
     * hardcoded to `null`, and it would pass for two of the three kinds against one that only
     * understood rotations.
     */
    @Test
    fun `each of the three genuine envelopes parses and verifies`() {
        Kind.values().forEach { kind ->
            val fixture = fixture(kind)
            val parsed = Utils.parseSignedStatement(fixture.envelope)
                ?: throw AssertionError("the genuine $kind envelope must parse")
            assertTrue(
                "the genuine $kind envelope must read back as the statement it carries",
                carriesGenuinePair(parsed, fixture),
            )
            assertEquals(
                "the genuine $kind envelope must verify against the stored key, or every " +
                    "`never VALID` claim in this file is a property of a verifier that refuses " +
                    "everything",
                StatementVerdict.VALID,
                verify(parsed),
            )
        }
    }

    /** A forged signature over genuinely canonical bytes: refused, and refused for that reason. */
    @Test
    fun `a different keypair's signature over a genuine pre-image never verifies`() {
        Kind.values().forEach { kind ->
            val fixture = fixture(kind)
            val forged = signWith(attackerKeyPair.private, fixture.preImage)
            val parsed = Utils.parseSignedStatement(framed(kind, fixture.preImage, forged))
                ?: throw AssertionError("a forged envelope is still well-formed and must parse")
            assertEquals(
                "another device's signature over the right bytes is still another device's",
                StatementVerdict.SIGNATURE_INVALID,
                verify(parsed),
            )
        }
    }

    /**
     * Arm (c) stated as its own assertion rather than left to the main loop's "never VALID": every
     * one of the six ordered kind pairs, both shapes, refused.
     *
     * The sweep is the point. A signature over a rotation must not also be a signature over an
     * authorization that never expires, and `StatementEnvelopeTest` pins one pair of the six.
     *
     * Worth recording honestly: no mutation of `Utils` available today is killed by this arm.
     * `Utils.kt:1211-1219` documents, with the planting measured, that `statementComponents`'
     * kind-tag comparison is an equivalent mutant — the re-encode guard catches the same inputs one
     * step later. Under that plant the rotate↔recover pair, whose component shapes are identical,
     * parses and is then refused by the guard, while the four pairs involving a revocation die
     * earlier still on the shape mismatch: traced byte by byte, `rotate→revoke` and
     * `recover→revoke` both end on the nothing-left-over rule, and `revoke→rotate` and
     * `revoke→recover` both end inside `readBigEndian`'s width check — the third text's length
     * prefix reads the sequence long's four high bytes as a zero length, leaving four bytes where
     * the second 64-bit component needs eight. (`loop/queue.md` attributes two of those to
     * `readText`'s length check; that is where the trace actually lands.)
     *
     * So this arm's value is coverage of all six pairs; it becomes the arm that catches a removed
     * re-encode guard the day someone writes a second caller for `statementComponents`.
     */
    @Test
    fun `every ordered kind pair is refused, in both shapes`() {
        val pairs = HashSet<String>()
        kindMutants().forEach { mutant ->
            // Arm (c)'s `detail` opens with the tag the signature was genuinely made under, and
            // `kind` is the tag it is being presented as. A reworded detail would collapse the
            // set and fail the count below rather than quietly counting the wrong thing.
            pairs += mutant.detail.substringBefore(' ') + "->" + mutant.kind.tag
            val parsed = Utils.parseSignedStatement(mutant.text)
            if (parsed == null) return@forEach
            assertEquals(
                "a cross-kind envelope must never verify: ${mutant.detail}",
                StatementVerdict.SIGNATURE_INVALID,
                verify(parsed),
            )
        }
        assertEquals(
            "all six ordered kind pairs must be swept, not sampled; got $pairs",
            6,
            pairs.size,
        )
    }

    /**
     * The class of byte flip that makes a pre-image non-canonical **without changing its length**,
     * pinned directly because it is the only thing in arm (a) that can kill the weaker of the two
     * mutations this task plants.
     *
     * Most flips cannot. Overwriting a long's eight bytes re-encodes to exactly those bytes and an
     * equal-length component swap to the swapped bytes — both canonical, so neither is a deviation
     * at all. Truncation and append die on the nothing-left-over rule. And the common flip to a
     * byte `>= 0x80` starts a malformed run that decodes to U+FFFD and usually *lengthens* the
     * re-encoding, which a `reEncoded.size == preImage.size` check refuses anyway.
     *
     * What survives that check is a flip inside a **four-byte** sequence: `F0 9D 84 9E` with its
     * last byte flipped to ASCII leaves `F0 9D 84` as a three-byte malformed run, which decodes to
     * one U+FFFD and re-encodes to exactly three bytes, plus the ASCII byte — the same length,
     * different bytes. That is why the statement ids in this file's fixtures carry `é` and `𝄞`, and
     * why [ByteDamage.FLIP_UTF8_TAIL] aims at those positions rather than waiting for a uniform
     * flip to land on one of four bytes in nine hundred.
     */
    @Test
    fun `a flip inside a four-byte sequence keeps the pre-image length and breaks canonicality`() {
        val fixture = fixture(Kind.ROTATE)
        val layout = layoutOf(fixture)
        val (lead, width) = layout.multiByteSeqs.firstOrNull { it.second == 4 }
            ?: throw AssertionError(
                "no four-byte UTF-8 sequence in the genuine pre-image, so the one class of flip " +
                    "that can distinguish a byte-comparison from a length-comparison is absent " +
                    "from arm (a) entirely",
            )

        val damaged = fixture.preImage.copyOf()
        damaged[lead + width - 1] = 'A'.code.toByte()
        assertEquals("a flip never changes the byte count", fixture.preImage.size, damaged.size)

        val index = layout.textAt.indices.first {
            lead >= layout.textAt[it] && lead < layout.textAt[it] + layout.textLen[it]
        }
        val from = layout.textAt[index]
        val until = from + layout.textLen[index]
        val component = damaged.copyOfRange(from, until)
        val reEncoded = String(component, Charsets.UTF_8).toByteArray(Charsets.UTF_8)

        assertEquals(
            "the replacement character must be exactly as long as the malformed run it replaces, " +
                "or a length comparison would already have caught this",
            component.size,
            reEncoded.size,
        )
        assertFalse(
            "…and it must not be the same bytes, or the pre-image would be canonical",
            reEncoded.contentEquals(component),
        )
        assertNull(
            "so the envelope must be refused, by the byte comparison and not by a length one",
            Utils.parseSignedStatement(framed(Kind.ROTATE, damaged, fixture.signature)),
        )
    }

    /**
     * Generator floors. A pool is a claim about what gets exercised, and a claim nothing checks is
     * one that survives the draw weights drifting until the interesting shapes stop appearing.
     * Every count is reported rather than only the failing one, so a thin corpus is visible at a
     * glance.
     */
    @Test
    fun `the generator really produces the damage it claims`() {
        val corpus = mutants()
        val perArm = corpus.groupingBy { it.arm }.eachCount()
        val perLabel = corpus.groupingBy { it.label }.eachCount()
        val classes = corpus.flatMap { it.classes }.groupingBy { it }.eachCount()
        val tally = "perArm=$perArm perLabel=$perLabel classes=$classes"

        assertEquals(
            "the corpus must be exactly the four arms' mutants. $tally",
            BYTE_MUTANTS + COMPONENT_MUTANTS + 12 + FRAMING_MUTANTS,
            corpus.size,
        )
        assertEquals(
            "arm (c) sweeps six ordered pairs, two shapes each. $tally",
            12,
            perArm[Arm.KINDS] ?: 0,
        )

        // Every sub-kind of damage the class KDoc names, drawn at least once.
        (ByteDamage.values().map { it.label } + FramingDamage.values().map { it.label })
            .forEach { label ->
                assertTrue("the generator never drew `$label`. $tally", (perLabel[label] ?: 0) > 0)
            }

        listOf(
            // The flip class that can distinguish a byte comparison from a length comparison.
            CLASS_FOUR_BYTE_TAIL_FLIP,
            // Its superset: a flip to a byte that is valid single-byte UTF-8 on its own.
            CLASS_ASCII_FLIP,
            CLASS_SWAPPED_LONGS,
            CLASS_SWAPPED_TEXTS,
            // The draw that produces a "mutant" identical to the genuine envelope, which is what
            // the per-arm skip criterion exists for. Deliberately in the pool, so the guard is
            // exercised rather than left waiting on a coincidence.
            CLASS_IDENTITY_REPLACEMENT,
            // The three Base64 respellings that decode to the identical bytes.
            "the padding dropped",
            "a newline inserted",
            "the last quantum respelled",
        ).forEach { what ->
            assertTrue("the generator never drew `$what`. $tally", (classes[what] ?: 0) > 0)
        }

        // The offsets in the damage plan are drawn modulo the pre-image sizes, and those are fixed
        // only because an X.509-encoded RSA-2048 public key is always 294 bytes — 392 Base64
        // characters. A toolchain that encoded one differently would silently shift every offset
        // in the plan, so it is said out loud here rather than left to the digest to report as an
        // unexplained change.
        assertEquals(
            "the plan's reproducibility rests on a fixed key encoding length",
            392,
            storedPublicKey.length,
        )
        Kind.values().forEach { kind ->
            val fixture = fixture(kind)
            // `layoutOf` throws if the layout this file aims at is not the one the encoder
            // produced, so calling it here checks all three fixtures rather than only the two
            // kinds the draw happens to reach first.
            assertTrue(
                "every fixture must carry a multi-byte component, or arm (a)'s UTF-8 sub-kind " +
                    "has nowhere to aim on ${kind.tag}",
                layoutOf(fixture).multiByteSeqs.isNotEmpty(),
            )
            assertEquals(
                "an RSA-2048 signature is 256 bytes; the plan's section damage assumes it",
                256,
                fixture.signature.size,
            )
        }
    }

    /**
     * The change-detector for the corpus itself.
     *
     * What is pinned is the **damage plan** — arm, label, kind, drawn parameters and the classes
     * each draw belongs to — and not the envelope strings, because the keypair is fresh on every
     * run and a committed private key is not something this repository will carry. The plan is what
     * has to be reproducible for a failure report naming an index to be actionable.
     *
     * The fixture sizes are digested alongside it: they are what the plan's offsets are drawn
     * modulo, so a toolchain that changed them has changed the corpus and should say so here.
     *
     * Not one of the safety assertions. It catches an *accidental* edit to the generator, which
     * would silently swap the corpus for a different one and make every earlier failure report in
     * the log unreproducible. Recomputing it is correct when the generator was edited on purpose,
     * and wrong every other time. `DecoderFuzzTest`'s `CORPUS_DIGEST` is a separate constant over a
     * separate generator and is untouched by this file.
     */
    @Test
    fun `the damage plan is identical on every run`() {
        val digest = MessageDigest.getInstance("SHA-256")
        Kind.values().forEach { kind ->
            val fixture = fixture(kind)
            digest.update(kind.name.toByteArray(Charsets.UTF_8))
            digest.update(bigEndian(fixture.preImage.size.toLong(), 4))
            digest.update(bigEndian(fixture.signature.size.toLong(), 4))
        }
        mutants().forEach { mutant ->
            digest.update(mutant.arm.name.toByteArray(Charsets.UTF_8))
            digest.update(mutant.label.toByteArray(Charsets.UTF_8))
            digest.update(mutant.kind.name.toByteArray(Charsets.UTF_8))
            digest.update(mutant.detail.toByteArray(Charsets.UTF_8))
            mutant.classes.sorted().forEach { digest.update(it.toByteArray(Charsets.UTF_8)) }
        }
        assertEquals(
            "the damage plan changed; update ENVELOPE_CORPUS_DIGEST only if the generator was " +
                "edited deliberately",
            ENVELOPE_CORPUS_DIGEST,
            hex(digest.digest()),
        )
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private fun drawKind(rnd: Random): Kind = Kind.values()[rnd.nextInt(Kind.values().size)]

    private fun fixture(kind: Kind): Fixture = fixtures.getValue(kind)

    /**
     * An envelope built by hand around arbitrary bytes.
     *
     * The framing literals are spelled out rather than read from [Utils]: a harness that builds its
     * framing from the constants it is testing is a harness that moves with them, which is the same
     * reason `IntentBuilderTest` pins the wire format as literals.
     */
    private fun framed(kind: Kind, preImage: ByteArray, signature: ByteArray): String =
        ENVELOPE_MARKER + ":" + kind.tag + ":" +
            Base64.encodeToString(preImage, Base64.NO_WRAP) + ":" +
            Base64.encodeToString(signature, Base64.NO_WRAP)

    /** Arm (b) goes through the production encoders, so its pre-images are canonical. */
    private fun encode(
        kind: Kind,
        texts: List<String>,
        longs: List<Long>,
        signature: ByteArray,
    ): String = when (kind) {
        Kind.ROTATE -> Utils.encodeRotationStatement(rotation(texts, longs), signature)
        Kind.RECOVER -> Utils.encodeRecoveryAuthorization(recovery(texts, longs), signature)
        Kind.REVOKE -> Utils.encodeRevocation(revocation(texts, longs), signature)
    }

    private fun preImageOf(kind: Kind, texts: List<String>, longs: List<Long>): ByteArray =
        when (kind) {
            Kind.ROTATE -> Utils.rotationStatementBytes(rotation(texts, longs))
            Kind.RECOVER -> Utils.recoveryAuthorizationBytes(recovery(texts, longs))
            Kind.REVOKE -> Utils.revocationBytes(revocation(texts, longs))
        }

    private fun reEncode(parsed: SignedStatement): ByteArray = when (parsed) {
        is SignedStatement.Rotate -> Utils.rotationStatementBytes(parsed.statement)
        is SignedStatement.Recover -> Utils.recoveryAuthorizationBytes(parsed.authorization)
        is SignedStatement.Revoke -> Utils.revocationBytes(parsed.revocation)
    }

    /** The verifier matching the kind that was actually parsed, at a clock inside the window. */
    private fun verify(parsed: SignedStatement): StatementVerdict = when (parsed) {
        is SignedStatement.Rotate -> Utils.verifyRotationStatement(
            parsed.statement,
            parsed.signature,
            storedPublicKey,
            FUZZ_CLOCK,
        )

        is SignedStatement.Recover -> Utils.verifyRecoveryAuthorization(
            parsed.authorization,
            parsed.signature,
            storedPublicKey,
        )

        is SignedStatement.Revoke -> Utils.verifyRevocation(
            parsed.revocation,
            parsed.signature,
            storedPublicKey,
        )
    }

    /**
     * Whether what parsed is the genuine statement *and* the genuine signature.
     *
     * Stated over the parsed pair rather than by decoding the two sections with a second Base64
     * reader: `Utils.parseSignedStatement` guarantees the returned statement re-encodes to the
     * bytes that arrived, so an equal statement and an equal signature is exactly "the decoded pair
     * is the genuine pair" — and a reader written here to check it would be a second
     * implementation of the acceptance rules this file is supposed to be testing.
     */
    private fun carriesGenuinePair(parsed: SignedStatement, genuine: Fixture): Boolean {
        val statementMatches = when (parsed) {
            is SignedStatement.Rotate ->
                genuine.kind == Kind.ROTATE &&
                    parsed.statement == rotation(genuine.texts, genuine.longs)

            is SignedStatement.Recover ->
                genuine.kind == Kind.RECOVER &&
                    parsed.authorization == recovery(genuine.texts, genuine.longs)

            is SignedStatement.Revoke ->
                genuine.kind == Kind.REVOKE &&
                    parsed.revocation == revocation(genuine.texts, genuine.longs)
        }
        return statementMatches && parsed.signature.contentEquals(genuine.signature)
    }

    /**
     * The pre-image the text itself carries, decoded as the parser decoded it.
     *
     * A plain decode and not a copy of `Utils`'s acceptance rules: this is only ever called on a
     * text that already parsed, so the section is known to be acceptable Base64 and the only
     * question left is what bytes it holds.
     */
    private fun carriedPreImage(text: String): ByteArray? {
        val sections = text.trim().split(':')
        if (sections.size != 4) return null
        return try {
            Base64.decode(sections[2].filterNot { it.isWhitespace() }, Base64.DEFAULT)
        } catch (_: Exception) {
            null
        }
    }

    private fun rotation(texts: List<String>, longs: List<Long>) = RotationStatement(
        oldPublicKey = texts[0],
        newPublicKey = texts[1],
        statementId = texts[2],
        issuedAtMillis = longs[0],
        expiresAtMillis = longs[1],
    )

    private fun recovery(texts: List<String>, longs: List<Long>) = RecoveryAuthorization(
        subjectPublicKey = texts[0],
        recoveryPublicKey = texts[1],
        authorizationId = texts[2],
        sequence = longs[0],
        issuedAtMillis = longs[1],
    )

    private fun revocation(texts: List<String>, longs: List<Long>) = Revocation(
        subjectPublicKey = texts[0],
        revokedAuthorizationId = texts[1],
        sequence = longs[0],
        issuedAtMillis = longs[1],
    )

    private fun tallyOf(counts: Map<Arm, Int>): String =
        Arm.values().joinToString(",") { "$it=${counts[it] ?: 0}" }

    private fun report(what: String, index: Int, total: Int, mutant: Mutant): String = buildString {
        append(what).append('\n')
        append("  corpusSeed = ").append(CORPUS_SEED).append("L\n")
        append("  mutant     = #").append(index).append(" of ").append(total).append('\n')
        append("  arm        = ").append(mutant.arm).append('\n')
        append("  damage     = ").append(mutant.label).append('\n')
        append("  kind       = ").append(mutant.kind.tag).append('\n')
        append("  detail     = ").append(mutant.detail).append('\n')
        if (mutant.classes.isNotEmpty()) {
            append("  classes    = ").append(mutant.classes.sorted()).append('\n')
        }
        append("  envelope   = ").append(printable(mutant.text))
    }

    /** Escape everything unprintable so an envelope survives a log file, and cap the length. */
    private fun printable(text: String): String {
        val capped = text.take(ENVELOPE_PREVIEW)
        val escaped = buildString(capped.length) {
            capped.forEach { c ->
                if (c in ' '..'~') {
                    append(c)
                } else {
                    append("\\u")
                    append(HEX[(c.code shr 12) and 0xF])
                    append(HEX[(c.code shr 8) and 0xF])
                    append(HEX[(c.code shr 4) and 0xF])
                    append(HEX[c.code and 0xF])
                }
            }
        }
        return if (text.length > ENVELOPE_PREVIEW) {
            "\"" + escaped + "\"... (+" + (text.length - ENVELOPE_PREVIEW) + " more chars)"
        } else {
            "\"" + escaped + "\""
        }
    }

    companion object {

        /** Arbitrary; what matters is only that it never changes. */
        private const val CORPUS_SEED = 0x4C494D20543234L

        /**
         * Mutants per arm. Arm (c) is not drawn — it is the exhaustive sweep of the six ordered
         * kind pairs, two shapes each, so it is always twelve.
         *
         * Sized against the runtime recorded in the class KDoc: every mutant costs a Base64
         * round trip of the whole pre-image and every one that parses costs an RSA verification.
         */
        private const val BYTE_MUTANTS = 400
        private const val COMPONENT_MUTANTS = 300
        private const val FRAMING_MUTANTS = 300

        /**
         * The per-arm floors — a single global counter could not do this job, since arms (a) and
         * (b) alone would keep it non-zero while two deleted arms went unnoticed.
         *
         * **Hard literals, deliberately, and not fractions of the arm's own size constant.** A
         * floor written as `BYTE_MUTANTS / 2` moves with the thing it is supposed to constrain:
         * `BYTE_MUTANTS = 0` would make the floor `0` and leave the main test green. Written as
         * numbers, cutting an arm to a handful for a quick local run and committing it reddens the
         * main test, which is the edit these exist to catch.
         *
         * Two of the four carry slack and two do not, which is worth being exact about rather than
         * describing all four as having margin: arms (a) and (b) are skippable, so their floors sit
         * well below the observed 395 and 253, while arms (c) and (d) are **never** skipped, so
         * their floors are exact — 12 and 300 against 12 and 300. There is no variation there for a
         * margin to absorb, and nothing that can fall short of them without a throw or a hard
         * failure first.
         */
        private val MINIMUM_JUDGED = mapOf(
            Arm.BYTES to 200,
            Arm.COMPONENTS to 150,
            Arm.KINDS to 12,
            Arm.FRAMING to 300,
        )

        /**
         * See `the damage plan is identical on every run`. Captured from the first run that also
         * passed the three properties and the generator floors; a change-detector from then on, and
         * nothing else.
         */
        private const val ENVELOPE_CORPUS_DIGEST =
            "030078e531f0cbac832c29a8c457c1cc600e1b6deff0717c957681a4c3419c1b"

        /** A fixed clock inside every fixture's window, so a verdict means the same on every run. */
        private const val FUZZ_CLOCK = 1_770_000_000_000L

        /** The framing marker, spelled out rather than read from the constant under test. */
        private const val ENVELOPE_MARKER = "lim.env.v1"

        /** The documented layout's three fixed widths, likewise spelled out. */
        private const val DOMAIN_BYTES = 16
        private const val LENGTH_PREFIX_BYTES = 4
        private const val STATEMENT_LONG_BYTES = 8

        private const val ENVELOPE_PREVIEW = 400
        private const val HEX = "0123456789abcdef"

        private const val BASE64_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

        /** Characters the envelope's Base64 rules must refuse. A colon would change the section
         *  count instead, which arm (d) covers separately. */
        private const val NON_ALPHABET = "!-_. *#é"

        /**
         * Junk appended to a Base64 section.
         *
         * A thin spot, recorded rather than overclaimed: every section here ends in padding (a
         * 2048-bit signature is 256 bytes, so always `==`; all three pre-images likewise), so an
         * appendage either puts a `=` mid-string or makes the length `% 4 == 1`, and
         * `Utils.parseSignedStatement` refuses both. These are therefore always `null`, and the
         * one acceptance path its KDoc describes — "junk that is itself well-formed Base64 changes
         * the signature and comes back SIGNATURE_INVALID" — is unreachable from an RSA-2048
         * fixture. `StatementEnvelopeTest`'s `trailing garbage is refused` reaches it by building
         * an unpadded signature section by hand, and the parses-then-SIGNATURE_INVALID shape is
         * covered here by the alphabet substitution.
         */
        private val APPENDAGES = listOf("cafe", "A", "=", "AAAA")

        private const val CLASS_ASCII_FLIP = "a flip to a single-byte UTF-8 value"
        private const val CLASS_FOUR_BYTE_TAIL_FLIP = "a flip inside a four-byte sequence"
        private const val CLASS_SWAPPED_LONGS = "the two long components swapped"
        private const val CLASS_SWAPPED_TEXTS = "two equal-length text components swapped"
        private const val CLASS_IDENTITY_REPLACEMENT = "a replacement equal to what it replaced"

        /**
         * Bytes a flip draws from: printable ASCII, the boundaries of the single-byte range, bare
         * continuation bytes, every multi-byte lead width, and the two values no UTF-8 sequence may
         * begin with.
         */
        private val BYTE_POOL = byteArrayOf(
            0x00, 0x09, 0x20, 0x30, 0x41, 0x61, 0x7A, 0x7E, 0x7F,
            0x80.toByte(), 0xBF.toByte(), 0xC0.toByte(), 0xC3.toByte(), 0xE0.toByte(),
            0xE2.toByte(), 0xF0.toByte(), 0xF4.toByte(), 0xF5.toByte(), 0xFF.toByte(),
        )

        /** Single-byte UTF-8 values only, for the flip that aims inside a multi-byte sequence. */
        private val ASCII_POOL = byteArrayOf(0x20, 0x30, 0x41, 0x61, 0x7E, 0x00)

        /** The arithmetic edges a timestamp or a sequence can arrive as. */
        private val LONG_POOL = listOf(
            0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE, FUZZ_CLOCK, -FUZZ_CLOCK,
        )

        /**
         * Replacements for a text component. The identity is in the pool deliberately: it is what
         * produces a "mutant" that is really the genuine envelope, and the per-arm skip criterion
         * exists for exactly that draw.
         */
        private val TEXT_REPLACEMENTS: List<Pair<String, (String) -> String>> = listOf(
            "itself" to { it },
            "the empty string" to { "" },
            "one character" to { "x" },
            "its last character dropped" to { it.dropLast(1) },
            "a multi-byte character appended" to { it + "é" },
            "an astral character appended" to { it + "𝄞" },
            "four kilobytes" to { "x".repeat(4096) },
            "the attacker's key" to { attackerPublicKey },
            "the replacement key" to { replacementPublicKey },
            "the stored key" to { storedPublicKey },
        )

        /** Replacements for a 64-bit component, the identity included for the same reason. */
        private val LONG_REPLACEMENTS: List<Pair<String, (Long, Random) -> Long>> = listOf(
            "itself" to { value, _ -> value },
            "zero" to { _, _ -> 0L },
            "one more" to { value, _ -> value + 1 },
            "one less" to { value, _ -> value - 1 },
            "Long.MIN_VALUE" to { _, _ -> Long.MIN_VALUE },
            "Long.MAX_VALUE" to { _, _ -> Long.MAX_VALUE },
            "negated" to { value, _ -> -value },
            "a drawn value" to { _, rnd -> rnd.nextLong() },
        )

        /** Framing markers a peer might send, none of which this version may read. */
        private val MARKERS = listOf(
            "a later framing version" to "lim.env.v2",
            "the marker upper-cased" to "LIM.ENV.V1",
            "an empty marker" to "",
            "the marker with a trailing space" to "lim.env.v1 ",
            "a truncated marker" to "lim.env",
            "the marker with a digit appended" to "lim.env.v11",
            "the domain prefix as a marker" to "lim.statement.v1",
        )

        /** Kind tags in the framing that no version of this library claims. */
        private val KIND_TAGS: List<Pair<String, (String) -> String>> = listOf(
            "a later rotation version" to { "lim.rotate.v2" },
            "a later recovery version" to { "lim.recover.v2" },
            "an empty tag" to { "" },
            "the tag upper-cased" to { it.uppercase() },
            "the domain prefix" to { "lim.statement.v1" },
            "the tag with a character appended" to { it + "x" },
            "the tag with a leading space" to { " $it" },
        )

        /** Section counts other than four; anything but four is damage. */
        private val SECTION_SHAPES: List<Pair<String, (List<String>) -> String>> = listOf(
            "the signature section dropped" to { it.dropLast(1).joinToString(":") },
            "the marker dropped" to { it.drop(1).joinToString(":") },
            "the kind tag dropped" to { (it.take(1) + it.drop(2)).joinToString(":") },
            "a fifth section appended" to { (it + "cafe").joinToString(":") },
            "an empty fifth section" to { (it + "").joinToString(":") },
            "an empty section inserted" to {
                (it.take(2) + "" + it.drop(2)).joinToString(":")
            },
            "no separators at all" to { it.joinToString("") },
        )

        private lateinit var keyPair: KeyPair
        private lateinit var attackerKeyPair: KeyPair
        private lateinit var storedPublicKey: String
        private lateinit var replacementPublicKey: String
        private lateinit var attackerPublicKey: String
        private lateinit var fixtures: Map<Kind, Fixture>

        /**
         * 2048-bit RSA generation is slow (~100ms each); do it once for the whole class — the
         * `DecoderFuzzTest` pattern.
         *
         * Three keys: the stored one every verifier is called with, a real replacement (a rotation
         * onto the stored key is `SAME_KEY` and one onto anything that is not an RSA key is
         * `NEW_KEY_UNUSABLE`, either of which would make the accept-one-genuine floor unreachable
         * for the wrong reason), and an attacker's, for the forged-signature control.
         *
         * **The statement ids carry `é` and `𝄞` on purpose.** A four-byte UTF-8 sequence is the
         * only place a single flipped byte can leave a pre-image non-canonical *at the same byte
         * length*, which is the one class of byte damage that distinguishes a byte comparison from a
         * length comparison — see
         * `a flip inside a four-byte sequence keeps the pre-image length and breaks canonicality`.
         * Ids are opaque text in this protocol, so nothing about this is unrepresentative.
         */
        @JvmStatic
        @BeforeClass
        fun generateKeys() {
            fun generate() = KeyPairGenerator.getInstance("RSA")
                .apply { initialize(2048) }
                .generateKeyPair()

            keyPair = generate()
            attackerKeyPair = generate()
            storedPublicKey = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
            replacementPublicKey = Base64.encodeToString(generate().public.encoded, Base64.NO_WRAP)
            attackerPublicKey =
                Base64.encodeToString(attackerKeyPair.public.encoded, Base64.NO_WRAP)

            fixtures = listOf(
                fixtureOf(
                    Kind.ROTATE,
                    listOf(storedPublicKey, replacementPublicKey, "rot-fuzz-é𝄞-1"),
                    listOf(FUZZ_CLOCK - 1_000L, FUZZ_CLOCK + 1_000L),
                ),
                fixtureOf(
                    Kind.RECOVER,
                    listOf(storedPublicKey, replacementPublicKey, "rec-fuzz-é𝄞-1"),
                    listOf(7L, FUZZ_CLOCK),
                ),
                fixtureOf(
                    Kind.REVOKE,
                    listOf(storedPublicKey, "rec-fuzz-é𝄞-1"),
                    listOf(8L, FUZZ_CLOCK),
                ),
            ).associateBy { it.kind }
        }

        /**
         * One genuine statement, signed over its canonical pre-image with `SHA256withRSA` — the
         * same primitive `Utils.verifySignature` uses, and no caller-supplied algorithm anywhere.
         */
        private fun fixtureOf(kind: Kind, texts: List<String>, longs: List<Long>): Fixture {
            val preImage = when (kind) {
                Kind.ROTATE -> Utils.rotationStatementBytes(
                    RotationStatement(texts[0], texts[1], texts[2], longs[0], longs[1]),
                )

                Kind.RECOVER -> Utils.recoveryAuthorizationBytes(
                    RecoveryAuthorization(texts[0], texts[1], texts[2], longs[0], longs[1]),
                )

                Kind.REVOKE -> Utils.revocationBytes(
                    Revocation(texts[0], texts[1], longs[0], longs[1]),
                )
            }
            val signature = signWith(keyPair.private, preImage)
            return Fixture(
                kind = kind,
                texts = texts,
                longs = longs,
                preImage = preImage,
                signature = signature,
                envelope = ENVELOPE_MARKER + ":" + kind.tag + ":" +
                    Base64.encodeToString(preImage, Base64.NO_WRAP) + ":" +
                    Base64.encodeToString(signature, Base64.NO_WRAP),
            )
        }

        private fun signWith(key: PrivateKey, bytes: ByteArray): ByteArray =
            Signature.getInstance("SHA256withRSA").run {
                initSign(key)
                update(bytes)
                sign()
            }

        /** [value]'s low [width] bytes written into [bytes] at [at], most significant first. */
        private fun writeBigEndian(bytes: ByteArray, at: Int, value: Long, width: Int) {
            for (i in 0 until width) {
                bytes[at + i] = ((value ushr (8 * (width - 1 - i))) and 0xFF).toByte()
            }
        }

        private fun bigEndian(value: Long, width: Int): ByteArray =
            ByteArray(width) { ((value ushr (8 * (width - 1 - it))) and 0xFF).toByte() }

        private fun swap(bytes: ByteArray, left: Int, right: Int, width: Int) {
            for (i in 0 until width) {
                val held = bytes[left + i]
                bytes[left + i] = bytes[right + i]
                bytes[right + i] = held
            }
        }

        private fun hex(bytes: ByteArray): String = buildString(bytes.size * 2) {
            bytes.forEach { b ->
                val v = b.toInt() and 0xFF
                append(HEX[v shr 4])
                append(HEX[v and 0xF])
            }
        }
    }
}
