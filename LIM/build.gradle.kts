import com.vanniktech.maven.publish.AndroidSingleVariantLibrary

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    id("org.jetbrains.kotlin.plugin.parcelize")
    alias(libs.plugins.vanniktech.publish)
}

android {
    namespace = "dev.eryalabs.lim"
    compileSdk = 36

    defaultConfig {
        minSdk = 24

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            isShrinkResources = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }

    testOptions {
        unitTests {
            // Robolectric needs the merged resources and manifest to boot a sandbox.
            isIncludeAndroidResources = true
        }
    }

    // Deliberately no `publishing { singleVariant("release") }` block here. The Maven Central
    // configuration at the bottom of this file declares the release variant, its sources jar
    // and its javadoc jar itself; declaring the variant in both places makes AGP fail with
    // "Publishing for variant 'release' is already configured".
}

dependencies {
    // Gson is the only runtime dependency — field maps are serialised over IPC as JSON.
    implementation("com.google.code.gson:gson:2.13.2")

    testImplementation(libs.junit)

    // Test-only. Utils touches android.util.Base64, Context and Intent, all of which are
    // unimplemented stubs in a plain JVM unit test — Robolectric supplies real behaviour so
    // the protocol can be verified on the host with no device, no network and no keystore.
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.test:core:1.6.1")

    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

// ---------------------------------------------------------------------------------------
// The documents the unit-test suite reads off disk, declared as inputs of the test task.
//
// Gradle decides whether a task is UP-TO-DATE from its *declared* inputs. The main and test
// sources are inputs because they are compiled, which is why nobody noticed this: a document
// is opened at test time with `File.readText`, and Gradle cannot see that. So a commit whose
// only change was one of the files below came back `Task :LIM:testDebugUnitTest UP-TO-DATE`
// and executed nothing — a green gate over an unexecuted test. Measured, not inferred: with
// `CHANGELOG.md` moved out of the tree the gate was BUILD SUCCESSFUL, while `--rerun-tasks`
// on the same tree failed 7 `ChangelogTest` tests; and breaking one member name in a
// `CHANGELOG.md` bullet was green with no `--rerun` while reddening 4 of them with one.
// Three of the four release-readiness artifacts are documents, so Definition-of-done item 1
// proved nothing at all for exactly the commits that change them.
//
// `BuildInputsTest` holds this list honest in both directions: every path here must exist on
// disk, every path here must appear below under its own `withPropertyName`, and every
// repository file a test source names must be in it — so the *next* test that reads a new
// document fails loudly instead of quietly never running.
//
// Two things this block deliberately does not do:
//
//  * It does not name anything under `src/`. This list is about documents, and a source
//    directory in it would say otherwise. Note that "sources are compiled, so editing one
//    already invalidates the task" is NOT true of a comment edit that leaves the class files
//    byte-identical, which was measured — see the scope note on `BuildInputsTest`. That
//    residual hole is a separate decision about the cache, not part of this one.
//  * It is not `outputs.upToDateWhen { false }`. That would make every edit anywhere re-run
//    the whole suite for ever while pinning nothing — it cannot tell a changed document from
//    a changed `LICENSE`, so it buys the appearance of this fix at the price of the cache.
//
// The paths are resolved against the repository root rather than this module directory, which
// sits one level below the files it has to name; `withPathSensitivity(RELATIVE)` then keeps
// the absolute location out of the cache key, so the key is the same on another machine.
// ---------------------------------------------------------------------------------------
tasks.withType<Test>().configureEach {
    val repository = rootProject.layout.projectDirectory

    inputs.files(repository.file("CHANGELOG.md"))
        .withPathSensitivity(PathSensitivity.RELATIVE)
        .withPropertyName("verifiedDocument:CHANGELOG.md")
    inputs.files(repository.file("README.md"))
        .withPathSensitivity(PathSensitivity.RELATIVE)
        .withPropertyName("verifiedDocument:README.md")
    inputs.files(repository.file("docs/INTEGRATION.md"))
        .withPathSensitivity(PathSensitivity.RELATIVE)
        .withPropertyName("verifiedDocument:docs/INTEGRATION.md")
    inputs.files(repository.file("LIM/api/lim.api"))
        .withPathSensitivity(PathSensitivity.RELATIVE)
        .withPropertyName("verifiedDocument:LIM/api/lim.api")
    inputs.files(repository.file("gradle/libs.versions.toml"))
        .withPathSensitivity(PathSensitivity.RELATIVE)
        .withPropertyName("verifiedDocument:gradle/libs.versions.toml")
    inputs.files(repository.file("settings.gradle.kts"))
        .withPathSensitivity(PathSensitivity.RELATIVE)
        .withPropertyName("verifiedDocument:settings.gradle.kts")
    inputs.files(repository.file("LIM/build.gradle.kts"))
        .withPathSensitivity(PathSensitivity.RELATIVE)
        .withPropertyName("verifiedDocument:LIM/build.gradle.kts")
    inputs.files(repository.file("LIM/consumer-rules.pro"))
        .withPathSensitivity(PathSensitivity.RELATIVE)
        .withPropertyName("verifiedDocument:LIM/consumer-rules.pro")
}

// ---------------------------------------------------------------------------------------
// Maven Central, via the Sonatype Central Portal.
//
// Chosen over JitPack because JitPack can only ever serve `com.github.Erya-Labs:LIM`, while
// every document the project publishes advertises `dev.eryalabs.lim:lim`. Central serves the
// coordinate as declared, so the docs stay true.
//
// A released version on Central is PERMANENT — it can never be altered or withdrawn. Check
// the POM below before the first release; after that it is public forever.
//
// No credential lives in this repository. Gradle reads these from ~/.gradle/gradle.properties:
//   mavenCentralUsername / mavenCentralPassword       Portal *user token*, not the account login
//   signingInMemoryKey / signingInMemoryKeyPassword   ASCII-armoured GPG secret key
// ---------------------------------------------------------------------------------------
mavenPublishing {
    configure(AndroidSingleVariantLibrary("release", sourcesJar = true, publishJavadocJar = true))

    coordinates("dev.eryalabs.lim", "lim", "1.1.0")

    pom {
        name.set("LIM")
        description.set(
            "Local Identity Management for Android: personal data stays encrypted on the " +
                "device, a service receives only an RSA public key, and individual fields " +
                "are disclosed per request with the user's consent."
        )
        inceptionYear.set("2026")
        url.set("https://github.com/Erya-Labs/LIM")

        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            // No email address: a POM on Central is public and permanent.
            developer {
                id.set("eryalabs")
                name.set("Erya Labs")
                url.set("https://eryalabs.dev")
            }
        }
        scm {
            url.set("https://github.com/Erya-Labs/LIM")
            connection.set("scm:git:git://github.com/Erya-Labs/LIM.git")
            developerConnection.set("scm:git:ssh://git@github.com/Erya-Labs/LIM.git")
        }
    }

    publishToMavenCentral()
    signAllPublications()
}
