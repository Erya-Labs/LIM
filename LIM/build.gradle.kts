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

    coordinates("dev.eryalabs.lim", "lim", "1.0.0")

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
