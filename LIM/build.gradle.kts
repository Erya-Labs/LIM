plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    id("org.jetbrains.kotlin.plugin.parcelize")
    id("maven-publish")
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

    publishing {
        singleVariant("release"){
            withSourcesJar()
            withJavadocJar()
        }
    }
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

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "dev.eryalabs.lim"
                artifactId = "lim"
                version = "1.0.0"
            }
        }
    }
}