import java.io.File
import java.security.MessageDigest
import java.util.Properties

plugins {
    id("com.android.application")
}

/*
 * ndk-build receives APP_BUILD_SCRIPT as an unquoted command-line argument, so a project path containing a
 * space makes it silently find no modules ("Android NDK: WARNING: There are no modules to build"). CMake
 * would not have this problem but cannot be downloaded on this network. The sources stay in the repository
 * under app/src/main/jni and are mirrored to a space-free directory at configuration time, so there is one
 * copy to edit and no manual step to remember. The mirror is wiped first: without that, sources deleted from
 * app/src/main/jni silently persist in the mirror and keep being compiled.
 */
val jniDir = File((providers.gradleProperty("jniMirrorDir").orNull ?: "C:/Android/nordjunk-jni").toString())
project.delete(jniDir)
project.copy {
    from("src/main/jni")
    into(jniDir)
}
val jniScript = File(jniDir, "Android.mk")

/*
 * ndk-build also receives NDK_OUT and NDK_LIBS_OUT unquoted, so mirroring the sources is not enough:
 * the build directory itself has to be on a space-free path. Override with -PbuildDir=... if this
 * machine keeps its builds elsewhere; the APK then lands in <buildDir>/outputs/apk/release.
 */
layout.buildDirectory.set(
    File((providers.gradleProperty("buildMirrorDir").orNull ?: "C:/Android/nordjunk-build").toString())
)

android {
    namespace = "com.nordoptimizer.lsposed"
    compileSdk = 34

    defaultConfig {
        minSdk = 27
        targetSdk = 34
        applicationId = "com.nordoptimizer.lsposed"
        versionCode = 13
        versionName = "1.8.2"

        // Debug aid for bisection: -PhookGroups=moose installs only that group, so a target app that
        // reacts badly can be narrowed to one hook set without editing source each time.
        val hookGroups = project.findProperty("hookGroups")?.toString() ?: "all"
        buildConfigField("String", "HOOK_GROUPS", "\"$hookGroups\"")
    }

    // The NordLynx handshake socket belongs to libtelio.so, so junk has to be written from native code:
    // see app/src/main/jni/nordjunk.c for the four measurements that ruled the Java routes out.
    ndkVersion = "27.3.13750724"
    externalNativeBuild {
        ndkBuild {
            path = jniScript
        }
    }

    buildFeatures {
        buildConfig = true
    }

    signingConfigs {
        create("release") {
            val ksProps = Properties()
            val ksFile = rootProject.file("keystore.properties")
            if (ksFile.exists()) {
                ksProps.load(ksFile.inputStream())
                storeFile = rootProject.file(ksProps.getProperty("keystorePath"))
                storePassword = ksProps.getProperty("keystorePassword")
                keyAlias = ksProps.getProperty("keystoreAlias")
                keyPassword = ksProps.getProperty("keystoreAliasPassword")
            } else {
                val customKeystore = project.findProperty("keystorePath")
                if (customKeystore != null) {
                    storeFile = File(customKeystore.toString())
                    storePassword = project.findProperty("keystorePassword")?.toString()
                    keyAlias = project.findProperty("keyAlias")?.toString()
                    keyPassword = project.findProperty("keyPassword")?.toString()
                } else {
                    storeFile = file(System.getProperty("user.home") + "/.android/debug.keystore")
                    storePassword = "android"
                    keyAlias = "debug"
                    keyPassword = "android"
                }
            }
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs["release"]
        }
        debug {
            signingConfig = signingConfigs["release"]
        }
    }

    applicationVariants.all {
        outputs.all {
            if (this is com.android.build.gradle.internal.api.BaseVariantOutputImpl) {
                outputFileName = "NordOptimizer-v${versionName}-signed.apk"
            }
        }
    }
}

dependencies {
    compileOnly(files("libs/xposed-api-stub.jar"))
}

tasks.register("checksums") {
    dependsOn("assembleRelease")

    doLast {
        val apkDir = layout.buildDirectory.dir("outputs/apk/release").get().asFile
        val versionName = android.defaultConfig.versionName
        val apk = File(apkDir, "NordOptimizer-v${versionName}-signed.apk")

        if (apk.exists()) {
            fun digest(algorithm: String): String =
                MessageDigest.getInstance(algorithm).let { md ->
                    apk.inputStream().use { input ->
                        val buf = ByteArray(64 * 1024)
                        var n: Int
                        while (input.read(buf).also { n = it } > 0) md.update(buf, 0, n)
                    }
                    md.digest().joinToString("") { "%02x".format(it) }
                }

            val sha256 = digest("SHA-256")
            val md5 = digest("MD5")

            File(apkDir, "${apk.name}.sha256").writeText("$sha256  ${apk.name}\n")
            File(apkDir, "${apk.name}.md5").writeText("$md5  ${apk.name}\n")

            println("Signed APK: ${apk.absolutePath}")
            println("SHA-256: $sha256")
            println("MD5:     $md5")
        }
    }
}
