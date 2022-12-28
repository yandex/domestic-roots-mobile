@file:Suppress("MagicNumber")

import com.android.build.api.dsl.AndroidSourceSet

plugins {
    id("com.android.library")
    kotlin("android")
}

apply(from = "../../common.gradle")

android {
    defaultConfig {
        minSdk = 19

        testInstrumentationRunner = "android.support.test.runner.AndroidJUnitRunner"

        consumerProguardFiles("consumer-proguard-rules.pro")
    }

    sourceSets {
        getByName<AndroidSourceSet>("main").java.srcDirs("src/main/kotlin")
        getByName<AndroidSourceSet>("test").java.srcDirs("src/test/kotlin")
        getByName<AndroidSourceSet>("androidTest").java.srcDirs("src/androidTest/kotlin")
    }
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.2")

    api(project(":certificatetransparency"))

    testImplementation("junit:junit:4.12")
    testImplementation("org.mockito:mockito-core:4.3.1")
    testImplementation("org.mockito.kotlin:mockito-kotlin:4.0.0")

    testImplementation("androidx.test:core:1.4.0")
    testImplementation("androidx.test:runner:1.4.0")
    testImplementation("androidx.test.ext:junit:1.1.3")
    testImplementation("org.robolectric:robolectric:4.9")
}
