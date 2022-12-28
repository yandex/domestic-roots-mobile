import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("java-library")
    id("kotlin")
    kotlin("plugin.serialization") version "1.6.10"
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))

    implementation("org.bouncycastle:bcpkix-jdk15to18:1.70")
    implementation("org.bouncycastle:bcprov-jdk15to18:1.70")
    implementation("org.bouncycastle:bctls-jdk15to18:1.70")
    // Adding bcutil directly as it's used through bcprov-jdk15to18 but not directly added
    implementation("org.bouncycastle:bcutil-jdk15to18:1.70")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.2")

    implementation("com.squareup.okhttp3:okhttp:3.12.13")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.3.2")
    testImplementation("com.squareup.retrofit2:retrofit:2.9.0")
    testImplementation("com.squareup.retrofit2:retrofit-mock:2.9.0")
    testImplementation("com.squareup.okhttp3:mockwebserver:3.12.13")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito:mockito-core:4.3.1")
    testImplementation("org.mockito.kotlin:mockito-kotlin:4.0.0")

    testImplementation("nl.jqno.equalsverifier:equalsverifier:3.8.3")
}

tasks.withType(KotlinCompile::class.java).all {
    kotlinOptions {
        freeCompilerArgs += "-opt-in=kotlin.RequiresOptIn"
    }
}
