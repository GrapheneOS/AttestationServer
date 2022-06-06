plugins {
    java
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(18))
    }
}

tasks.jar {
    manifest {
        attributes("Main-Class" to "app.attestation.server.AttestationServer")
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.almworks.sqlite4java:sqlite4java:1.0.392")
    runtimeOnly(files("libs/sqlite4java-prebuilt/libsqlite4java-linux-amd64-1.0.392.so"))
    implementation("com.github.ben-manes.caffeine:caffeine:3.1.1")
    implementation("com.google.guava:guava:31.1-jre")
    implementation("com.google.zxing:core:3.5.0")
    implementation("com.google.zxing:javase:3.5.0")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.71")
    implementation("org.eclipse.angus:jakarta.mail:1.0.0")
    implementation("org.eclipse.parsson:jakarta.json:1.1.0")
}

tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

tasks.withType<JavaCompile> {
    options.compilerArgs.addAll(arrayOf("-Xlint:unchecked", "-Xlint:deprecation"))
}

val copyJavaDeps by tasks.registering(Copy::class) {
    from(configurations.runtimeClasspath)
    into("build/libs")
}

tasks.build {
    dependsOn(copyJavaDeps)
}
