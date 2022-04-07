plugins {
    java
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
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
    implementation("com.github.ben-manes.caffeine:caffeine:3.0.6")
    implementation("com.google.guava:guava:31.1-jre")
    implementation("com.google.zxing:core:3.4.1")
    implementation("com.google.zxing:javase:3.4.1")
    implementation("com.sun.mail:jakarta.mail:2.0.1")
    implementation("jakarta.json:jakarta.json-api:2.1.0")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.70")
    implementation("org.glassfish:jakarta.json:2.0.1")
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
