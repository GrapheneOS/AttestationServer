plugins {
    java
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
}

val sqliteYear = "2026"
val sqliteVersion = "3540100"
val sqliteJniMaxGlibc = "2.44"

repositories {
    mavenCentral()
    exclusiveContent {
        forRepository {
            ivy("https://sqlite.org/") {
                name = "sqlite.org"
                patternLayout {
                    artifact("$sqliteYear/[module]-[revision].[ext]")
                }
                metadataSources {
                    artifact()
                }
            }
        }
        filter {
            includeGroup("org.sqlite")
        }
    }
}

val sqliteSources = configurations.create("sqliteSources") {
    isCanBeConsumed = false
    isTransitive = false
}

val sqliteJniDir = layout.buildDirectory.dir("sqlite-jni")

fun sqliteArchive(module: String): Provider<File> {
    val fileName = "$module-$sqliteVersion.zip"
    return sqliteSources.filter { it.name == fileName }.elements.map { it.single().asFile }
}

val sqliteJniPatch = layout.projectDirectory.file("patches/sqlite3-jni.patch")

val extractSqliteJni = tasks.register<Sync>("extractSqliteJni") {
    val patch = sqliteJniPatch.asFile
    inputs.file(patch)
    into(sqliteJniDir.map { it.dir("src") })
    includeEmptyDirs = false
    from(zipTree(sqliteArchive("sqlite-amalgamation"))) {
        include("*/sqlite3.c", "*/sqlite3.h")
        eachFile { path = "c/$name" }
    }
    from(zipTree(sqliteArchive("sqlite-src"))) {
        include("*/ext/jni/src/c/*")
        include("*/ext/jni/src/org/sqlite/jni/capi/**/*.java", "*/ext/jni/src/org/sqlite/jni/annotation/**/*.java")
        exclude("**/capi/Tester1.java", "**/capi/SQLTester.java")
        eachFile { path = path.substringAfter("/ext/jni/src/").replace(Regex("^org/"), "java/org/") }
    }
    doLast {
        val process = ProcessBuilder(
            "patch", "-p1", "-F0", "--batch", "--no-backup-if-mismatch", "-d", destinationDir.path, "-i", patch.path,
        ).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { "applying $patch failed:\n$output" }
    }
}

sourceSets {
    create("sqliteJni") {
        java.srcDir(extractSqliteJni.map { it.destinationDir.resolve("java") })
    }
}

tasks.named<JavaCompile>("compileSqliteJniJava") {
    options.encoding = "UTF-8"
}

val sqliteJniJar = tasks.register<Jar>("sqliteJniJar") {
    archiveFileName.set("sqlite3-jni.jar")
    destinationDirectory.set(sqliteJniDir)
    from(sourceSets["sqliteJni"].output)
}

val compileSqliteJni = tasks.register<Exec>("compileSqliteJni") {
    val osName = providers.systemProperty("os.name").get()
    val arch = providers.systemProperty("os.arch").get()
    check(osName == "Linux") { "building the SQLite JNI library is only supported on Linux, not $osName" }
    val archFlags = when (arch) {
        "amd64", "x86_64" -> listOf("-fcf-protection")
        "aarch64" -> listOf("-mbranch-protection=standard")
        else -> emptyList()
    }
    val flags = """
        -std=c99 -O2 -fPIC -fno-plt -fstack-clash-protection -fstack-protector-strong
        -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fno-strict-aliasing -fwrapv
        -fno-omit-frame-pointer -D_GNU_SOURCE -DNDEBUG -Wall
        -DSQLITE_TRUSTED_SCHEMA=0 -DSQLITE_DEFAULT_DEFENSIVE
        -DSQLITE_TEMP_STORE=1 -DSQLITE_DEFAULT_CACHE_SIZE=-2000 -DSQLITE_DEFAULT_PAGE_SIZE=4096
        -shared -s -Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now,-z,defs
    """.trim().split(Regex("\\s+")) + archFlags
    val sources = extractSqliteJni.map { it.destinationDir.resolve("c") }
    val javaHome = javaToolchains.compilerFor(java.toolchain).map { it.metadata.installationPath.asFile }
    val library = sqliteJniDir.map { it.file("native/libsqlite3-jni.so") }

    inputs.dir(sources).withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.property("javaHome", javaHome.map { it.absolutePath })
    inputs.property("flags", flags)
    outputs.file(library)

    executable = "gcc"
    workingDir(sources)
    argumentProviders.add(CommandLineArgumentProvider {
        val jdkInclude = javaHome.get().resolve("include")
        flags + listOf(
            "-I$jdkInclude",
            "-I${jdkInclude.resolve("linux")}",
            "-o", library.get().asFile.absolutePath,
            "sqlite3-jni.c",
            "-lm",
        )
    })
    doFirst {
        library.get().asFile.parentFile.mkdirs()
    }
}

val checkSqliteJniGlibc = tasks.register("checkSqliteJniGlibc") {
    val library = compileSqliteJni.map { it.outputs.files.singleFile }
    val maxGlibc = sqliteJniMaxGlibc
    inputs.file(library)
    doLast {
        val process = ProcessBuilder("readelf", "--version-info", "-W", library.get().path)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { "readelf failed:\n$output" }
        fun key(version: String) = version.split('.').map(String::toInt).plus(listOf(0, 0)).take(3)
            .reduce { a, b -> a * 1000 + b }
        val required = Regex("""Name: GLIBC_([0-9.]+)\s""").findAll(output).map { it.groupValues[1] }
            .maxByOrNull(::key)
            ?: error("no glibc version requirements found in ${library.get()}")
        check(key(required) <= key(maxGlibc)) {
            "libsqlite3-jni.so requires GLIBC_$required, newer than the pinned sqliteJniMaxGlibc = " +
                "\"$maxGlibc\". Confirm the server's glibc is at least that version before raising the pin."
        }
    }
}

tasks.jar {
    archiveBaseName.set("attestation-server")

    manifest {
        attributes(
            "Main-Class" to "app.attestation.server.AttestationServer",
            "Class-Path" to configurations.runtimeClasspath.get().joinToString(" ") { it.name },
            "Enable-Native-Access" to "ALL-UNNAMED"
        )
    }
}

dependencies {
    sqliteSources("org.sqlite:sqlite-amalgamation:$sqliteVersion@zip")
    sqliteSources("org.sqlite:sqlite-src:$sqliteVersion@zip")
    implementation(files(sqliteJniJar))
    implementation("com.github.ben-manes.caffeine:caffeine:3.3.1")
    implementation("com.google.guava:guava:33.8.0-jre")
    implementation("com.google.zxing:core:3.5.4")
    implementation("com.google.zxing:javase:3.5.4")
    implementation("org.bouncycastle:bcprov-jdk18on:1.87")
    implementation("org.eclipse.angus:jakarta.mail:2.0.5")
    implementation("org.eclipse.parsson:jakarta.json:1.1.9")
    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

listOf(tasks.compileJava, tasks.compileTestJava).forEach {
    it.configure {
        options.compilerArgs.addAll(listOf("-Xlint", "-Xlint:-serial"))
    }
}

abstract class JavaLibraryPath : CommandLineArgumentProvider {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val library: RegularFileProperty

    override fun asArguments() = listOf("-Djava.library.path=${library.get().asFile.parent}")
}

tasks.test {
    dependsOn(checkSqliteJniGlibc)
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    jvmArgumentProviders.add(objects.newInstance<JavaLibraryPath>().apply {
        library.fileProvider(compileSqliteJni.map { it.outputs.files.singleFile })
    })
}

val copyJavaDeps = tasks.register<Copy>("copyJavaDeps") {
    dependsOn(checkSqliteJniGlibc)
    from(configurations.runtimeClasspath)
    from(compileSqliteJni)
    into("build/libs")
}

tasks.build {
    dependsOn(copyJavaDeps)
}
