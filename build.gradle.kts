plugins {
    java
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
}

val sqliteYear = "2026"
val sqliteVersion = "3540000"
val sqliteJniMaxGlibc = "2.34"

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

val extractSqliteJni = tasks.register<Sync>("extractSqliteJni") {
    into(sqliteJniDir.map { it.dir("src") })
    includeEmptyDirs = false
    from(zipTree(sqliteArchive("sqlite-amalgamation"))) {
        include("*/sqlite3.c", "*/sqlite3.h")
        eachFile { path = "c/$name" }
    }
    from(zipTree(sqliteArchive("sqlite-src"))) {
        include("*/ext/jni/src/c/*")
        eachFile { path = "c/$name" }
    }
    from(zipTree(sqliteArchive("sqlite-src"))) {
        include("*/ext/jni/src/org/sqlite/jni/capi/**/*.java", "*/ext/jni/src/org/sqlite/jni/annotation/**/*.java")
        exclude("**/capi/Tester1.java", "**/capi/SQLTester.java")
        eachFile { path = "java/" + path.substringAfter("/ext/jni/src/") }
    }
    doLast {
        // Upstream bugs: sqlite3_jni_internal_details() uses the metrics struct even when
        // SQLITE_JNI_ENABLE_METRICS is undefined, and closing finds the connection through client
        // data, which API armor hides when opening failed, so the failed connection was never freed.
        // Math functions would require libm and can only be disabled by removing the forced default.
        val replacements = mapOf(
            "\n  SO(S3JniGlobal.metrics);\n" to "\n",
            "\n#  define SQLITE_ENABLE_MATH_FUNCTIONS 1\n" to "\n",
            """
            |  int rc = 0;
            |  S3JniDb * const ps = S3JniDb_from_jlong(jpDb);
            |
            |  assert(version == 1 || version == 2);
            |  if( ps ){
            |    rc = 1==version
            |      ? (jint)sqlite3_close(ps->pDb)
            |      : (jint)sqlite3_close_v2(ps->pDb);
            |  }
            |  return (jint)rc;
            |""".trimMargin() to """
            |  sqlite3 * const pDb = LongPtrGet_sqlite3(jpDb);
            |
            |  assert(version == 1 || version == 2);
            |  return 1==version
            |    ? (jint)sqlite3_close(pDb)
            |    : (jint)sqlite3_close_v2(pDb);
            |""".trimMargin(),
        )
        val file = destinationDir.resolve("c/sqlite3-jni.c")
        var text = file.readText()
        for ((old, new) in replacements) {
            val count = text.split(old).size - 1
            check(count == 1) { "expected exactly one occurrence of '${old.trim()}' in $file, found $count" }
            text = text.replace(old, new)
        }
        file.writeText(text)
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
    val flags = listOf(
        "-std=c99", "-O2", "-fPIC", "-fno-plt", "-fstack-clash-protection", "-fstack-protector-strong",
        "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3", "-fno-strict-aliasing", "-fwrapv",
        "-fno-omit-frame-pointer", "-D_GNU_SOURCE", "-DNDEBUG", "-Wall",
    ) + archFlags + listOf(
        "-DSQLITE_THREADSAFE=1", "-DSQLITE_DQS=0", "-DSQLITE_OMIT_DEPRECATED", "-DSQLITE_TRUSTED_SCHEMA=0",
        "-DSQLITE_DEFAULT_DEFENSIVE", "-DSQLITE_ENABLE_RTREE=1", "-DSQLITE_ENABLE_COLUMN_METADATA",
        "-DSQLITE_ENABLE_MEMORY_MANAGEMENT", "-DSQLITE_TEMP_STORE=1", "-DSQLITE_DEFAULT_CACHE_SIZE=-2000",
        "-DSQLITE_DEFAULT_PAGE_SIZE=4096",
        "-shared", "-s", "-Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now,-z,defs",
    )
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
        val process = ProcessBuilder("readelf", "--version-info", "-W", library.get().absolutePath)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { "readelf failed:\n$output" }
        fun parse(version: String) = version.split('.').map(String::toInt)
        val versionComparator = Comparator<List<Int>> { a, b ->
            a.zip(b).map { (x, y) -> x.compareTo(y) }.firstOrNull { it != 0 } ?: a.size.compareTo(b.size)
        }
        val needed = Regex("""Name: (GLIBC_\S+)""")
            .findAll(output.substringAfter("Version needs section", ""))
            .map { it.groupValues[1] }
            .toSet()
        val (numbered, markers) = needed.partition { Regex("""GLIBC_[0-9]+(\.[0-9]+)+""").matches(it) }
        check(markers.isEmpty()) {
            "libsqlite3-jni.so requires ${markers.joinToString()}, which can't be checked against the pinned " +
                "sqliteJniMaxGlibc = \"$maxGlibc\". Adjust the compileSqliteJni link flags so it isn't required."
        }
        val required = numbered.map { parse(it.removePrefix("GLIBC_")) }
            .maxWithOrNull(versionComparator)
            ?: error("no glibc version requirements found in ${library.get()}")
        check(versionComparator.compare(required, parse(maxGlibc)) <= 0) {
            "libsqlite3-jni.so requires GLIBC_${required.joinToString(".")}, newer than the pinned " +
                "sqliteJniMaxGlibc = \"$maxGlibc\". Confirm the server's glibc is at least that " +
                "version before raising the pin in build.gradle.kts."
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
    implementation("com.google.guava:guava:33.7.2-jre")
    implementation("com.google.zxing:core:3.5.4")
    implementation("com.google.zxing:javase:3.5.4")
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
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
