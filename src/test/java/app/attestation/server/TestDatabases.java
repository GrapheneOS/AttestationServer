package app.attestation.server;

import app.attestation.server.sqlite.SQLiteConnection;
import app.attestation.server.sqlite.SQLiteException;
import app.attestation.server.sqlite.SQLiteStatement;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.joining;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class TestDatabases {
    private TestDatabases() {}

    static SQLiteConnection attestation(final Path dir) throws SQLiteException {
        final Path file = dir.resolve("attestation.db");
        AttestationServer.setupAttestationDatabase(file.toFile());
        return AttestationServer.open(file.toFile());
    }

    static SQLiteConnection samples(final Path dir) throws SQLiteException {
        final Path file = dir.resolve("samples.db");
        AttestationServer.setupSamplesDatabase(file.toFile());
        return AttestationServer.open(file.toFile());
    }

    static Certificate[] chain() throws CertificateException {
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        final List<Certificate> chain = new ArrayList<>();
        for (final String name : List.of("google_root_1.der", "google_root_4.der", "google_root_0.der")) {
            try (final InputStream stream = AttestationProtocol.class.getResourceAsStream(name)) {
                chain.add(factory.generateCertificate(stream));
            } catch (final IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return chain.toArray(new Certificate[0]);
    }

    static byte[] bytes(final int fill) {
        final byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) fill);
        return bytes;
    }

    static Map<String, Object> account(final String username, final long loginTime) {
        return row("userId", null, "username", username, "passwordHash", bytes(1), "passwordSalt", bytes(2),
                "subscribeKey", bytes(3), "creationTime", loginTime, "loginTime", loginTime,
                "verifyInterval", 6 * 60 * 60, "alertDelay", 48 * 60 * 60);
    }

    static Map<String, Object> device(final byte[] fingerprint, final long userId, final long verifiedTime)
            throws CertificateException, IOException {
        return row("fingerprint", fingerprint,
                "pinnedCertificates", AttestationProtocol.encodeChain(AttestationProtocol.DEFLATE_DICTIONARY_4, chain()),
                "attestKey", 1, "pinnedVerifiedBootKey", bytes(0x5a), "verifiedBootHash", bytes(0x6b),
                "pinnedOsVersion", 160_000, "pinnedOsPatchLevel", 202_510, "pinnedVendorPatchLevel", 20_251_005,
                "pinnedBootPatchLevel", 20_251_005, "pinnedAppVersion", 90, "pinnedAppVariant", 0,
                "pinnedSecurityLevel", 1, "userProfileSecure", 1, "enrolledBiometrics", 0, "accessibility", 0,
                "deviceAdmin", 0, "adbEnabled", 0, "addUsersWhenLocked", 0, "oemUnlockAllowed", 0,
                "systemUser", 1, "autoRebootSeconds", 3_600, "portSecurityMode", 1, "userCount", 2,
                "oemUnlockAllowed2", 0, "verifiedTimeFirst", verifiedTime, "verifiedTimeLast", verifiedTime,
                "expiredTimeLast", null, "failureTimeLast", null, "failureAlertTime", null, "userId", userId,
                "deletionTime", null);
    }

    static Map<String, Object> attestation(final byte[] fingerprint, final long time) {
        return row("id", null, "fingerprint", fingerprint, "time", time, "strong", 1, "osVersion", 160_000,
                "osPatchLevel", 202_510, "vendorPatchLevel", 20_251_005, "bootPatchLevel", 20_251_005,
                "verifiedBootHash", bytes(0x6b), "appVersion", 90, "userProfileSecure", 1, "enrolledBiometrics", 0,
                "accessibility", 0, "deviceAdmin", 0, "adbEnabled", 0, "addUsersWhenLocked", 0,
                "oemUnlockAllowed", 0, "systemUser", 1, "autoRebootSeconds", 3_600, "portSecurityMode", 1,
                "userCount", 2, "oemUnlockAllowed2", 0);
    }

    static Map<String, Object> row(final Object... columnsAndValues) {
        final Map<String, Object> row = new LinkedHashMap<>();
        for (int i = 0; i < columnsAndValues.length; i += 2) {
            row.put((String) columnsAndValues[i], columnsAndValues[i + 1]);
        }
        return row;
    }

    static Map<String, Object> with(final Map<String, Object> row, final Object... columnsAndValues) {
        final Map<String, Object> copy = new LinkedHashMap<>(row);
        copy.putAll(row(columnsAndValues));
        return copy;
    }

    static List<String> columns(final SQLiteConnection conn, final String table) throws SQLiteException {
        final List<String> columns = new ArrayList<>();
        try (final SQLiteStatement st = conn.prepare("SELECT name FROM pragma_table_info(?) ORDER BY cid")) {
            st.bind(1, table);
            while (st.step()) {
                columns.add(st.columnString(0));
            }
        }
        return columns;
    }

    // Values for columns missing from the table are ignored, so one row can serve several schema versions.
    static long insert(final SQLiteConnection conn, final String table, final Map<String, Object> values)
            throws SQLiteException {
        final List<String> columns = columns(conn, table);
        assertTrue(values.keySet().containsAll(columns), () -> table + " needs values for " + columns);
        final String sql = "INSERT INTO " + table + " (" + String.join(", ", columns) + ") VALUES ("
                + columns.stream().map(column -> "?").collect(joining(", ")) + ")";
        try (final SQLiteStatement st = conn.prepare(sql)) {
            for (int i = 0; i < columns.size(); i++) {
                switch (values.get(columns.get(i))) {
                    case null -> st.bind(i + 1, (String) null);
                    case Integer value -> st.bind(i + 1, value);
                    case Long value -> st.bind(i + 1, value);
                    case Boolean value -> st.bind(i + 1, value ? 1 : 0);
                    case String value -> st.bind(i + 1, value);
                    case byte[] value -> st.bind(i + 1, value);
                    default -> throw new IllegalArgumentException(columns.get(i));
                }
            }
            st.step();
        }
        return conn.getLastInsertId();
    }

    // Rows as SQL literals from quote(), so values compare by both type and value.
    static List<Map<String, String>> dump(final SQLiteConnection conn, final String table, final String orderBy)
            throws SQLiteException {
        final List<String> columns = columns(conn, table);
        final String sql = "SELECT " + columns.stream().map(column -> "quote(\"" + column + "\")")
                .collect(joining(", ")) + " FROM " + table + " ORDER BY " + orderBy;
        final List<Map<String, String>> rows = new ArrayList<>();
        try (final SQLiteStatement st = conn.prepare(sql)) {
            while (st.step()) {
                final Map<String, String> row = new LinkedHashMap<>();
                for (int i = 0; i < columns.size(); i++) {
                    row.put(columns.get(i), st.columnString(i));
                }
                rows.add(row);
            }
        }
        return rows;
    }

    static long queryLong(final SQLiteConnection conn, final String sql) throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare(sql)) {
            assertTrue(st.step(), sql);
            return st.columnLong(0);
        }
    }

    static String queryString(final SQLiteConnection conn, final String sql) throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare(sql)) {
            assertTrue(st.step(), sql);
            return st.columnString(0);
        }
    }

    static List<String> queryStrings(final SQLiteConnection conn, final String sql) throws SQLiteException {
        final List<String> values = new ArrayList<>();
        try (final SQLiteStatement st = conn.prepare(sql)) {
            while (st.step()) {
                values.add(st.columnString(0));
            }
        }
        return values;
    }

    static List<String> schema(final SQLiteConnection conn) throws SQLiteException {
        return queryStrings(conn, "SELECT type || ' ' || name || ': ' || coalesce(sql, '') FROM sqlite_schema"
                + " WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").stream()
                .map(entry -> entry.replaceAll("\\s+", " "))
                .toList();
    }
}
