package app.attestation.server;

import app.attestation.server.sqlite.SQLiteConnection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static app.attestation.server.TestDatabases.account;
import static app.attestation.server.TestDatabases.attestation;
import static app.attestation.server.TestDatabases.bytes;
import static app.attestation.server.TestDatabases.device;
import static app.attestation.server.TestDatabases.dump;
import static app.attestation.server.TestDatabases.insert;
import static app.attestation.server.TestDatabases.queryLong;
import static app.attestation.server.TestDatabases.queryStrings;
import static app.attestation.server.TestDatabases.row;
import static app.attestation.server.TestDatabases.with;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MaintenanceTest {
    private static final long DAY = 24 * 60 * 60 * 1000;
    private static final long NOW = 1_000 * DAY;
    private static final long DELETED_DEVICE_CUTOFF = NOW - 7 * DAY;
    private static final long INACTIVE_DEVICE_CUTOFF = NOW - 90 * DAY;
    private static final long HISTORY_CUTOFF = NOW - 180 * DAY;
    private static final long INACTIVE_ACCOUNT_CUTOFF = NOW - 365 * DAY;

    @TempDir
    Path dir;

    private SQLiteConnection samples;
    private SQLiteConnection conn;

    @BeforeEach
    void open() throws Exception {
        samples = TestDatabases.samples(dir);
        conn = TestDatabases.attestation(dir);
    }

    @AfterEach
    void close() {
        conn.close();
        samples.close();
    }

    private void insertDevice(final int fingerprint, final long userId, final long verifiedTime,
            final Long deletionTime) throws Exception {
        insert(conn, "Devices", with(device(bytes(fingerprint), userId, verifiedTime), "deletionTime", deletionTime));
    }

    private Map<String, List<Map<String, String>>> dumpAll() throws Exception {
        final Map<String, List<Map<String, String>>> tables = new LinkedHashMap<>();
        tables.put("Accounts", dump(conn, "Accounts", "userId"));
        tables.put("EmailAddresses", dump(conn, "EmailAddresses", "userId, address"));
        tables.put("Sessions", dump(conn, "Sessions", "sessionId"));
        tables.put("Devices", dump(conn, "Devices", "fingerprint"));
        tables.put("Attestations", dump(conn, "Attestations", "id"));
        tables.put("Samples", dump(samples, "Samples", "time"));
        return tables;
    }

    @Test
    void maintain() throws Exception {
        final long active = insert(conn, "Accounts", account("Active", NOW));
        final long inactive = insert(conn, "Accounts", account("Inactive", INACTIVE_ACCOUNT_CUTOFF - 1));
        insert(conn, "Accounts", account("Boundary", INACTIVE_ACCOUNT_CUTOFF));
        final long inactiveWithDevice = insert(conn, "Accounts", account("InactiveWithDevice", NOW - 400 * DAY));
        final long leavingDeleted = insert(conn, "Accounts", account("LeavingDeleted", INACTIVE_ACCOUNT_CUTOFF - 1));
        final long leavingInactive = insert(conn, "Accounts", account("LeavingInactive", INACTIVE_ACCOUNT_CUTOFF - 1));

        insert(conn, "EmailAddresses", row("userId", active, "address", "active@example.com"));
        insert(conn, "EmailAddresses", row("userId", inactive, "address", "inactive@example.com"));
        insert(conn, "Sessions", row("sessionId", null, "userId", active, "token", bytes(1), "expiryTime", NOW - 1));
        insert(conn, "Sessions", row("sessionId", null, "userId", active, "token", bytes(2), "expiryTime", NOW));
        insert(conn, "Sessions", row("sessionId", null, "userId", inactive, "token", bytes(3),
                "expiryTime", NOW + DAY));

        insertDevice(0x01, active, NOW, DELETED_DEVICE_CUTOFF - 1);
        insertDevice(0x02, active, NOW, DELETED_DEVICE_CUTOFF);
        insertDevice(0x03, active, INACTIVE_DEVICE_CUTOFF - 1, null);
        insertDevice(0x04, active, INACTIVE_DEVICE_CUTOFF, null);
        insertDevice(0x05, active, NOW, null);
        insertDevice(0x06, inactiveWithDevice, NOW, null);
        insertDevice(0x07, leavingDeleted, NOW, DELETED_DEVICE_CUTOFF - 1);
        insertDevice(0x08, leavingInactive, INACTIVE_DEVICE_CUTOFF - 1, null);

        insert(conn, "Attestations", attestation(bytes(0x01), NOW));
        insert(conn, "Attestations", attestation(bytes(0x03), NOW));
        insert(conn, "Attestations", attestation(bytes(0x05), HISTORY_CUTOFF - 1));
        final long boundaryAttestation = insert(conn, "Attestations", attestation(bytes(0x05), HISTORY_CUTOFF));
        final long recentAttestation = insert(conn, "Attestations", attestation(bytes(0x05), NOW));

        insert(samples, "Samples", row("sample", bytes(9), "time", NOW - 1_000 * DAY));
        samples.exec("INSERT INTO Samples VALUES (zeroblob(1000000), 1); DELETE FROM Samples WHERE time = 1");
        conn.exec("INSERT INTO Configuration VALUES ('padding', hex(zeroblob(1000000))); DELETE FROM Configuration WHERE key = 'padding'");
        assertTrue(queryLong(samples, "PRAGMA freelist_count") > 0);
        assertTrue(queryLong(conn, "PRAGMA freelist_count") > 0);

        Maintenance.maintain(samples, conn, NOW);

        assertEquals(List.of("Active", "Boundary", "InactiveWithDevice"),
                queryStrings(conn, "SELECT username FROM Accounts ORDER BY userId"));
        assertEquals(List.of("active@example.com"), queryStrings(conn, "SELECT address FROM EmailAddresses"));
        assertEquals(List.of(Long.toString(NOW)), queryStrings(conn, "SELECT expiryTime FROM Sessions"));
        assertEquals(List.of("02", "04", "05", "06"),
                queryStrings(conn, "SELECT substr(hex(fingerprint), 1, 2) FROM Devices ORDER BY fingerprint"));
        assertEquals(List.of(Long.toString(boundaryAttestation), Long.toString(recentAttestation)),
                queryStrings(conn, "SELECT id FROM Attestations ORDER BY id"));
        assertEquals(1, queryLong(samples, "SELECT count(*) FROM Samples"));

        assertEquals(List.of(), queryStrings(conn, "PRAGMA foreign_key_check"));
        assertEquals(0, queryLong(samples, "PRAGMA freelist_count"));
        assertEquals(0, queryLong(conn, "PRAGMA freelist_count"));
        assertEquals(1, queryLong(conn, "SELECT count(*) FROM sqlite_schema WHERE name = 'sqlite_stat1'"));

        final Map<String, List<Map<String, String>>> before = dumpAll();
        Maintenance.maintain(samples, conn, NOW);
        assertEquals(before, dumpAll());
    }

    @Test
    void maintainEmptyDatabases() throws Exception {
        Maintenance.maintain(samples, conn, NOW);
        assertEquals(0, queryLong(conn, "SELECT count(*) FROM Accounts"));
        assertTrue(conn.getAutoCommit());
    }
}
