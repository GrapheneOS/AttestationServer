package app.attestation.server;

import app.attestation.server.AttestationServer.Account;
import app.attestation.server.AttestationServer.Session;
import app.attestation.server.AttestationServer.UsernameUnavailableException;
import app.attestation.server.sqlite.SQLiteConnection;
import app.attestation.server.sqlite.SQLiteStatement;
import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static app.attestation.server.TestDatabases.bytes;
import static app.attestation.server.TestDatabases.insert;
import static app.attestation.server.TestDatabases.queryLong;
import static app.attestation.server.TestDatabases.queryString;
import static app.attestation.server.TestDatabases.queryStrings;
import static app.attestation.server.TestDatabases.row;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccountTest {
    private static final String PASSWORD = "correct horse";
    private static final String NEW_PASSWORD = "battery staple";
    private static final long SESSION_LENGTH = 48 * 60 * 60 * 1000;

    @TempDir
    Path dir;

    private SQLiteConnection conn;

    @BeforeEach
    void open() throws Exception {
        conn = TestDatabases.attestation(dir);
    }

    @AfterEach
    void close() {
        conn.close();
    }

    private long count(final String table) throws Exception {
        return queryLong(conn, "SELECT count(*) FROM " + table);
    }

    private long loginTime() throws Exception {
        return queryLong(conn, "SELECT loginTime FROM Accounts");
    }

    @Test
    void createAccount() throws Exception {
        final long before = System.currentTimeMillis();
        AttestationServer.createAccount(conn, "Alice", PASSWORD);
        final long after = System.currentTimeMillis();

        try (final SQLiteStatement st = conn.prepare("""
                SELECT userId, username, passwordHash, passwordSalt, subscribeKey, creationTime, loginTime,
                    verifyInterval, alertDelay
                FROM Accounts""")) {
            assertTrue(st.step());
            assertEquals(1, st.columnLong(0));
            assertEquals("Alice", st.columnString(1));
            assertEquals(32, st.columnBlob(2).length);
            assertEquals(32, st.columnBlob(3).length);
            assertEquals(32, st.columnBlob(4).length);
            final long creationTime = st.columnLong(5);
            assertTrue(creationTime >= before && creationTime <= after);
            assertEquals(creationTime, st.columnLong(6));
            assertEquals(6 * 60 * 60, st.columnInt(7));
            assertEquals(48 * 60 * 60, st.columnInt(8));
            assertFalse(st.step());
        }
        assertTrue(conn.getAutoCommit());
    }

    @Test
    void createAccountRejectsTakenUsername() throws Exception {
        AttestationServer.createAccount(conn, "Alice", PASSWORD);
        assertThrows(UsernameUnavailableException.class,
                () -> AttestationServer.createAccount(conn, "Alice", NEW_PASSWORD));
        assertThrows(UsernameUnavailableException.class,
                () -> AttestationServer.createAccount(conn, "aLICE", NEW_PASSWORD));
        assertEquals(1, count("Accounts"));
        assertTrue(conn.getAutoCommit());
    }

    static Stream<Arguments> invalidAccounts() {
        final String loneSurrogate = Character.toString(0xd800);
        return Stream.of(
                Arguments.of("", PASSWORD),
                Arguments.of("a".repeat(33), PASSWORD),
                Arguments.of("Alice Smith", PASSWORD),
                Arguments.of("alice_smith", PASSWORD),
                Arguments.of("Ålice", PASSWORD),
                Arguments.of("Alice", "a".repeat(7)),
                Arguments.of("Alice", "a".repeat(257)),
                Arguments.of("Alice", PASSWORD + loneSurrogate));
    }

    @ParameterizedTest
    @MethodSource("invalidAccounts")
    void createAccountRejectsInvalidInput(final String username, final String password) throws Exception {
        assertThrowsExactly(GeneralSecurityException.class,
                () -> AttestationServer.createAccount(conn, username, password));
        assertEquals(0, count("Accounts"));
    }

    @Test
    void createAccountAcceptsLimits() throws Exception {
        AttestationServer.createAccount(conn, "a".repeat(32), "a".repeat(8));
        AttestationServer.createAccount(conn, "Z9", "a".repeat(256));
        AttestationServer.createAccount(conn, "Bob", "password " + Character.toString(0x1f600));
        assertEquals(List.of("a".repeat(32), "Z9", "Bob"), queryStrings(conn, "SELECT username FROM Accounts ORDER BY userId"));
    }

    @Test
    void login() throws Exception {
        AttestationServer.createAccount(conn, "Alice", PASSWORD);
        insert(conn, "Sessions", row("sessionId", null, "userId", 1, "token", bytes(7), "expiryTime", 1L));
        insert(conn, "Sessions", row("sessionId", null, "userId", 1, "token", bytes(8),
                "expiryTime", Long.MAX_VALUE));

        final long before = System.currentTimeMillis();
        final Session session = AttestationServer.login(conn, "ALICE", PASSWORD);
        final long after = System.currentTimeMillis();

        assertEquals(32, session.token().length);
        try (final SQLiteStatement st = conn.prepare("SELECT userId, token, expiryTime FROM Sessions WHERE sessionId = ?")) {
            st.bind(1, session.sessionId());
            assertTrue(st.step());
            assertEquals(1, st.columnLong(0));
            assertArrayEquals(session.token(), st.columnBlob(1));
            final long expiryTime = st.columnLong(2);
            assertTrue(expiryTime >= before + SESSION_LENGTH && expiryTime <= after + SESSION_LENGTH);
        }
        assertEquals(List.of("2", Long.toString(session.sessionId())),
                queryStrings(conn, "SELECT sessionId FROM Sessions ORDER BY sessionId"));
        final long loginTime = loginTime();
        assertTrue(loginTime >= before && loginTime <= after);
        assertTrue(conn.getAutoCommit());

        final Session second = AttestationServer.login(conn, "Alice", PASSWORD);
        assertTrue(second.sessionId() > session.sessionId());
        assertFalse(Arrays.equals(session.token(), second.token()));
        assertEquals(3, count("Sessions"));
    }

    @Test
    void loginRejectsWrongPassword() throws Exception {
        AttestationServer.createAccount(conn, "Alice", PASSWORD);
        insert(conn, "Sessions", row("sessionId", null, "userId", 1, "token", bytes(7), "expiryTime", 1L));
        final long loginTime = loginTime();

        assertThrowsExactly(GeneralSecurityException.class, () -> AttestationServer.login(conn, "Alice", NEW_PASSWORD));

        assertTrue(conn.getAutoCommit());
        assertEquals(1, count("Sessions"));
        assertEquals(loginTime, loginTime());
    }

    @Test
    void loginRejectsUnknownUser() throws Exception {
        AttestationServer.createAccount(conn, "Alice", PASSWORD);
        assertThrows(UsernameUnavailableException.class, () -> AttestationServer.login(conn, "Bob", PASSWORD));
        assertTrue(conn.getAutoCommit());
        assertEquals(0, count("Sessions"));
    }

    @Test
    void loginRejectsInvalidPassword() throws Exception {
        AttestationServer.createAccount(conn, "Alice", PASSWORD);
        assertThrowsExactly(GeneralSecurityException.class, () -> AttestationServer.login(conn, "Alice", "short"));
        assertTrue(conn.getAutoCommit());
        assertEquals(0, count("Sessions"));
    }

    @Test
    void changePassword() throws Exception {
        AttestationServer.createAccount(conn, "Alice", PASSWORD);
        final List<String> before = queryStrings(conn, "SELECT hex(passwordHash) || hex(passwordSalt) FROM Accounts");

        AttestationServer.changePassword(conn, 1, PASSWORD, NEW_PASSWORD);

        assertTrue(conn.getAutoCommit());
        assertFalse(before.equals(queryStrings(conn, "SELECT hex(passwordHash) || hex(passwordSalt) FROM Accounts")));
        assertThrowsExactly(GeneralSecurityException.class, () -> AttestationServer.login(conn, "Alice", PASSWORD));
        assertNotNull(AttestationServer.login(conn, "Alice", NEW_PASSWORD));
    }

    @Test
    void changePasswordRejectsWrongCurrentPassword() throws Exception {
        AttestationServer.createAccount(conn, "Alice", PASSWORD);
        final List<String> before = queryStrings(conn, "SELECT hex(passwordHash) || hex(passwordSalt) FROM Accounts");

        assertThrowsExactly(GeneralSecurityException.class,
                () -> AttestationServer.changePassword(conn, 1, NEW_PASSWORD, "another password"));
        assertThrowsExactly(GeneralSecurityException.class,
                () -> AttestationServer.changePassword(conn, 1, PASSWORD, "short"));

        assertTrue(conn.getAutoCommit());
        assertEquals(before, queryStrings(conn, "SELECT hex(passwordHash) || hex(passwordSalt) FROM Accounts"));
        assertNotNull(AttestationServer.login(conn, "Alice", PASSWORD));
    }

    @Test
    void verifySession() throws Exception {
        AttestationServer.createAccount(conn, "Alice", PASSWORD);
        conn.exec("UPDATE Accounts SET verifyInterval = 7200, alertDelay = 86400");
        final Session session = AttestationServer.login(conn, "Alice", PASSWORD);

        final Account account = AttestationServer.verifySession(conn, session.sessionId(), session.token(), false);

        assertEquals(1, account.userId());
        assertEquals("Alice", account.username());
        assertEquals(queryString(conn, "SELECT hex(subscribeKey) FROM Accounts"),
                BaseEncoding.base16().encode(account.subscribeKey()));
        assertEquals(7200, account.verifyInterval());
        assertEquals(86400, account.alertDelay());
        assertEquals(1, count("Sessions"));
    }

    @Test
    void verifySessionRejectsInvalidSessions() throws Exception {
        AttestationServer.createAccount(conn, "Alice", PASSWORD);
        final Session session = AttestationServer.login(conn, "Alice", PASSWORD);
        final byte[] wrongToken = session.token().clone();
        wrongToken[31] ^= 1;

        for (final boolean end : new boolean[] {false, true}) {
            assertNull(AttestationServer.verifySession(conn, session.sessionId(), wrongToken, end));
            assertNull(AttestationServer.verifySession(conn, session.sessionId(), new byte[0], end));
            assertNull(AttestationServer.verifySession(conn, session.sessionId() + 1, session.token(), end));
        }
        assertEquals(1, count("Sessions"));

        try (final SQLiteStatement st = conn.prepare("UPDATE Sessions SET expiryTime = ?")) {
            st.bind(1, System.currentTimeMillis() - 1);
            st.step();
        }
        assertNull(AttestationServer.verifySession(conn, session.sessionId(), session.token(), false));
        assertNull(AttestationServer.verifySession(conn, session.sessionId(), session.token(), true));
        assertEquals(1, count("Sessions"));
    }

    @Test
    void verifySessionEndsSession() throws Exception {
        AttestationServer.createAccount(conn, "Alice", PASSWORD);
        final Session session = AttestationServer.login(conn, "Alice", PASSWORD);
        final Session other = AttestationServer.login(conn, "Alice", PASSWORD);

        final Account account = AttestationServer.verifySession(conn, session.sessionId(), session.token(), true);

        assertEquals(1, account.userId());
        assertEquals("Alice", account.username());
        assertEquals(List.of(Long.toString(other.sessionId())), queryStrings(conn, "SELECT sessionId FROM Sessions"));
        assertNull(AttestationServer.verifySession(conn, session.sessionId(), session.token(), false));
        assertNotNull(AttestationServer.verifySession(conn, other.sessionId(), other.token(), false));
    }
}
