package app.attestation.server;

import app.attestation.server.sqlite.SQLiteConnection;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import static app.attestation.server.TestDatabases.bytes;
import static app.attestation.server.TestDatabases.insert;
import static app.attestation.server.TestDatabases.queryStrings;
import static app.attestation.server.TestDatabases.row;
import static app.attestation.server.TestDatabases.with;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlertDispatcherTest {
    private static final long HOUR = 60 * 60 * 1000;
    private static final long NOW = 24_000 * HOUR;
    private static final long EXPIRED = NOW - 48 * HOUR - 1;
    private static final String FROM = "alerts@example.com";
    private static final List<String> REMOTE_KEYS =
            List.of("emailUsername", "emailPassword", "emailHost", "emailPort", "emailFrom");

    private static class RecordingDispatcher extends AlertDispatcher {
        final List<Message> sent = new ArrayList<>();
        MessagingException failure;

        @Override
        void send(final Message message) throws MessagingException {
            if (failure != null) {
                throw failure;
            }
            sent.add(message);
        }
    }

    @TempDir
    Path dir;

    private SQLiteConnection conn;
    private final RecordingDispatcher dispatcher = new RecordingDispatcher();

    @BeforeEach
    void open() throws Exception {
        conn = TestDatabases.attestation(dir);
    }

    @AfterEach
    void close() {
        conn.close();
    }

    private void configure(final String key, final Object value) throws Exception {
        insert(conn, "Configuration", row("key", key, "value", value));
    }

    private void configureLocal() throws Exception {
        configure("emailLocal", 1);
        configure("emailFrom", FROM);
    }

    private void configureRemote(final String except) throws Exception {
        configure("emailLocal", 0);
        final List<Object> values = List.of("user", "secret", "smtp.example.com", 465, FROM);
        for (int i = 0; i < REMOTE_KEYS.size(); i++) {
            if (!REMOTE_KEYS.get(i).equals(except)) {
                configure(REMOTE_KEYS.get(i), values.get(i));
            }
        }
    }

    private long account(final String username, final String... addresses) throws Exception {
        final long userId = insert(conn, "Accounts", TestDatabases.account(username, NOW));
        for (final String address : addresses) {
            insert(conn, "EmailAddresses", row("userId", userId, "address", address));
        }
        return userId;
    }

    private void device(final int fingerprint, final long userId, final long verifiedTimeLast,
            final Object... columnsAndValues) throws Exception {
        insert(conn, "Devices", with(TestDatabases.device(bytes(fingerprint), userId, verifiedTimeLast),
                columnsAndValues));
    }

    private List<String> expiredTimeLast() throws Exception {
        return queryStrings(conn, "SELECT quote(expiredTimeLast) FROM Devices ORDER BY fingerprint");
    }

    private static String formatted(final int fingerprint) {
        return "* " + String.join("-", Collections.nCopies(16, "%02X%02X".formatted(fingerprint, fingerprint)))
                + "\n";
    }

    private List<String> recipients() throws Exception {
        final List<String> recipients = new ArrayList<>();
        for (final Message message : dispatcher.sent) {
            assertEquals(1, message.getRecipients(Message.RecipientType.TO).length);
            recipients.add(((InternetAddress) message.getRecipients(Message.RecipientType.TO)[0]).getAddress());
        }
        return recipients;
    }

    @Test
    void sendsExpiryAlerts() throws Exception {
        configureLocal();
        final long alice = account("Alice", "alice@example.com", "alice@example.org");
        final long bob = account("Bob");
        final long carol = account("Carol", "carol@example.com");
        device(0x01, alice, EXPIRED);
        device(0x02, alice, EXPIRED - HOUR);
        device(0x03, alice, NOW - 48 * HOUR);
        device(0x04, alice, EXPIRED, "deletionTime", NOW - HOUR);
        device(0x05, bob, EXPIRED);
        device(0x06, carol, NOW);

        dispatcher.dispatch(conn, NOW);

        assertEquals(List.of("alice@example.com", "alice@example.org"), recipients());
        for (final Message message : dispatcher.sent) {
            final InternetAddress from = (InternetAddress) message.getFrom()[0];
            assertEquals(FROM, from.getAddress());
            assertEquals("Attestation Service", from.getPersonal());
            assertEquals("Devices failed to provide valid attestations within 48 hours", message.getSubject());
            final String text = (String) message.getContent();
            assertTrue(text.startsWith("This is an alert for the account 'Alice'.\n\n"), text);
            assertTrue(text.contains(formatted(0x01)), text);
            assertTrue(text.contains(formatted(0x02)), text);
            assertEquals(2, text.lines().filter(line -> line.startsWith("* ")).count(), text);
            assertTrue(text.contains("https://" + AttestationServer.DOMAIN + "/"), text);

            final Properties properties = message.getSession().getProperties();
            assertEquals(FROM, properties.getProperty("mail.from"));
            assertEquals("30000", properties.getProperty("mail.smtp.connectiontimeout"));
            assertEquals("30000", properties.getProperty("mail.smtp.timeout"));
            assertEquals("30000", properties.getProperty("mail.smtp.writetimeout"));
            assertNull(properties.get("mail.smtps.host"));
        }
        assertEquals(List.of(Long.toString(NOW), Long.toString(NOW), "NULL", "NULL", "NULL", "NULL"),
                expiredTimeLast());
    }

    @Test
    void usesAccountAlertDelay() throws Exception {
        configureLocal();
        final long alice = account("Alice", "alice@example.com");
        final long bob = account("Bob", "bob@example.com");
        conn.exec("UPDATE Accounts SET alertDelay = 86400 WHERE username = 'Bob'");
        device(0x01, alice, NOW - 30 * HOUR);
        device(0x02, bob, NOW - 30 * HOUR);

        dispatcher.dispatch(conn, NOW);

        assertEquals(List.of("bob@example.com"), recipients());
        assertEquals("Devices failed to provide valid attestations within 24 hours",
                dispatcher.sent.getFirst().getSubject());
        assertEquals(List.of("NULL", Long.toString(NOW)), expiredTimeLast());
    }

    @Test
    void throttlesAlerts() throws Exception {
        configureLocal();
        device(0x01, account("Alice", "alice@example.com"), EXPIRED);

        dispatcher.dispatch(conn, NOW);
        dispatcher.dispatch(conn, NOW + 1);
        dispatcher.dispatch(conn, NOW + 24 * HOUR);
        assertEquals(1, dispatcher.sent.size());
        assertEquals(List.of(Long.toString(NOW)), expiredTimeLast());

        dispatcher.dispatch(conn, NOW + 24 * HOUR + 1);
        assertEquals(2, dispatcher.sent.size());
        assertEquals(List.of(Long.toString(NOW + 24 * HOUR + 1)), expiredTimeLast());
    }

    @Test
    void sendFailureLeavesDeviceUnmarked() throws Exception {
        configureLocal();
        device(0x01, account("Alice", "alice@example.com"), EXPIRED);
        dispatcher.failure = new MessagingException("unavailable");

        dispatcher.dispatch(conn, NOW);
        assertEquals(List.of("NULL"), expiredTimeLast());

        dispatcher.failure = null;
        dispatcher.dispatch(conn, NOW + 1);
        assertEquals(List.of("alice@example.com"), recipients());
        assertEquals(List.of(Long.toString(NOW + 1)), expiredTimeLast());
    }

    @Test
    void remoteConfiguration() throws Exception {
        configureRemote(null);
        device(0x01, account("Alice", "alice@example.com"), EXPIRED);

        dispatcher.dispatch(conn, NOW);

        assertEquals(List.of("alice@example.com"), recipients());
        final Session session = dispatcher.sent.getFirst().getSession();
        final Properties properties = session.getProperties();
        assertEquals(FROM, properties.getProperty("mail.from"));
        assertEquals("smtps", properties.getProperty("mail.transport.protocol.rfc822"));
        assertEquals(true, properties.get("mail.smtps.auth"));
        assertEquals("smtp.example.com", properties.getProperty("mail.smtps.host"));
        assertEquals("465", properties.getProperty("mail.smtps.port"));
        assertEquals(true, properties.get("mail.smtps.ssl.checkserveridentity"));
        assertEquals("TLSv1.3", properties.getProperty("mail.smtps.ssl.protocols"));
        assertEquals("30000", properties.getProperty("mail.smtps.connectiontimeout"));
        assertEquals("30000", properties.getProperty("mail.smtps.timeout"));
        assertEquals("30000", properties.getProperty("mail.smtps.writetimeout"));
        final PasswordAuthentication authentication =
                session.requestPasswordAuthentication(null, 465, "smtps", null, null);
        assertEquals("user", authentication.getUserName());
        assertEquals("secret", authentication.getPassword());
    }

    @Test
    void textEmailLocal() throws Exception {
        configure("emailLocal", "1");
        configure("emailFrom", FROM);
        device(0x01, account("Alice", "alice@example.com"), EXPIRED);

        dispatcher.dispatch(conn, NOW);

        assertEquals(List.of("alice@example.com"), recipients());
        assertNull(dispatcher.sent.getFirst().getSession().getProperties().get("mail.smtps.host"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"emailUsername", "emailPassword", "emailHost", "emailPort", "emailFrom"})
    void incompleteRemoteConfiguration(final String missing) throws Exception {
        configureRemote(missing);
        device(0x01, account("Alice", "alice@example.com"), EXPIRED);

        dispatcher.dispatch(conn, NOW);

        assertEquals(List.of(), dispatcher.sent);
        assertEquals(List.of("NULL"), expiredTimeLast());
    }

    @Test
    void incompleteLocalConfiguration() throws Exception {
        configure("emailLocal", 1);
        device(0x01, account("Alice", "alice@example.com"), EXPIRED);

        dispatcher.dispatch(conn, NOW);

        assertEquals(List.of(), dispatcher.sent);
        assertEquals(List.of("NULL"), expiredTimeLast());
    }

    @Test
    void noConfiguration() throws Exception {
        device(0x01, account("Alice", "alice@example.com"), EXPIRED);

        dispatcher.dispatch(conn, NOW);
        dispatcher.dispatch(conn, NOW + 1);

        assertEquals(List.of(), dispatcher.sent);
        assertEquals(List.of("NULL"), expiredTimeLast());
    }
}
