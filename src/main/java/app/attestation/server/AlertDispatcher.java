package app.attestation.server;

import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;
import com.google.common.io.BaseEncoding;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.util.ArrayList;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import static app.attestation.server.SyslogLevel.CRIT;

class AlertDispatcher implements Runnable {
    private static final long WAIT_MS = 60 * 1000;
    private static final int TIMEOUT_MS = 30 * 1000;
    private static final long ALERT_THROTTLE_MS = 24 * 60 * 60 * 1000;

    // Split displayed fingerprint into groups of 4 characters
    private static final int FINGERPRINT_SPLIT_INTERVAL = 4;

    private static final Logger logger = Logger.getLogger(AlertDispatcher.class.getName());

    private record Account(long userId, String username, int alertDelay) {}

    @Override
    public void run() {
        final SQLiteConnection conn;
        try {
            conn = AttestationServer.open(AttestationServer.ATTESTATION_DATABASE);
        } catch (final SQLiteException e) {
            logger.log(CRIT, "database error, cannot set up AlertDispatcher thread", e);
            return;
        }
        final SQLiteStatement selectConfiguration;
        final SQLiteStatement selectAccountsForExpiryAlert;
        final SQLiteStatement selectExpired;
        final SQLiteStatement updateExpired;
        final SQLiteStatement selectFailed;
        final SQLiteStatement selectEmails;
        try {
            selectConfiguration = conn.prepare("""
                    SELECT
                    (SELECT value FROM Configuration WHERE key = 'emailLocal'),
                    (SELECT value FROM Configuration WHERE key = 'emailUsername'),
                    (SELECT value FROM Configuration WHERE key = 'emailPassword'),
                    (SELECT value FROM Configuration WHERE key = 'emailHost'),
                    (SELECT value FROM Configuration WHERE key = 'emailPort')""");
            selectAccountsForExpiryAlert = conn.prepare("""
                    SELECT userId, username, alertDelay FROM Accounts
                    WHERE (SELECT 1 FROM Devices WHERE userId = Accounts.userID
                        AND verifiedTimeLast < ? - alertDelay * 1000 AND deletionTime is NULL
                        AND (expiredTimeLast IS NULL OR expiredTimeLast < ?))""");
            selectExpired = conn.prepare("""
                    SELECT fingerprint FROM Devices
                    WHERE userId = ? AND verifiedTimeLast < ? AND deletionTime IS NULL""");
            updateExpired = conn.prepare(
                    "UPDATE Devices SET expiredTimeLast = ? WHERE fingerprint = ?");
            selectFailed = conn.prepare("""
                    SELECT fingerprint FROM Devices
                    WHERE userId = ? AND failureTimeLast IS NOT NULL AND deletionTime IS NULL""");
            selectEmails = conn.prepare("SELECT address FROM EmailAddresses WHERE userId = ?");
        } catch (final SQLiteException e) {
            conn.dispose();
            logger.log(CRIT, "database error, cannot set up AlertDispatcher thread", e);
            return;
        }

        while (true) {
            try {
                Thread.sleep(WAIT_MS);
            } catch (final InterruptedException e) {
                return;
            }

            logger.info("dispatching alerts");

            try {
                selectConfiguration.step();
                final int local = selectConfiguration.columnInt(0);
                final String emailUsername = selectConfiguration.columnString(1);
                final String emailPassword = selectConfiguration.columnString(2);
                final String emailHost = selectConfiguration.columnString(3);
                final String emailPort = selectConfiguration.columnString(4);
                selectConfiguration.reset();

                final Session session;
                if (local == 1) {
                    if (emailUsername == null) {
                        logger.warning("missing configuration for sending alert emails");
                        continue;
                    }
                    final Properties props = new Properties();
                    props.put("mail.smtp.connectiontimeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtp.timeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtp.writetimeout", Integer.toString(TIMEOUT_MS));
                    session = Session.getInstance(props);
                } else {
                    if (emailUsername == null || emailPassword == null || emailHost == null || emailPort == null) {
                        logger.warning("missing configuration for sending alert emails");
                        continue;
                    }

                    final Properties props = new Properties();
                    props.put("mail.transport.protocol.rfc822", "smtps");
                    props.put("mail.smtps.auth", true);
                    props.put("mail.smtps.host", emailHost);
                    props.put("mail.smtps.port", emailPort);
                    props.put("mail.smtps.ssl.checkserveridentity", true);
                    props.put("mail.smtps.ssl.protocols", "TLSv1.3");
                    props.put("mail.smtps.connectiontimeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtps.timeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtps.writetimeout", Integer.toString(TIMEOUT_MS));

                    session = Session.getInstance(props,
                            new jakarta.mail.Authenticator() {
                                protected PasswordAuthentication getPasswordAuthentication() {
                                    return new PasswordAuthentication(emailUsername, emailPassword);
                                }
                            });
                }

                final ArrayList<Account> accountsForExpiryAlert = new ArrayList<>();
                final long now = System.currentTimeMillis();
                selectAccountsForExpiryAlert.bind(1, now);
                selectAccountsForExpiryAlert.bind(2, now - ALERT_THROTTLE_MS);
                while (selectAccountsForExpiryAlert.step()) {
                    accountsForExpiryAlert.add(new Account(
                            selectAccountsForExpiryAlert.columnLong(0),
                            selectAccountsForExpiryAlert.columnString(1),
                            selectAccountsForExpiryAlert.columnInt(2)));
                }
                selectAccountsForExpiryAlert.reset();

                for (final Account account : accountsForExpiryAlert) {
                    final ArrayList<byte[]> expiredFingerprints = new ArrayList<>();
                    final StringBuilder expired = new StringBuilder();
                    selectExpired.bind(1, account.userId);
                    selectExpired.bind(2, now - account.alertDelay * 1000);
                    while (selectExpired.step()) {
                        final byte[] fingerprint = selectExpired.columnBlob(0);
                        expiredFingerprints.add(fingerprint);

                        expired.append("* ");

                        final String encoded = BaseEncoding.base16().encode(fingerprint);

                        for (int i = 0; i < encoded.length(); i += FINGERPRINT_SPLIT_INTERVAL) {
                            expired.append(encoded, i, Math.min(encoded.length(), i + FINGERPRINT_SPLIT_INTERVAL));
                            if (i + FINGERPRINT_SPLIT_INTERVAL < encoded.length()) {
                                expired.append("-");
                            }
                        }

                        expired.append("\n");
                    }
                    selectExpired.reset();

                    if (expiredFingerprints.isEmpty()) {
                        continue;
                    }

                    selectEmails.bind(1, account.userId);
                    final ArrayList<String> addresses = new ArrayList<>();
                    while (selectEmails.step()) {
                        addresses.add(selectEmails.columnString(0));
                    }
                    selectEmails.reset();

                    for (final String address : addresses) {
                        logger.info("sending email to " + address + " for account " + account.userId);
                        try {
                            final Message message = new MimeMessage(session);
                            message.setFrom(new InternetAddress(emailUsername));
                            message.setRecipients(Message.RecipientType.TO,
                                    InternetAddress.parse(address));
                            message.setSubject(
                                    "Devices failed to provide valid attestations within " +
                                    account.alertDelay / 60 / 60 + " hours");
                            message.setText("This is an alert for the account '" + account.username + "'.\n\n" +
                                    "The following devices have failed to provide valid attestations before the expiry time:\n\n" +
                                    expired + "\nLog in to https://" + AttestationServer.DOMAIN + "/ for more information.\n\n" +
                                    "If you do not want to receive these alerts and cannot log in to the account,\nemail contact@" + AttestationServer.DOMAIN + " from the address receiving the alerts.");

                            Transport.send(message);

                            for (final byte[] fingerprint : expiredFingerprints) {
                                updateExpired.bind(1, now);
                                updateExpired.bind(2, fingerprint);
                                updateExpired.step();
                                updateExpired.reset();
                            }
                        } catch (final MessagingException e) {
                            logger.log(Level.WARNING, "email error", e);
                        }
                    }
                }

                final ArrayList<Account> accountsForFailureAlert = new ArrayList<>();

                for (final Account account : accountsForFailureAlert) {
                    final StringBuilder failed = new StringBuilder();
                    selectFailed.bind(1, account.userId);
                    while (selectFailed.step()) {
                        final byte[] fingerprint = selectFailed.columnBlob(0);
                        final String encoded = BaseEncoding.base16().encode(fingerprint);
                        failed.append("* ").append(encoded).append("\n");
                    }
                    selectFailed.reset();

                    if (failed.length() == 0) {
                        continue;
                    }

                    selectEmails.bind(1, account.userId);
                    final ArrayList<String> addresses = new ArrayList<>();
                    while (selectEmails.step()) {
                        addresses.add(selectEmails.columnString(0));
                    }
                    selectEmails.reset();

                    for (final String address : addresses) {
                        logger.info("sending email to " + address + " for account " + account.userId);
                        try {
                            final Message message = new MimeMessage(session);
                            message.setFrom(new InternetAddress(emailUsername));
                            message.setRecipients(Message.RecipientType.TO,
                                    InternetAddress.parse(address));
                            message.setSubject("Devices provided invalid attestations");
                            message.setText("This is an alert for the account '" + account.username + "'.\n\n" +
                                    "The following devices have provided invalid attestations:\n\n" +
                                    failed + "\nLog in to https://" + AttestationServer.DOMAIN + "/ for more information.\n\n" +
                                    "If you do not want to receive these alerts and cannot log in to the account,\nemail contact@" + AttestationServer.DOMAIN + " from the address receiving the alerts");

                            Transport.send(message);
                        } catch (final MessagingException e) {
                            logger.log(Level.WARNING, "email error", e);
                        }
                    }
                }
            } catch (final SQLiteException e) {
                logger.log(Level.WARNING, "database error", e);
            } finally {
                try {
                    selectConfiguration.reset();
                    selectAccountsForExpiryAlert.reset();
                    selectExpired.reset();
                    updateExpired.reset();
                    selectFailed.reset();
                    selectEmails.reset();
                } catch (final SQLiteException e) {
                    logger.log(Level.WARNING, "database error", e);
                }
            }

            logger.info("dispatching alerts completed");
        }
    }
}
