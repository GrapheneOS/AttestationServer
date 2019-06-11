package app.attestation.server;

import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;

import java.io.File;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import java.util.ArrayList;
import java.util.Properties;

import com.google.common.io.BaseEncoding;

class AlertDispatcher implements Runnable {
    private static final long WAIT_MS = 15 * 60 * 1000;
    private static final int TIMEOUT_MS = 30 * 1000;

    // Split displayed fingerprint into groups of 4 characters
    private static final int FINGERPRINT_SPLIT_INTERVAL = 4;

    @Override
    public void run() {
        final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        final SQLiteStatement selectConfiguration;
        final SQLiteStatement selectAccounts;
        final SQLiteStatement selectExpired;
        final SQLiteStatement updateExpired;
        final SQLiteStatement selectFailed;
        final SQLiteStatement selectEmails;
        try {
            AttestationServer.open(conn, false);
            selectConfiguration = conn.prepare("SELECT " +
                    "(SELECT value FROM Configuration WHERE key = 'emailLocal'), " +
                    "(SELECT value FROM Configuration WHERE key = 'emailUsername'), " +
                    "(SELECT value FROM Configuration WHERE key = 'emailPassword'), " +
                    "(SELECT value FROM Configuration WHERE key = 'emailHost'), " +
                    "(SELECT value FROM Configuration WHERE key = 'emailPort')");
            selectAccounts = conn.prepare("SELECT userId, alertDelay FROM Accounts");
            selectExpired = conn.prepare("SELECT fingerprint FROM Devices " +
                    "WHERE userId = ? AND verifiedTimeLast < ? AND deletionTime IS NULL");
            updateExpired = conn.prepare("UPDATE Devices SET expiredTimeLast = ? " +
                    "WHERE fingerprint = ?");
            selectFailed = conn.prepare("SELECT fingerprint FROM Devices " +
                    "WHERE userId = ? AND failureTimeLast IS NOT NULL AND deletionTime IS NULL");
            selectEmails = conn.prepare("SELECT address FROM EmailAddresses WHERE userId = ?");
        } catch (final SQLiteException e) {
            conn.dispose();
            throw new RuntimeException(e);
        }

        while (true) {
            try {
                Thread.sleep(WAIT_MS);
            } catch (final InterruptedException e) {
                return;
            }

            System.err.println("dispatching alerts");

            try {
                selectConfiguration.step();
                final int local = selectConfiguration.columnInt(0);
                final String username = selectConfiguration.columnString(1);
                final String password = selectConfiguration.columnString(2);
                final String host = selectConfiguration.columnString(3);
                final String port = selectConfiguration.columnString(4);

                final Session session;
                if (local == 1) {
                    if (username == null) {
                        System.err.println("missing email configuration");
                        continue;
                    }
                    final Properties props = new Properties();
                    props.put("mail.smtp.connectiontimeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtp.timeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtp.writetimeout", Integer.toString(TIMEOUT_MS));
                    session = Session.getInstance(props);
                } else {
                    if (username == null || password == null || host == null || port == null) {
                        System.err.println("missing email configuration");
                        continue;
                    }

                    final Properties props = new Properties();
                    props.put("mail.transport.protocol.rfc822", "smtps");
                    props.put("mail.smtps.auth", true);
                    props.put("mail.smtps.host", host);
                    props.put("mail.smtps.port", port);
                    props.put("mail.smtps.connectiontimeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtps.timeout", Integer.toString(TIMEOUT_MS));
                    props.put("mail.smtps.writetimeout", Integer.toString(TIMEOUT_MS));

                    session = Session.getInstance(props,
                            new javax.mail.Authenticator() {
                                protected PasswordAuthentication getPasswordAuthentication() {
                                    return new PasswordAuthentication(username, password);
                                }
                            });
                }

                while (selectAccounts.step()) {
                    final long userId = selectAccounts.columnLong(0);
                    final int alertDelay = selectAccounts.columnInt(1);

                    final ArrayList<byte[]> expiredFingerprints = new ArrayList<>();
                    final StringBuilder expired = new StringBuilder();
                    selectExpired.bind(1, userId);
                    selectExpired.bind(2, System.currentTimeMillis() - alertDelay * 1000);
                    while (selectExpired.step()) {
                        final byte[] fingerprint = selectExpired.columnBlob(0);
                        expiredFingerprints.add(fingerprint);

                        expired.append("* ");

                        final String encoded = BaseEncoding.base16().encode(fingerprint);

                        for (int i = 0; i < encoded.length(); i += FINGERPRINT_SPLIT_INTERVAL) {
                            expired.append(encoded.substring(i,
                                    Math.min(encoded.length(), i + FINGERPRINT_SPLIT_INTERVAL)));
                            if (i + FINGERPRINT_SPLIT_INTERVAL < encoded.length()) {
                                expired.append("-");
                            }
                        }

                        expired.append("\n");
                    }
                    selectExpired.reset();

                    if (expired.length() > 0) {
                        selectEmails.bind(1, userId);
                        while (selectEmails.step()) {
                            final String address = selectEmails.columnString(0);
                            System.err.println("sending email to " + address);
                            try {
                                final Message message = new MimeMessage(session);
                                message.setFrom(new InternetAddress(username));
                                message.setRecipients(Message.RecipientType.TO,
                                        InternetAddress.parse(address));
                                message.setSubject(
                                        "Devices failed to provide valid attestations within " +
                                        alertDelay / 60 / 60 + " hours");
                                message.setText("The following devices have failed to provide valid attestations before the expiry time:\n\n" +
                                        expired.toString() + "\nLog in to https://attestation.app/ for more information.");

                                Transport.send(message);

                                final long now = System.currentTimeMillis();

                                for (final byte[] fingerprint : expiredFingerprints) {
                                    updateExpired.bind(1, now);
                                    updateExpired.bind(2, fingerprint);
                                    updateExpired.step();
                                    updateExpired.reset();
                                }
                            } catch (final MessagingException e) {
                                e.printStackTrace();
                            }
                        }
                        selectEmails.reset();
                    }

                    final StringBuilder failed = new StringBuilder();
                    selectFailed.bind(1, userId);
                    while (selectFailed.step()) {
                        final byte[] fingerprint = selectFailed.columnBlob(0);
                        final String encoded = BaseEncoding.base16().encode(fingerprint);
                        failed.append("* ").append(encoded).append("\n");
                    }
                    selectFailed.reset();

                    if (failed.length() > 0) {
                        selectEmails.bind(1, userId);
                        while (selectEmails.step()) {
                            final String address = selectEmails.columnString(0);
                            System.err.println("sending email to " + address);
                            try {
                                final Message message = new MimeMessage(session);
                                message.setFrom(new InternetAddress(username));
                                message.setRecipients(Message.RecipientType.TO,
                                        InternetAddress.parse(address));
                                message.setSubject("Devices provided invalid attestations");
                                message.setText("The following devices have provided invalid attestations:\n\n" +
                                        failed.toString());

                                Transport.send(message);
                            } catch (final MessagingException e) {
                                e.printStackTrace();
                            }
                        }
                        selectEmails.reset();
                    }
                }
            } catch (final SQLiteException e) {
                e.printStackTrace();
            } finally {
                try {
                    selectConfiguration.reset();
                    selectAccounts.reset();
                    selectExpired.reset();
                    updateExpired.reset();
                    selectFailed.reset();
                    selectEmails.reset();
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
