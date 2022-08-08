package app.attestation.server;

import app.attestation.server.AttestationProtocol.DeviceInfo;
import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;
import jakarta.json.JsonWriter;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import org.bouncycastle.crypto.generators.SCrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.DataFormatException;

import static app.attestation.server.attestation.Attestation.KM_SECURITY_LEVEL_STRONG_BOX;
import static app.attestation.server.AttestationProtocol.fingerprintsCustomOS;
import static app.attestation.server.AttestationProtocol.fingerprintsStock;
import static app.attestation.server.AttestationProtocol.fingerprintsStrongBoxCustomOS;
import static app.attestation.server.AttestationProtocol.fingerprintsStrongBoxStock;
import static com.almworks.sqlite4java.SQLiteConstants.SQLITE_CONSTRAINT_UNIQUE;

public class AttestationServer {
    static final File SAMPLES_DATABASE = new File("samples.db");
    private static final int MAX_SAMPLE_SIZE = 64 * 1024;

    private static final int DEFAULT_VERIFY_INTERVAL = 4 * 60 * 60;
    private static final int MIN_VERIFY_INTERVAL = 60 * 60;
    private static final int MAX_VERIFY_INTERVAL = 7 * 24 * 70 * 60;
    private static final int DEFAULT_ALERT_DELAY = 48 * 60 * 60;
    private static final int MIN_ALERT_DELAY = 32 * 60 * 60;
    private static final int MAX_ALERT_DELAY = 2 * 7 * 24 * 60 * 60;
    private static final int BUSY_TIMEOUT = 10 * 1000;
    private static final int QR_CODE_PIXEL_SIZE = 300;
    private static final long SESSION_LENGTH = 48 * 60 * 60 * 1000;
    private static final int HISTORY_PER_PAGE = 20;

    private static final String DOMAIN = "attestation.app";
    private static final String ORIGIN = "https://" + DOMAIN;

    private static final Logger logger = Logger.getLogger(AttestationServer.class.getName());

    // This should be moved to a table in the database so that it can be modified dynamically
    // without modifying the source code.
    private static final String[] emailBlacklistPatterns = {
        "(contact|security|webmaster)@(attestation.app|grapheneos.org|seamlessupdate.app)"
    };

    private static final Cache<ByteBuffer, Boolean> pendingChallenges = Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.MINUTES)
            .maximumSize(1000000)
            .build();

    static SQLiteConnection open(final File db, final boolean readOnly) throws SQLiteException {
        final SQLiteConnection conn = new SQLiteConnection(db);
        if (readOnly) {
            conn.openReadonly();
        } else {
            conn.open();
        }
        try {
            conn.setBusyTimeout(BUSY_TIMEOUT);
            conn.exec("PRAGMA foreign_keys = ON");
            conn.exec("PRAGMA journal_mode = WAL");
            conn.exec("PRAGMA trusted_schema = OFF");
        } catch (final Exception e) {
            conn.dispose();
            throw e;
        }
        return conn;
    }

    private static void createAttestationTables(final SQLiteConnection conn) throws SQLiteException {
        conn.exec(
                "CREATE TABLE IF NOT EXISTS Configuration (\n" +
                "key TEXT PRIMARY KEY NOT NULL,\n" +
                "value ANY NOT NULL\n" +
                ") STRICT");

        conn.exec(
                "CREATE TABLE IF NOT EXISTS Accounts (\n" +
                "userId INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\n" +
                "username TEXT NOT NULL COLLATE NOCASE UNIQUE,\n" +
                "passwordHash BLOB NOT NULL,\n" +
                "passwordSalt BLOB NOT NULL,\n" +
                "subscribeKey BLOB NOT NULL,\n" +
                "creationTime INTEGER NOT NULL,\n" +
                "loginTime INTEGER NOT NULL,\n" +
                "verifyInterval INTEGER NOT NULL,\n" +
                "alertDelay INTEGER NOT NULL\n" +
                ") STRICT");

        conn.exec(
                "CREATE TABLE IF NOT EXISTS EmailAddresses (\n" +
                "userId INTEGER NOT NULL REFERENCES Accounts (userId) ON DELETE CASCADE,\n" +
                "address TEXT NOT NULL,\n" +
                "PRIMARY KEY (userId, address)\n" +
                ") STRICT");

        conn.exec(
                "CREATE TABLE IF NOT EXISTS Sessions (\n" +
                "sessionId INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\n" +
                "userId INTEGER NOT NULL REFERENCES Accounts (userId) ON DELETE CASCADE,\n" +
                "token BLOB NOT NULL,\n" +
                "expiryTime INTEGER NOT NULL\n" +
                ") STRICT");

        conn.exec(
                "CREATE TABLE IF NOT EXISTS Devices (\n" +
                "fingerprint BLOB NOT NULL PRIMARY KEY,\n" +
                "pinnedCertificates BLOB NOT NULL,\n" +
                "attestKey INTEGER NOT NULL CHECK (attestKey in (0, 1)),\n" +
                "pinnedVerifiedBootKey BLOB NOT NULL,\n" +
                "verifiedBootHash BLOB,\n" +
                "pinnedOsVersion INTEGER NOT NULL,\n" +
                "pinnedOsPatchLevel INTEGER NOT NULL,\n" +
                "pinnedVendorPatchLevel INTEGER,\n" +
                "pinnedBootPatchLevel INTEGER,\n" +
                "pinnedAppVersion INTEGER NOT NULL,\n" +
                "pinnedSecurityLevel INTEGER NOT NULL,\n" +
                "userProfileSecure INTEGER NOT NULL CHECK (userProfileSecure in (0, 1)),\n" +
                "enrolledBiometrics INTEGER NOT NULL CHECK (enrolledBiometrics in (0, 1)),\n" +
                "accessibility INTEGER NOT NULL CHECK (accessibility in (0, 1)),\n" +
                "deviceAdmin INTEGER NOT NULL CHECK (deviceAdmin in (0, 1, 2)),\n" +
                "adbEnabled INTEGER NOT NULL CHECK (adbEnabled in (0, 1)),\n" +
                "addUsersWhenLocked INTEGER NOT NULL CHECK (addUsersWhenLocked in (0, 1)),\n" +
                "denyNewUsb INTEGER NOT NULL CHECK (denyNewUsb in (0, 1)),\n" +
                "oemUnlockAllowed INTEGER NOT NULL CHECK (oemUnlockAllowed in (0, 1)),\n" +
                "systemUser INTEGER NOT NULL CHECK (systemUser in (0, 1)),\n" +
                "verifiedTimeFirst INTEGER NOT NULL,\n" +
                "verifiedTimeLast INTEGER NOT NULL,\n" +
                "expiredTimeLast INTEGER,\n" +
                "failureTimeLast INTEGER,\n" +
                "userId INTEGER NOT NULL REFERENCES Accounts (userId) ON DELETE CASCADE,\n" +
                "deletionTime INTEGER\n" +
                ") STRICT");

        conn.exec(
                "CREATE TABLE IF NOT EXISTS Attestations (\n" +
                "id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\n" +
                "fingerprint BLOB NOT NULL REFERENCES Devices (fingerprint) ON DELETE CASCADE,\n" +
                "time INTEGER NOT NULL,\n" +
                "strong INTEGER NOT NULL CHECK (strong in (0, 1)),\n" +
                "osVersion INTEGER NOT NULL,\n" +
                "osPatchLevel INTEGER NOT NULL,\n" +
                "vendorPatchLevel INTEGER,\n" +
                "bootPatchLevel INTEGER,\n" +
                "verifiedBootHash BLOB,\n" +
                "appVersion INTEGER NOT NULL,\n" +
                "userProfileSecure INTEGER NOT NULL CHECK (userProfileSecure in (0, 1)),\n" +
                "enrolledBiometrics INTEGER NOT NULL CHECK (enrolledBiometrics in (0, 1)),\n" +
                "accessibility INTEGER NOT NULL CHECK (accessibility in (0, 1)),\n" +
                "deviceAdmin INTEGER NOT NULL CHECK (deviceAdmin in (0, 1, 2)),\n" +
                "adbEnabled INTEGER NOT NULL CHECK (adbEnabled in (0, 1)),\n" +
                "addUsersWhenLocked INTEGER NOT NULL CHECK (addUsersWhenLocked in (0, 1)),\n" +
                "denyNewUsb INTEGER NOT NULL CHECK (denyNewUsb in (0, 1)),\n" +
                "oemUnlockAllowed INTEGER NOT NULL CHECK (oemUnlockAllowed in (0, 1)),\n" +
                "systemUser INTEGER NOT NULL CHECK (systemUser in (0, 1))\n" +
                ") STRICT");
    }

    private static void createAttestationIndices(final SQLiteConnection conn) throws SQLiteException {
        conn.exec("CREATE INDEX IF NOT EXISTS Accounts_loginTime " +
                "ON Accounts (loginTime)");

        conn.exec("CREATE INDEX IF NOT EXISTS Sessions_expiryTime " +
                "ON Sessions (expiryTime)");
        conn.exec("CREATE INDEX IF NOT EXISTS Sessions_userId " +
                "ON Sessions (userId)");

        conn.exec("CREATE INDEX IF NOT EXISTS Devices_userId_verifiedTimeFirst " +
                "ON Devices (userId, verifiedTimeFirst)");
        conn.exec("CREATE INDEX IF NOT EXISTS Devices_userId_verifiedTimeLast_deletionTimeNull " +
                "ON Devices (userId, verifiedTimeLast) WHERE deletionTime IS NULL");
        conn.exec("CREATE INDEX IF NOT EXISTS Devices_deletionTime " +
                "ON Devices (deletionTime) WHERE deletionTime IS NOT NULL");
        conn.exec("CREATE INDEX IF NOT EXISTS Devices_verifiedTimeLast_deletionTimeNull " +
                "ON Devices (verifiedTimeLast) WHERE deletionTime IS NULL");

        conn.exec("CREATE INDEX IF NOT EXISTS Attestations_fingerprint_id " +
                "ON Attestations (fingerprint, id)");
    }

    private static void createSamplesTable(final SQLiteConnection conn) throws SQLiteException {
        conn.exec(
                "CREATE TABLE IF NOT EXISTS Samples (\n" +
                "sample BLOB NOT NULL,\n" +
                "time INTEGER NOT NULL\n" +
                ") STRICT");
    }

    private static int getUserVersion(final SQLiteConnection conn) throws SQLiteException {
        SQLiteStatement pragmaUserVersion = null;
        try {
            pragmaUserVersion = conn.prepare("PRAGMA user_version");
            pragmaUserVersion.step();
            int userVersion = pragmaUserVersion.columnInt(0);
            logger.info("Existing schema version: " + userVersion);
            return userVersion;
        } finally {
            if (pragmaUserVersion != null) {
                pragmaUserVersion.dispose();
            }
        }
    }

    public static void main(final String[] args) throws Exception {
        final SQLiteConnection samplesConn = open(SAMPLES_DATABASE, false);
        try {
            final SQLiteStatement selectCreated = samplesConn.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='Samples'");
            if (!selectCreated.step()) {
                samplesConn.exec("PRAGMA user_version = 1");
            }
            selectCreated.dispose();

            int userVersion = getUserVersion(samplesConn);

            createSamplesTable(samplesConn);

            // migrate to STRICT table
            if (userVersion == 0) {
                samplesConn.exec("PRAGMA foreign_keys = OFF");
                samplesConn.exec("BEGIN IMMEDIATE TRANSACTION");

                samplesConn.exec("ALTER TABLE Samples RENAME TO OldSamples");

                createSamplesTable(samplesConn);

                samplesConn.exec("INSERT INTO Samples " +
                        "(sample, time) " +
                        "SELECT " +
                        "sample, time " +
                        "FROM OldSamples");

                samplesConn.exec("DROP TABLE OldSamples");

                samplesConn.exec("PRAGMA user_version = 1");
                samplesConn.exec("COMMIT TRANSACTION");
                userVersion = 1;
                samplesConn.exec("PRAGMA foreign_keys = ON");
            }

            logger.info("New schema version: " + userVersion);
        } finally {
            samplesConn.dispose();
        }

        final SQLiteConnection attestationConn = open(AttestationProtocol.ATTESTATION_DATABASE, false);
        try {
            final SQLiteStatement selectCreated = attestationConn.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='Configuration'");
            if (!selectCreated.step()) {
                attestationConn.exec("PRAGMA user_version = 10");
            }
            selectCreated.dispose();

            int userVersion = getUserVersion(attestationConn);

            createAttestationTables(attestationConn);
            createAttestationIndices(attestationConn);

            if (userVersion < 7) {
                throw new RuntimeException("Database schemas older than version 4 are no longer " +
                        "supported. Use an older AttestationServer revision to upgrade.");
            }

            // add attestKey column to Devices table with default 0 value
            if (userVersion < 8) {
                attestationConn.exec("PRAGMA foreign_keys = OFF");
                attestationConn.exec("BEGIN IMMEDIATE TRANSACTION");

                attestationConn.exec("ALTER TABLE Devices RENAME TO OldDevices");
                attestationConn.exec("ALTER TABLE Attestations RENAME TO OldAttestations");

                createAttestationTables(attestationConn);

                attestationConn.exec("INSERT INTO Devices " +
                        "(fingerprint, pinnedCertificates, attestKey, pinnedVerifiedBootKey, verifiedBootHash, pinnedOsVersion, pinnedOsPatchLevel, pinnedVendorPatchLevel, pinnedBootPatchLevel, pinnedAppVersion, pinnedSecurityLevel, userProfileSecure, enrolledBiometrics, accessibility, deviceAdmin, adbEnabled, addUsersWhenLocked, denyNewUsb, oemUnlockAllowed, systemUser, verifiedTimeFirst, verifiedTimeLast, expiredTimeLast, failureTimeLast, userId, deletionTime) " +
                        "SELECT " +
                        "fingerprint, pinnedCertificates, 0, pinnedVerifiedBootKey, verifiedBootHash, pinnedOsVersion, pinnedOsPatchLevel, pinnedVendorPatchLevel, pinnedBootPatchLevel, pinnedAppVersion, pinnedSecurityLevel, userProfileSecure, enrolledBiometrics, accessibility, deviceAdmin, adbEnabled, addUsersWhenLocked, denyNewUsb, oemUnlockAllowed, systemUser, verifiedTimeFirst, verifiedTimeLast, expiredTimeLast, failureTimeLast, userId, deletionTime " +
                        "FROM OldDevices");

                attestationConn.exec("INSERT INTO Attestations " +
                        "(id, fingerprint, time, strong, teeEnforced, osEnforced) " +
                        "SELECT " +
                        "id, fingerprint, time, strong, teeEnforced, osEnforced " +
                        "FROM OldAttestations");

                attestationConn.exec("DROP TABLE OldDevices");
                attestationConn.exec("DROP TABLE OldAttestations");

                createAttestationIndices(attestationConn);
                attestationConn.exec("PRAGMA user_version = 8");
                attestationConn.exec("COMMIT TRANSACTION");
                userVersion = 8;
                attestationConn.exec("PRAGMA foreign_keys = ON");
                logger.info("Migrated to schema version: " + userVersion);
            }

            // remove obsolete requestToken column from Sessions table
            if (userVersion < 9) {
                attestationConn.exec("PRAGMA foreign_keys = OFF");
                attestationConn.exec("BEGIN IMMEDIATE TRANSACTION");

                attestationConn.exec("ALTER TABLE Sessions RENAME TO OldSessions");

                createAttestationTables(attestationConn);

                attestationConn.exec("INSERT INTO Sessions " +
                        "(sessionId, userId, token, expiryTime) " +
                        "SELECT " +
                        "sessionId, userId, cookieToken, expiryTime " +
                        "FROM OldSessions");

                attestationConn.exec("DROP TABLE OldSessions");

                createAttestationIndices(attestationConn);
                attestationConn.exec("PRAGMA user_version = 9");
                attestationConn.exec("COMMIT TRANSACTION");
                userVersion = 9;
                attestationConn.exec("PRAGMA foreign_keys = ON");
                logger.info("Migrated to schema version: " + userVersion);
            }

            // remove obsolete backups key from Configuration table
            if (userVersion < 10) {
                attestationConn.exec("DELETE FROM Configuration WHERE key = 'backups'");

                attestationConn.exec("PRAGMA foreign_keys = OFF");
                attestationConn.exec("BEGIN IMMEDIATE TRANSACTION");

                attestationConn.exec("ALTER TABLE Attestations RENAME TO OldAttestations");

                createAttestationTables(attestationConn);

                final SQLiteStatement select = attestationConn.prepare("SELECT id, fingerprint, time, strong, teeEnforced, osEnforced FROM OldAttestations");
                final SQLiteStatement insert = attestationConn.prepare("INSERT INTO Attestations " +
                        "(id, fingerprint, time, strong, osVersion, osPatchLevel, vendorPatchLevel, bootPatchLevel, verifiedBootHash, appVersion, userProfileSecure, enrolledBiometrics, accessibility, deviceAdmin, adbEnabled, addUsersWhenLocked, denyNewUsb, oemUnlockAllowed, systemUser) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

                while (select.step()) {
                    insert.bind(1, select.columnLong(0));
                    insert.bind(2, select.columnBlob(1));
                    insert.bind(3, select.columnLong(2));
                    insert.bind(4, select.columnInt(3));

                    final String[] teeEnforced = select.columnString(4).split("\n");
                    for (final String line : teeEnforced) {
                        final String[] pair = line.split(": ");
                        switch (pair[0]) {
                            case "OS version":
                                final String[] versionSplit = pair[1].split("\\.");
                                if (versionSplit.length != 3) {
                                    throw new RuntimeException("unreachable");
                                }
                                int version = Integer.parseInt(String.format("%d%02d%02d",
                                        Integer.parseInt(versionSplit[0]), Integer.parseInt(versionSplit[1]), Integer.parseInt(versionSplit[2])));
                                insert.bind(5, version);
                                break;
                            case "OS patch level":
                                insert.bind(6, Integer.parseInt(pair[1].replace("-", "")));
                                break;
                            case "Vendor patch level":
                                insert.bind(7, Integer.parseInt(pair[1].replace("-", "")));
                                break;
                            case "Boot patch level":
                                insert.bind(8, Integer.parseInt(pair[1].replace("-", "")));
                                break;
                            case "Verified boot hash":
                                insert.bind(9, BaseEncoding.base16().decode(pair[1]));
                                break;
                            default:
                                throw new RuntimeException("unreachable");
                        }
                    }
                    final String[] osEnforced = select.columnString(5).split("\n");
                    for (final String line : osEnforced) {
                        final String[] pair = line.split(": ");
                        switch (pair[0]) {
                            case "Auditor app version":
                                insert.bind(10, Integer.parseInt(pair[1]));
                                break;
                            case "User profile secure":
                                insert.bind(11, pair[1].equals("yes") ? 1 : 0);
                                break;
                            case "Enrolled fingerprints":
                            case "Enrolled biometrics":
                                insert.bind(12, pair[1].equals("yes") ? 1 : 0);
                                break;
                            case "Accessibility service(s) enabled":
                                insert.bind(13, pair[1].equals("yes") ? 1 : 0);
                                break;
                            case "Device administrator(s) enabled":
                                if (pair[1].equals("no")) {
                                    insert.bind(14, 0);
                                } else if (pair[1].equals("yes, but only system apps")) {
                                    insert.bind(14, 1);
                                } else if (pair[1].equals("yes, with non-system apps")) {
                                    insert.bind(14, 2);
                                } else {
                                    throw new RuntimeException("unreachable");
                                }
                                break;
                            case "Android Debug Bridge enabled":
                                insert.bind(15, pair[1].equals("yes") ? 1 : 0);
                                break;
                            case "Add users from lock screen":
                                insert.bind(16, pair[1].equals("yes") ? 1 : 0);
                                break;
                            case "Disallow new USB peripherals when locked":
                                insert.bind(17, pair[1].equals("yes") ? 1 : 0);
                                break;
                            case "OEM unlocking allowed":
                                insert.bind(18, pair[1].equals("yes") ? 1 : 0);
                                break;
                            case "Main user account":
                                insert.bind(19, pair[1].equals("yes") ? 1 : 0);
                                break;
                            default:
                                throw new RuntimeException("unreachable");
                        }
                    }

                    insert.step();
                    insert.reset();
                }
                insert.dispose();
                select.dispose();

                attestationConn.exec("DROP TABLE OldAttestations");

                createAttestationIndices(attestationConn);

                attestationConn.exec("PRAGMA user_version = 10");
                attestationConn.exec("COMMIT TRANSACTION");
                userVersion = 10;
                attestationConn.exec("PRAGMA foreign_keys = ON");
                logger.info("Migrated to schema version: " + userVersion);
            }

            logger.info("Finished database setup");
        } finally {
            attestationConn.dispose();
        }

        new Thread(new AlertDispatcher()).start();
        new Thread(new Maintenance()).start();

        final ThreadPoolExecutor executor = new ThreadPoolExecutor(128, 128, 0, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>(1024));
        executor.prestartAllCoreThreads();

        System.setProperty("sun.net.httpserver.nodelay", "true");
        final HttpServer server = HttpServer.create(new InetSocketAddress("::1", 8080), 4096);
        server.createContext("/api/status", new StatusHandler());
        server.createContext("/api/create-account", new CreateAccountHandler());
        server.createContext("/api/change-password", new ChangePasswordHandler());
        server.createContext("/api/login", new LoginHandler());
        server.createContext("/api/logout", new LogoutHandler());
        server.createContext("/api/logout-everywhere", new LogoutEverywhereHandler());
        server.createContext("/api/rotate", new RotateHandler());
        server.createContext("/api/account", new AccountHandler());
        server.createContext("/api/account.png", new AccountQrHandler());
        server.createContext("/api/configuration", new ConfigurationHandler());
        server.createContext("/api/delete-device", new DeleteDeviceHandler());
        server.createContext("/api/devices.json", new DevicesHandler());
        server.createContext("/api/attestation-history.json", new AttestationHistoryHandler());
        server.createContext("/challenge", new ChallengeHandler());
        server.createContext("/verify", new VerifyHandler());
        server.createContext("/submit", new SubmitHandler());
        server.setExecutor(executor);
        server.start();
    }

    private static String getRequestHeaderValue(final HttpExchange exchange, final String header)
            throws GeneralSecurityException {
        final List<String> values = exchange.getRequestHeaders().get(header);
        if (values == null) {
            return null;
        }
        if (values.size() > 1) {
            throw new GeneralSecurityException("multiple values for '" + header + "' header");
        }
        return values.get(0);
    }

    private abstract static class PostHandler implements HttpHandler {
        protected abstract void handlePost(final HttpExchange exchange) throws IOException, SQLiteException;

        public void checkRequestHeaders(final HttpExchange exchange) throws GeneralSecurityException {
            final String origin = getRequestHeaderValue(exchange, "Origin");
            if (origin == null || !origin.equals(ORIGIN)) {
                throw new GeneralSecurityException();
            }
            final String contentType = getRequestHeaderValue(exchange, "Content-Type");
            if (contentType == null || !contentType.equals("application/json")) {
                throw new GeneralSecurityException();
            }
            final String fetchMode = getRequestHeaderValue(exchange, "Sec-Fetch-Mode");
            if (fetchMode != null && !fetchMode.equals("same-origin")) {
                throw new GeneralSecurityException();
            }
            final String fetchSite = getRequestHeaderValue(exchange, "Sec-Fetch-Site");
            if (fetchSite != null && !fetchSite.equals("same-origin")) {
                throw new GeneralSecurityException();
            }
            final String fetchDest = getRequestHeaderValue(exchange, "Sec-Fetch-Dest");
            if (fetchDest != null && !fetchDest.equals("empty")) {
                throw new GeneralSecurityException();
            }
        }

        @Override
        public final void handle(final HttpExchange exchange) throws IOException {
            try {
                if (!exchange.getRequestMethod().equals("POST")) {
                    exchange.getResponseHeaders().set("Allow", "POST");
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }
                try {
                    checkRequestHeaders(exchange);
                } catch (final GeneralSecurityException e) {
                    logger.log(Level.INFO, "invalid request headers", e);
                    exchange.sendResponseHeaders(403, -1);
                    return;
                }
                handlePost(exchange);
            } catch (final Exception e) {
                logger.log(Level.SEVERE, "unhandled error handling request", e);
                exchange.sendResponseHeaders(500, -1);
            } finally {
                exchange.close();
            }
        }
    }

    private abstract static class AppPostHandler extends PostHandler {
        @Override
        public void checkRequestHeaders(final HttpExchange exchange) throws GeneralSecurityException {
            if (getRequestHeaderValue(exchange, "Origin") != null) {
                throw new GeneralSecurityException();
            }
        }
    }

    private static class StatusHandler extends AppPostHandler {
        @Override
        public final void handlePost(final HttpExchange exchange) throws IOException {
            final byte[] response = "success\n".getBytes();
            exchange.sendResponseHeaders(200, response.length);
            try (final OutputStream output = exchange.getResponseBody()) {
                output.write(response);
            }
        }
    }

    private static final SecureRandom random = new SecureRandom();

    private static byte[] generateRandomToken() {
        final byte[] token = new byte[32];
        random.nextBytes(token);
        return token;
    }

    private static byte[] hash(final byte[] password, final byte[] salt) {
        return SCrypt.generate(password, salt, 32768, 8, 1, 32);
    }

    private static class UsernameUnavailableException extends GeneralSecurityException {
        public UsernameUnavailableException() {}
    }

    private static void validateUsername(final String username) throws GeneralSecurityException {
        if (username.length() > 32 || !username.matches("[a-zA-Z0-9]+")) {
            throw new GeneralSecurityException("invalid username");
        }
    }

    private static void validateUnicode(final String s) throws CharacterCodingException {
        StandardCharsets.UTF_16LE.newEncoder().encode(CharBuffer.wrap(s));
    }

    private static void validatePassword(final String password) throws GeneralSecurityException {
        if (password.length() < 8 || password.length() > 256) {
            throw new GeneralSecurityException("invalid password");
        }

        try {
            validateUnicode(password);
        } catch (final CharacterCodingException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private static void createAccount(final String username, final String password)
            throws GeneralSecurityException, SQLiteException {
        validateUsername(username);
        validatePassword(password);

        final byte[] passwordSalt = generateRandomToken();
        final byte[] passwordHash = hash(password.getBytes(), passwordSalt);
        final byte[] subscribeKey = generateRandomToken();

        final SQLiteConnection conn = open(AttestationProtocol.ATTESTATION_DATABASE, false);
        try {
            final SQLiteStatement insert = conn.prepare("INSERT INTO Accounts " +
                    "(username, passwordHash, passwordSalt, subscribeKey, creationTime, loginTime, verifyInterval, alertDelay) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            insert.bind(1, username);
            insert.bind(2, passwordHash);
            insert.bind(3, passwordSalt);
            insert.bind(4, subscribeKey);
            final long now = System.currentTimeMillis();
            insert.bind(5, now);
            insert.bind(6, now);
            insert.bind(7, DEFAULT_VERIFY_INTERVAL);
            insert.bind(8, DEFAULT_ALERT_DELAY);
            insert.step();
            insert.dispose();
        } catch (final SQLiteException e) {
            if (e.getErrorCode() == SQLITE_CONSTRAINT_UNIQUE) {
                throw new UsernameUnavailableException();
            }
            throw e;
        } finally {
            conn.dispose();
        }
    }

    private static void changePassword(final long userId, final String currentPassword, final String newPassword)
            throws GeneralSecurityException, SQLiteException {
        validatePassword(currentPassword);
        validatePassword(newPassword);

        final SQLiteConnection conn = open(AttestationProtocol.ATTESTATION_DATABASE, false);
        try {
            conn.exec("BEGIN IMMEDIATE TRANSACTION");

            final SQLiteStatement select = conn.prepare("SELECT passwordHash, passwordSalt " +
                    "FROM Accounts WHERE userId = ?");
            select.bind(1, userId);
            select.step();
            final byte[] currentPasswordHash = select.columnBlob(0);
            final byte[] currentPasswordSalt = select.columnBlob(1);
            select.dispose();
            if (!MessageDigest.isEqual(hash(currentPassword.getBytes(), currentPasswordSalt), currentPasswordHash)) {
                throw new GeneralSecurityException("invalid password");
            }

            final byte[] newPasswordSalt = generateRandomToken();
            final byte[] newPasswordHash = hash(newPassword.getBytes(), newPasswordSalt);

            final SQLiteStatement update = conn.prepare("UPDATE Accounts " +
                    "SET passwordHash = ?, passwordSalt = ? WHERE userId = ?");
            update.bind(1, newPasswordHash);
            update.bind(2, newPasswordSalt);
            update.bind(3, userId);
            update.step();
            update.dispose();

            conn.exec("COMMIT TRANSACTION");
        } finally {
            conn.dispose();
        }
    }

    private static class Session {
        final long sessionId;
        final byte[] token;

        Session(final long sessionId, final byte[] token) {
            this.sessionId = sessionId;
            this.token = token;
        }
    }

    private static Session login(final String username, final String password)
            throws GeneralSecurityException, SQLiteException {
        validatePassword(password);

        final SQLiteConnection conn = open(AttestationProtocol.ATTESTATION_DATABASE, false);
        try {
            conn.exec("BEGIN IMMEDIATE TRANSACTION");

            final SQLiteStatement select = conn.prepare("SELECT userId, passwordHash, " +
                    "passwordSalt FROM Accounts WHERE username = ?");
            select.bind(1, username);
            if (!select.step()) {
                throw new UsernameUnavailableException();
            }
            final long userId = select.columnLong(0);
            final byte[] passwordHash = select.columnBlob(1);
            final byte[] passwordSalt = select.columnBlob(2);
            select.dispose();
            if (!MessageDigest.isEqual(hash(password.getBytes(), passwordSalt), passwordHash)) {
                throw new GeneralSecurityException("invalid password");
            }

            final long now = System.currentTimeMillis();
            final SQLiteStatement delete = conn.prepare("DELETE FROM Sessions WHERE expiryTime < ?");
            delete.bind(1, now);
            delete.step();
            delete.dispose();

            final byte[] token = generateRandomToken();

            final SQLiteStatement insert = conn.prepare("INSERT INTO Sessions " +
                    "(userId, token, expiryTime) VALUES (?, ?, ?)");
            insert.bind(1, userId);
            insert.bind(2, token);
            insert.bind(3, now + SESSION_LENGTH);
            insert.step();
            insert.dispose();

            final SQLiteStatement updateLoginTime = conn.prepare("UPDATE Accounts SET " +
                    "loginTime = ? WHERE userId = ?");
            updateLoginTime.bind(1, now);
            updateLoginTime.bind(2, userId);
            updateLoginTime.step();
            updateLoginTime.dispose();

            conn.exec("COMMIT TRANSACTION");

            return new Session(conn.getLastInsertId(), token);
        } finally {
            conn.dispose();
        }
    }

    private static class CreateAccountHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final String username;
            final String password;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                final JsonObject object = reader.readObject();
                username = object.getString("username");
                password = object.getString("password");
            } catch (final ClassCastException | JsonException | NullPointerException e) {
                logger.log(Level.INFO, "invalid request", e);
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            try {
                createAccount(username, password);
            } catch (final UsernameUnavailableException e) {
                exchange.sendResponseHeaders(409, -1);
                return;
            } catch (final GeneralSecurityException e) {
                logger.log(Level.INFO, "invalid request", e);
                exchange.sendResponseHeaders(400, -1);
                return;
            }
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static class ChangePasswordHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final String currentPassword;
            final String newPassword;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                final JsonObject object = reader.readObject();
                currentPassword = object.getString("currentPassword");
                newPassword = object.getString("newPassword");
            } catch (final ClassCastException | JsonException | NullPointerException e) {
                logger.log(Level.INFO, "invalid request", e);
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final Account account = verifySession(exchange, false);
            if (account == null) {
                return;
            }

            try {
                changePassword(account.userId, currentPassword, newPassword);
            } catch (final GeneralSecurityException e) {
                logger.log(Level.INFO, "invalid request", e);
                exchange.sendResponseHeaders(400, -1);
                return;
            }
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static class LoginHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final String username;
            final String password;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                final JsonObject object = reader.readObject();
                username = object.getString("username");
                password = object.getString("password");
            } catch (final ClassCastException | JsonException | NullPointerException e) {
                logger.log(Level.INFO, "invalid request", e);
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final Session session;
            try {
                session = login(username, password);
            } catch (final UsernameUnavailableException e) {
                exchange.sendResponseHeaders(400, -1);
                return;
            } catch (final GeneralSecurityException e) {
                logger.log(Level.INFO, "invalid login information", e);
                exchange.sendResponseHeaders(403, -1);
                return;
            }

            final Base64.Encoder encoder = Base64.getEncoder();
            exchange.getResponseHeaders().set("Set-Cookie",
                    String.format("__Host-session=%d|%s; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=%d",
                        session.sessionId, new String(encoder.encode(session.token)),
                        SESSION_LENGTH / 1000));
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static class LogoutHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final Account account = verifySession(exchange, true);
            if (account == null) {
                return;
            }
            purgeSessionCookie(exchange);
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static class LogoutEverywhereHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final Account account = verifySession(exchange, false);
            if (account == null) {
                return;
            }
            final SQLiteConnection conn = open(AttestationProtocol.ATTESTATION_DATABASE, false);
            try {
                final SQLiteStatement select = conn.prepare("DELETE FROM Sessions WHERE userId = ?");
                select.bind(1, account.userId);
                select.step();
                select.dispose();
            } finally {
                conn.dispose();
            }
            purgeSessionCookie(exchange);
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static class RotateHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final Account account = verifySession(exchange, false);
            if (account == null) {
                return;
            }
            final SQLiteConnection conn = open(AttestationProtocol.ATTESTATION_DATABASE, false);
            try {
                final byte[] subscribeKey = generateRandomToken();

                final SQLiteStatement select = conn.prepare("UPDATE Accounts SET " +
                        "subscribeKey = ? WHERE userId = ?");
                select.bind(1, subscribeKey);
                select.bind(2, account.userId);
                select.step();
                select.dispose();
            } finally {
                conn.dispose();
            }
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static String getCookie(final HttpExchange exchange, final String key) {
        final List<String> cookieHeaders = exchange.getRequestHeaders().get("Cookie");
        if (cookieHeaders == null) {
            return null;
        }
        for (final String cookieHeader : cookieHeaders) {
            final String[] cookies = cookieHeader.split(";");
            for (final String cookie : cookies) {
                final String[] keyValue = cookie.trim().split("=", 2);
                if (keyValue.length == 2) {
                    if (keyValue[0].equals(key)) {
                        return keyValue[1];
                    }
                }
            }
        }
        return null;
    }

    private static void purgeSessionCookie(final HttpExchange exchange) {
        exchange.getResponseHeaders().set("Set-Cookie",
                "__Host-session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0");
    }

    private static class Account {
        final long userId;
        final String username;
        final byte[] subscribeKey;
        final int verifyInterval;
        final int alertDelay;

        Account(final long userId, final String username, final byte[] subscribeKey,
                final int verifyInterval, final int alertDelay) {
            this.userId = userId;
            this.username = username;
            this.subscribeKey = subscribeKey;
            this.verifyInterval = verifyInterval;
            this.alertDelay = alertDelay;
        }
    }

    private static Account verifySession(final HttpExchange exchange, final boolean end)
            throws IOException, SQLiteException {
        final String cookie = getCookie(exchange, "__Host-session");
        if (cookie == null) {
            exchange.sendResponseHeaders(403, -1);
            return null;
        }
        final String[] session = cookie.split("\\|", 2);
        if (session.length != 2) {
            purgeSessionCookie(exchange);
            exchange.sendResponseHeaders(403, -1);
            return null;
        }
        final long sessionId = Long.parseLong(session[0]);
        final byte[] token = Base64.getDecoder().decode(session[1]);

        final SQLiteConnection conn = open(AttestationProtocol.ATTESTATION_DATABASE, !end);
        try {
            final SQLiteStatement select = conn.prepare("SELECT token, expiryTime, " +
                    "username, subscribeKey, Accounts.userId, verifyInterval, alertDelay " +
                    "FROM Sessions " +
                    "INNER JOIN Accounts on Accounts.userId = Sessions.userId " +
                    "WHERE sessionId = ?");
            select.bind(1, sessionId);
            if (!select.step() || !MessageDigest.isEqual(token, select.columnBlob(0))) {
                purgeSessionCookie(exchange);
                exchange.sendResponseHeaders(403, -1);
                return null;
            }

            if (select.columnLong(1) < System.currentTimeMillis()) {
                purgeSessionCookie(exchange);
                exchange.sendResponseHeaders(403, -1);
                return null;
            }

            if (end) {
                final SQLiteStatement delete = conn.prepare("DELETE FROM Sessions " +
                        "WHERE sessionId = ?");
                delete.bind(1, sessionId);
                delete.step();
                delete.dispose();
            }

            return new Account(select.columnLong(4), select.columnString(2), select.columnBlob(3),
                    select.columnInt(5), select.columnInt(6));
        } finally {
            conn.dispose();
        }
    }

    private static class AccountHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final Account account = verifySession(exchange, false);
            if (account == null) {
                return;
            }
            final JsonObjectBuilder accountJson = Json.createObjectBuilder();
            accountJson.add("username", account.username);
            accountJson.add("verifyInterval", account.verifyInterval);
            accountJson.add("alertDelay", account.alertDelay);

            final SQLiteConnection conn = open(AttestationProtocol.ATTESTATION_DATABASE, true);
            try {
                final SQLiteStatement select = conn.prepare("SELECT address FROM EmailAddresses " +
                        "WHERE userId = ?");
                select.bind(1, account.userId);
                if (select.step()) {
                    accountJson.add("email", select.columnString(0));
                }
                select.dispose();
            } finally {
                conn.dispose();
            }

            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, 0);
            try (final OutputStream output = exchange.getResponseBody();
                    final JsonWriter writer = Json.createWriter(output)) {
                writer.write(accountJson.build());
            }
        }
    }

    private static void writeQrCode(final byte[] contents, final OutputStream output) throws IOException {
        try {
            final QRCodeWriter writer = new QRCodeWriter();
            final Map<EncodeHintType,Object> hints = new EnumMap<>(EncodeHintType.class);
            hints.put(EncodeHintType.CHARACTER_SET, StandardCharsets.ISO_8859_1);
            final BitMatrix result = writer.encode(new String(contents, StandardCharsets.ISO_8859_1),
                    BarcodeFormat.QR_CODE, QR_CODE_PIXEL_SIZE, QR_CODE_PIXEL_SIZE, hints);
            MatrixToImageWriter.writeToStream(result, "png", output);
        } catch (WriterException e) {
            throw new RuntimeException(e);
        }
    }

    private static class AccountQrHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final Account account = verifySession(exchange, false);
            if (account == null) {
                return;
            }
            exchange.getResponseHeaders().set("Content-Type", "image/png");
            exchange.sendResponseHeaders(200, 0);
            try (final OutputStream output = exchange.getResponseBody()) {
                final String contents = DOMAIN + " " +
                    account.userId + " " +
                    BaseEncoding.base64().encode(account.subscribeKey) + " " +
                    account.verifyInterval;
                writeQrCode(contents.getBytes(), output);
            }
        }
    }

    private static class ConfigurationHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final int verifyInterval;
            final int alertDelay;
            final String email;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                final JsonObject object = reader.readObject();
                verifyInterval = object.getInt("verifyInterval");
                alertDelay = object.getInt("alertDelay");
                email = object.getString("email").trim();
            } catch (final ClassCastException | JsonException | NullPointerException e) {
                logger.log(Level.INFO, "invalid request", e);
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final Account account = verifySession(exchange, false);
            if (account == null) {
                return;
            }

            if (verifyInterval < MIN_VERIFY_INTERVAL || verifyInterval > MAX_VERIFY_INTERVAL) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            if (alertDelay < MIN_ALERT_DELAY || alertDelay > MAX_ALERT_DELAY || alertDelay <= verifyInterval) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            if (!email.isEmpty()) {
                try {
                    new InternetAddress(email).validate();
                    for (final String emailBlacklistPattern : emailBlacklistPatterns) {
                        if (email.matches(emailBlacklistPattern)) {
                            exchange.sendResponseHeaders(400, -1);
                            return;
                        }
                    }
                } catch (final AddressException e) {
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }
            }

            final SQLiteConnection conn = open(AttestationProtocol.ATTESTATION_DATABASE, false);
            try {
                conn.exec("BEGIN IMMEDIATE TRANSACTION");

                final SQLiteStatement update = conn.prepare("UPDATE Accounts SET " +
                        "verifyInterval = ?, alertDelay = ? WHERE userId = ?");
                update.bind(1, verifyInterval);
                update.bind(2, alertDelay);
                update.bind(3, account.userId);
                update.step();
                update.dispose();

                final SQLiteStatement delete = conn.prepare("DELETE FROM EmailAddresses " +
                        "WHERE userId = ?");
                delete.bind(1, account.userId);
                delete.step();
                delete.dispose();

                if (!email.isEmpty()) {
                    final SQLiteStatement insert = conn.prepare("INSERT INTO EmailAddresses " +
                            "(userId, address) VALUES (?, ?)");
                    insert.bind(1, account.userId);
                    insert.bind(2, email);
                    insert.step();
                    insert.dispose();
                }

                conn.exec("COMMIT TRANSACTION");
            } finally {
                conn.dispose();
            }
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static class DeleteDeviceHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final String fingerprint;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                final JsonObject object = reader.readObject();
                fingerprint = object.getString("fingerprint");
            } catch (final ClassCastException | JsonException | NullPointerException e) {
                logger.log(Level.INFO, "invalid request", e);
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final Account account = verifySession(exchange, false);
            if (account == null) {
                return;
            }

            final SQLiteConnection conn = open(AttestationProtocol.ATTESTATION_DATABASE, false);
            try {
                final SQLiteStatement update = conn.prepare("UPDATE Devices SET " +
                        "deletionTime = ? WHERE userId = ? AND fingerprint = ?");
                update.bind(1, System.currentTimeMillis());
                update.bind(2, account.userId);
                update.bind(3, BaseEncoding.base16().decode(fingerprint));
                update.step();
                update.dispose();

                if (conn.getChanges() == 0) {
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }
            } finally {
                conn.dispose();
            }
            exchange.sendResponseHeaders(200, -1);
        }
    }

    private static String convertToPem(final byte[] derEncoded) {
        return "-----BEGIN CERTIFICATE-----\n" +
                new String(Base64.getMimeEncoder(64, "\n".getBytes()).encode(derEncoded)) +
                "\n-----END CERTIFICATE-----";
    }

    private static void writeDevicesJson(final HttpExchange exchange, final long userId)
            throws IOException, SQLiteException {
        final JsonArrayBuilder devices = Json.createArrayBuilder();
        final SQLiteConnection conn = open(AttestationProtocol.ATTESTATION_DATABASE, true);
        try {
            final SQLiteStatement select = conn.prepare("SELECT fingerprint, " +
                    "pinnedCertificates, attestKey, hex(pinnedVerifiedBootKey), " +
                    "(SELECT hex(verifiedBootHash) WHERE verifiedBootHash IS NOT NULL), " +
                    "pinnedOsVersion, pinnedOsPatchLevel, pinnedVendorPatchLevel, " +
                    "pinnedBootPatchLevel, pinnedAppVersion, pinnedSecurityLevel, " +
                    "userProfileSecure, enrolledBiometrics, accessibility, deviceAdmin, " +
                    "adbEnabled, addUsersWhenLocked, denyNewUsb, oemUnlockAllowed, " +
                    "systemUser, verifiedTimeFirst, verifiedTimeLast, " +
                    "(SELECT min(id) FROM Attestations WHERE Attestations.fingerprint = Devices.fingerprint), " +
                    "(SELECT max(id) FROM Attestations WHERE Attestations.fingerprint = Devices.fingerprint) " +
                    "FROM Devices WHERE userId is ? AND deletionTime IS NULL " +
                    "ORDER BY verifiedTimeFirst");
            select.bind(1, userId);
            while (select.step()) {
                final JsonObjectBuilder device = Json.createObjectBuilder();
                final byte[] fingerprint = select.columnBlob(0);
                device.add("fingerprint", BaseEncoding.base16().encode(fingerprint));
                try {
                    final Certificate[] pinnedCertificates = AttestationProtocol.decodeChain(AttestationProtocol.DEFLATE_DICTIONARY_2, select.columnBlob(1));
                    final JsonArrayBuilder certificates = Json.createArrayBuilder();
                    for (final Certificate pinnedCertificate : pinnedCertificates) {
                        certificates.add(convertToPem(pinnedCertificate.getEncoded()));
                    }
                    device.add("pinnedCertificates", certificates);
                } catch (final DataFormatException | GeneralSecurityException e) {
                    throw new IOException(e);
                }
                device.add("attestKey", select.columnInt(2));
                final String verifiedBootKey = select.columnString(3);
                device.add("verifiedBootKey", verifiedBootKey);
                DeviceInfo info;
                final int pinnedSecurityLevel = select.columnInt(10);
                if (pinnedSecurityLevel == KM_SECURITY_LEVEL_STRONG_BOX) {
                    info = fingerprintsStrongBoxCustomOS.get(verifiedBootKey);
                    if (info == null) {
                        info = fingerprintsStrongBoxStock.get(verifiedBootKey);
                        if (info == null) {
                            throw new RuntimeException("invalid fingerprint");
                        }
                    }
                } else {
                    info = fingerprintsCustomOS.get(verifiedBootKey);
                    if (info == null) {
                        info = fingerprintsStock.get(verifiedBootKey);
                        if (info == null) {
                            throw new RuntimeException("invalid fingerprint");
                        }
                    }
                }
                device.add("osName", info.osName);
                device.add("name", info.name);
                if (!select.columnNull(4)) {
                    device.add("verifiedBootHash", select.columnString(4));
                }
                device.add("pinnedOsVersion", select.columnInt(5));
                device.add("pinnedOsPatchLevel", select.columnInt(6));
                if (!select.columnNull(7)) {
                    device.add("pinnedVendorPatchLevel", select.columnInt(7));
                }
                if (!select.columnNull(8)) {
                    device.add("pinnedBootPatchLevel", select.columnInt(8));
                }
                device.add("pinnedAppVersion", select.columnInt(9));
                device.add("pinnedSecurityLevel", pinnedSecurityLevel);
                device.add("userProfileSecure", select.columnInt(11));
                device.add("enrolledBiometrics", select.columnInt(12));
                device.add("accessibility", select.columnInt(13));
                device.add("deviceAdmin", select.columnInt(14));
                device.add("adbEnabled", select.columnInt(15));
                device.add("addUsersWhenLocked", select.columnInt(16));
                device.add("denyNewUsb", select.columnInt(17));
                device.add("oemUnlockAllowed", select.columnInt(18));
                device.add("systemUser", select.columnInt(19));
                device.add("verifiedTimeFirst", select.columnLong(20));
                device.add("verifiedTimeLast", select.columnLong(21));
                device.add("minId", select.columnLong(22));
                device.add("maxId", select.columnLong(23));
                devices.add(device);
            }
            select.dispose();
        } finally {
            conn.dispose();
        }

        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, 0);
        try (final OutputStream output = exchange.getResponseBody();
                final JsonWriter writer = Json.createWriter(output)) {
            writer.write(devices.build());
        }
    }

    private static class DevicesHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final Account account = verifySession(exchange, false);
            if (account == null) {
                return;
            }
            writeDevicesJson(exchange, account.userId);
        }
    }

    private static class AttestationHistoryHandler extends PostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            String fingerprint;
            try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                final JsonObject object = reader.readObject();
                fingerprint = object.getString("fingerprint");
                long offsetId = object.getJsonNumber("offsetId").longValue();
                final Account account = verifySession(exchange, false);
                if (account == null) {
                    return;
                }
                writeAttestationHistoryJson(exchange, fingerprint, account, offsetId);
            } catch (final ClassCastException | JsonException | NullPointerException | NumberFormatException | GeneralSecurityException e) {
                logger.log(Level.INFO, "invalid request", e);
                exchange.sendResponseHeaders(400, -1);
            }
        }
    }

    private static void writeAttestationHistoryJson(final HttpExchange exchange, final String deviceFingerprint,
            final Account userAccount, final long offsetId)
            throws IOException, SQLiteException, GeneralSecurityException {
        final JsonArrayBuilder attestations = Json.createArrayBuilder();
        final byte[] fingerprint = BaseEncoding.base16().decode(deviceFingerprint);
        final SQLiteConnection conn = open(AttestationProtocol.ATTESTATION_DATABASE, true);
        try {
            final SQLiteStatement history = conn.prepare("SELECT id, time, strong, osVersion, osPatchLevel, " +
                "vendorPatchLevel, bootPatchLevel, Attestations.verifiedBootHash, appVersion, " +
                "Attestations.userProfileSecure, Attestations.enrolledBiometrics, " +
                "Attestations.accessibility, Attestations.deviceAdmin, Attestations.adbEnabled, " +
                "Attestations.addUsersWhenLocked, Attestations.denyNewUsb, " +
                "Attestations.oemUnlockAllowed, Attestations.systemUser " +
                "FROM Attestations INNER JOIN Devices ON " +
                "Attestations.fingerprint = Devices.fingerprint " +
                "WHERE Devices.fingerprint = ? AND userid = ? " +
                "AND Attestations.id <= ? ORDER BY id DESC LIMIT " + HISTORY_PER_PAGE);
            history.bind(1, fingerprint);
            history.bind(2, userAccount.userId);
            history.bind(3, offsetId);
            int rowCount = 0;
            while (history.step()) {
                final JsonObjectBuilder attestation = Json.createObjectBuilder();
                attestation.add("id", history.columnLong(0));
                attestation.add("time", history.columnLong(1));
                attestation.add("strong", history.columnInt(2) != 0);
                attestation.add("osVersion", history.columnInt(3));
                attestation.add("osPatchLevel", history.columnInt(4));
                if (!history.columnNull(5)) {
                    attestation.add("vendorPatchLevel", history.columnInt(5));
                }
                if (!history.columnNull(6)) {
                    attestation.add("bootPatchLevel", history.columnInt(6));
                }
                if (!history.columnNull(7)) {
                    attestation.add("verifiedBootHash", BaseEncoding.base16().encode(history.columnBlob(7)));
                }
                attestation.add("appVersion", history.columnInt(8));
                attestation.add("userProfileSecure", history.columnInt(9));
                attestation.add("enrolledBiometrics", history.columnInt(10));
                attestation.add("accessibility", history.columnInt(11));
                attestation.add("deviceAdmin", history.columnInt(12));
                attestation.add("adbEnabled", history.columnInt(13));
                attestation.add("addUsersWhenLocked", history.columnInt(14));
                attestation.add("denyNewUsb", history.columnInt(15));
                attestation.add("oemUnlockAllowed", history.columnInt(16));
                attestation.add("systemUser", history.columnInt(17));
                attestations.add(attestation);
                rowCount += 1;
            }
            history.dispose();
            if (rowCount == 0) {
                throw new GeneralSecurityException("found no attestation history for userId: " + userAccount.userId +
                        ", fingerprint: " + deviceFingerprint);
            }
        } finally {
            conn.dispose();
        }
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, 0);
        try (final OutputStream output = exchange.getResponseBody();
                final JsonWriter writer = Json.createWriter(output)) {
            writer.write(attestations.build());
        }
    }

    private static class ChallengeHandler extends AppPostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException {
            final byte[] challenge = AttestationProtocol.getChallenge();
            pendingChallenges.put(ByteBuffer.wrap(challenge), true);

            final byte[] challengeMessage =
                    Bytes.concat(new byte[]{AttestationProtocol.PROTOCOL_VERSION},
                            new byte[AttestationProtocol.CHALLENGE_LENGTH], challenge);

            exchange.sendResponseHeaders(200, challengeMessage.length);
            try (final OutputStream output = exchange.getResponseBody()) {
                output.write(challengeMessage);
            }
        }
    }

    private static class VerifyHandler extends AppPostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            String authorization = null;
            try {
                authorization = getRequestHeaderValue(exchange, "Authorization");
            } catch (final GeneralSecurityException e) {}
            if (authorization == null) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }
            final String[] tokens = authorization.split(" ");
            if (!tokens[0].equals("Auditor") || tokens.length < 2 || tokens.length > 3) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }
            final long userId = Long.parseLong(tokens[1]);
            final String subscribeKey = tokens.length == 3 ? tokens[2] : null;

            final byte[] currentSubscribeKey;
            final int verifyInterval;
            final SQLiteConnection conn = open(AttestationProtocol.ATTESTATION_DATABASE, true);
            try {
                final SQLiteStatement select = conn.prepare("SELECT subscribeKey, verifyInterval " +
                        "FROM Accounts WHERE userId = ?");
                select.bind(1, userId);
                if (!select.step()) {
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }
                currentSubscribeKey = select.columnBlob(0);
                verifyInterval = select.columnInt(1);
                select.dispose();
            } finally {
                conn.dispose();
            }

            if (subscribeKey != null && !MessageDigest.isEqual(BaseEncoding.base64().decode(subscribeKey),
                    currentSubscribeKey)) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final InputStream input = exchange.getRequestBody();

            final ByteArrayOutputStream attestation = new ByteArrayOutputStream();
            final byte[] buffer = new byte[4096];
            for (int read = input.read(buffer); read != -1; read = input.read(buffer)) {
                attestation.write(buffer, 0, read);

                if (attestation.size() > AttestationProtocol.MAX_MESSAGE_SIZE) {
                    exchange.sendResponseHeaders(413, -1);
                    return;
                }
            }

            final byte[] attestationResult = attestation.toByteArray();

            try {
                AttestationProtocol.verifySerialized(attestationResult, pendingChallenges, userId, subscribeKey == null);
            } catch (final BufferUnderflowException | NegativeArraySizeException | DataFormatException | GeneralSecurityException | IOException e) {
                logger.log(Level.INFO, "invalid request", e);
                final byte[] response = "Error\n".getBytes();
                exchange.sendResponseHeaders(400, response.length);
                try (final OutputStream output = exchange.getResponseBody()) {
                    output.write(response);
                }
                return;
            }

            final byte[] result = (BaseEncoding.base64().encode(currentSubscribeKey) + " " +
                    verifyInterval).getBytes();
            exchange.sendResponseHeaders(200, result.length);
            try (final OutputStream output = exchange.getResponseBody()) {
                output.write(result);
            }
        }
    }

    private static class SubmitHandler extends AppPostHandler {
        @Override
        public void handlePost(final HttpExchange exchange) throws IOException, SQLiteException {
            final InputStream input = exchange.getRequestBody();

            final ByteArrayOutputStream sample = new ByteArrayOutputStream();
            final byte[] buffer = new byte[4096];
            for (int read = input.read(buffer); read != -1; read = input.read(buffer)) {
                if (sample.size() + read > MAX_SAMPLE_SIZE) {
                    logger.warning("sample submission beyond size limit");
                    exchange.sendResponseHeaders(413, -1);
                    return;
                }

                sample.write(buffer, 0, read);
            }

            if (sample.size() == 0) {
                logger.warning("empty sample submission");
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            final SQLiteConnection conn = open(SAMPLES_DATABASE, false);
            try {
                final SQLiteStatement insert = conn.prepare("INSERT INTO Samples " +
                       "(sample, time) VALUES (?, ?)");
                insert.bind(1, sample.toByteArray());
                insert.bind(2, System.currentTimeMillis());
                insert.step();
                insert.dispose();
            } finally {
                conn.dispose();
            }

            exchange.sendResponseHeaders(200, -1);
        }
    }
}
