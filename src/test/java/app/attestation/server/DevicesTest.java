package app.attestation.server;

import app.attestation.server.sqlite.SQLiteConnection;
import com.google.common.io.BaseEncoding;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static app.attestation.server.TestDatabases.account;
import static app.attestation.server.TestDatabases.attestation;
import static app.attestation.server.TestDatabases.bytes;
import static app.attestation.server.TestDatabases.device;
import static app.attestation.server.TestDatabases.insert;
import static app.attestation.server.TestDatabases.queryStrings;
import static app.attestation.server.TestDatabases.with;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DevicesTest {
    private static final String PIXEL_6_GRAPHENEOS = "F0A890375D1405E62EBFD87E8D3F475F948EF031BBF9DDD516D5F600A23677E8";
    private static final String PIXEL_6_STOCK = "0F6E75C80183B5DEC074B0054D4271E99389EBE4B136B0819DE1F150BA0FF9D7";
    private static final String PIXEL_TABLET_GRAPHENEOS = "94DF136E6C6AA08DC26580AF46F36419B5F9BAF46039DB076F5295B91AAFF230";
    private static final String UNKNOWN = "Unknown (legacy device)";

    private static final byte[] FINGERPRINT = bytes(0xa);

    @TempDir
    Path dir;

    private SQLiteConnection conn;
    private long alice;
    private long bob;

    @BeforeEach
    void open() throws Exception {
        conn = TestDatabases.attestation(dir);
        alice = insert(conn, "Accounts", account("Alice", 1_000));
        bob = insert(conn, "Accounts", account("Bob", 1_000));
    }

    @AfterEach
    void close() {
        conn.close();
    }

    private static String hex(final byte[] bytes) {
        return BaseEncoding.base16().encode(bytes);
    }

    private static Map<String, Object> fullDevice(final long userId) throws Exception {
        return with(device(FINGERPRINT, userId, 3_000), "verifiedTimeLast", 3_500L,
                "pinnedVerifiedBootKey", BaseEncoding.base16().decode(PIXEL_6_GRAPHENEOS),
                "pinnedBootPatchLevel", 20_251_006, "pinnedAppVariant", 2,
                "userProfileSecure", 1, "enrolledBiometrics", 0, "accessibility", 1, "deviceAdmin", 2,
                "adbEnabled", 0, "addUsersWhenLocked", 1, "oemUnlockAllowed", 0, "systemUser", 1,
                "autoRebootSeconds", 3_600, "portSecurityMode", 3, "userCount", 2, "oemUnlockAllowed2", 1);
    }

    private static Map<String, Object> fullAttestation(final long time) {
        return with(attestation(FINGERPRINT, time), "strong", 0, "osVersion", 160_001, "osPatchLevel", 202_511,
                "vendorPatchLevel", 20_251_101, "bootPatchLevel", 20_251_102, "appVersion", 91,
                "userProfileSecure", 1, "enrolledBiometrics", 0, "accessibility", 1, "deviceAdmin", 2,
                "adbEnabled", 0, "addUsersWhenLocked", 1, "oemUnlockAllowed", 0, "systemUser", 1,
                "autoRebootSeconds", 0, "portSecurityMode", 4, "userCount", 3, "oemUnlockAllowed2", 1);
    }

    private static JsonArrayBuilder pem(final Certificate[] chain) throws Exception {
        final JsonArrayBuilder certificates = Json.createArrayBuilder();
        for (final Certificate certificate : chain) {
            certificates.add("-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(certificate.getEncoded())
                    + "\n-----END CERTIFICATE-----");
        }
        return certificates;
    }

    private static JsonObject find(final JsonArray devices, final byte[] fingerprint) {
        return devices.stream().map(JsonObject.class::cast)
                .filter(device -> device.getString("fingerprint").equals(hex(fingerprint)))
                .findFirst().orElseThrow();
    }

    @Test
    void devicesJson() throws Exception {
        insert(conn, "Devices", fullDevice(alice));
        final long minId = insert(conn, "Attestations", attestation(FINGERPRINT, 3_000));
        insert(conn, "Devices", device(bytes(0xf), bob, 1_000));
        insert(conn, "Attestations", attestation(bytes(0xf), 3_100));
        final long maxId = insert(conn, "Attestations", attestation(FINGERPRINT, 3_500));

        final JsonObject expected = Json.createObjectBuilder()
                .add("fingerprint", hex(FINGERPRINT))
                .add("pinnedCertificates", pem(TestDatabases.chain()))
                .add("attestKey", 1)
                .add("verifiedBootKey", PIXEL_6_GRAPHENEOS)
                .add("osName", "GrapheneOS")
                .add("name", "Google Pixel 6")
                .add("verifiedBootHash", hex(bytes(0x6b)))
                .add("pinnedOsVersion", 160_000)
                .add("pinnedOsPatchLevel", 202_510)
                .add("pinnedVendorPatchLevel", 20_251_005)
                .add("pinnedBootPatchLevel", 20_251_006)
                .add("pinnedAppVersion", 90)
                .add("pinnedAppVariant", 2)
                .add("pinnedSecurityLevel", 1)
                .add("userProfileSecure", 1)
                .add("enrolledBiometrics", 0)
                .add("accessibility", 1)
                .add("deviceAdmin", 2)
                .add("adbEnabled", 0)
                .add("addUsersWhenLocked", 1)
                .add("oemUnlockAllowed", 0)
                .add("systemUser", 1)
                .add("autoRebootSeconds", 3_600)
                .add("portSecurityMode", 3)
                .add("userCount", 2)
                .add("oemUnlockAllowed2", 1)
                .add("verifiedTimeFirst", 3_000)
                .add("verifiedTimeLast", 3_500)
                .add("minId", minId)
                .add("maxId", maxId)
                .add("hasPogoPins", 0)
                .build();
        assertEquals(Json.createArrayBuilder().add(expected).build(), AttestationServer.getDevicesJson(conn, alice));
    }

    @Test
    void devicesJsonVariants() throws Exception {
        final Map<String, Object> base = fullDevice(alice);
        insert(conn, "Devices", with(base, "fingerprint", bytes(1), "verifiedTimeFirst", 4_000L,
                "pinnedVerifiedBootKey", bytes(0x5a), "verifiedBootHash", null, "pinnedVendorPatchLevel", null,
                "pinnedBootPatchLevel", null, "autoRebootSeconds", null, "portSecurityMode", null,
                "userCount", null, "oemUnlockAllowed2", null));
        insert(conn, "Devices", with(base, "fingerprint", bytes(2), "verifiedTimeFirst", 2_000L,
                "pinnedVerifiedBootKey", BaseEncoding.base16().decode(PIXEL_TABLET_GRAPHENEOS),
                "autoRebootSeconds", -2, "portSecurityMode", -2, "userCount", -2, "oemUnlockAllowed2", -2));
        insert(conn, "Devices", with(base, "fingerprint", bytes(3), "verifiedTimeFirst", 3_000L,
                "pinnedVerifiedBootKey", BaseEncoding.base16().decode(PIXEL_6_STOCK), "pinnedSecurityLevel", 2));
        insert(conn, "Devices", with(base, "fingerprint", bytes(4), "verifiedTimeFirst", 1_000L,
                "deletionTime", 5_000L));
        insert(conn, "Devices", with(base, "fingerprint", bytes(5), "verifiedTimeFirst", 1_500L, "userId", bob));

        final JsonArray devices = AttestationServer.getDevicesJson(conn, alice);

        assertEquals(List.of(hex(bytes(2)), hex(bytes(3)), hex(bytes(1))),
                devices.stream().map(device -> device.asJsonObject().getString("fingerprint")).toList());

        final JsonObject legacy = find(devices, bytes(1));
        assertEquals(UNKNOWN, legacy.getString("osName"));
        assertEquals(UNKNOWN, legacy.getString("name"));
        assertEquals(hex(bytes(0x5a)), legacy.getString("verifiedBootKey"));
        for (final String key : List.of("verifiedBootHash", "pinnedVendorPatchLevel", "pinnedBootPatchLevel",
                "autoRebootSeconds", "portSecurityMode", "userCount", "oemUnlockAllowed2")) {
            assertFalse(legacy.containsKey(key), key);
        }
        assertEquals(0, legacy.getJsonNumber("minId").longValue());
        assertEquals(0, legacy.getJsonNumber("maxId").longValue());
        assertEquals(0, legacy.getInt("hasPogoPins"));

        final JsonObject tablet = find(devices, bytes(2));
        assertEquals("GrapheneOS", tablet.getString("osName"));
        assertEquals("Google Pixel Tablet", tablet.getString("name"));
        assertEquals(1, tablet.getInt("hasPogoPins"));
        for (final String key : List.of("autoRebootSeconds", "portSecurityMode", "userCount", "oemUnlockAllowed2")) {
            assertEquals(-2, tablet.getInt(key), key);
        }

        final JsonObject strongBox = find(devices, bytes(3));
        assertEquals("Stock", strongBox.getString("osName"));
        assertEquals("Google Pixel 6", strongBox.getString("name"));
        assertEquals(2, strongBox.getInt("pinnedSecurityLevel"));

        assertEquals(List.of(), AttestationServer.getDevicesJson(conn, bob + 1));
    }

    @Test
    void attestationHistoryJson() throws Exception {
        insert(conn, "Devices", fullDevice(alice));
        insert(conn, "Devices", device(bytes(0xb), alice, 1_000));
        final long id = insert(conn, "Attestations", fullAttestation(10_000));
        insert(conn, "Attestations", with(fullAttestation(11_000), "vendorPatchLevel", null,
                "bootPatchLevel", null, "verifiedBootHash", null, "autoRebootSeconds", null,
                "portSecurityMode", null, "userCount", null, "oemUnlockAllowed2", null));
        insert(conn, "Attestations", with(fullAttestation(12_000), "strong", 1, "autoRebootSeconds", -2,
                "portSecurityMode", -2, "userCount", -2, "oemUnlockAllowed2", -2));
        insert(conn, "Attestations", attestation(bytes(0xb), 13_000));

        final JsonArray history = AttestationServer.getAttestationHistoryJson(conn, hex(FINGERPRINT), alice,
                Long.MAX_VALUE);

        assertEquals(3, history.size());
        final JsonObject expected = Json.createObjectBuilder()
                .add("id", id)
                .add("time", 10_000)
                .add("strong", false)
                .add("osVersion", 160_001)
                .add("osPatchLevel", 202_511)
                .add("vendorPatchLevel", 20_251_101)
                .add("bootPatchLevel", 20_251_102)
                .add("verifiedBootHash", hex(bytes(0x6b)))
                .add("appVersion", 91)
                .add("userProfileSecure", 1)
                .add("enrolledBiometrics", 0)
                .add("accessibility", 1)
                .add("deviceAdmin", 2)
                .add("adbEnabled", 0)
                .add("addUsersWhenLocked", 1)
                .add("oemUnlockAllowed", 0)
                .add("systemUser", 1)
                .add("autoRebootSeconds", 0)
                .add("portSecurityMode", 4)
                .add("userCount", 3)
                .add("oemUnlockAllowed2", 1)
                .build();
        assertEquals(expected, history.getJsonObject(2));

        final JsonObject withNulls = history.getJsonObject(1);
        assertEquals(id + 1, withNulls.getJsonNumber("id").longValue());
        for (final String key : List.of("vendorPatchLevel", "bootPatchLevel", "verifiedBootHash",
                "autoRebootSeconds", "portSecurityMode", "userCount", "oemUnlockAllowed2")) {
            assertFalse(withNulls.containsKey(key), key);
        }

        final JsonObject unknown = history.getJsonObject(0);
        assertEquals(id + 2, unknown.getJsonNumber("id").longValue());
        assertTrue(unknown.getBoolean("strong"));
        for (final String key : List.of("autoRebootSeconds", "portSecurityMode", "userCount", "oemUnlockAllowed2")) {
            assertEquals(-2, unknown.getInt(key), key);
        }
    }

    private static List<Long> ids(final JsonArray history) {
        return history.stream().map(entry -> entry.asJsonObject().getJsonNumber("id").longValue()).toList();
    }

    @Test
    void attestationHistoryPaging() throws Exception {
        insert(conn, "Devices", fullDevice(alice));
        insert(conn, "Devices", device(bytes(0xb), alice, 1_000));
        final List<Long> ids = new ArrayList<>();
        for (int i = 0; i < 25; i++) {
            ids.add(insert(conn, "Attestations", attestation(FINGERPRINT, 10_000 + i)));
            if (i % 5 == 0) {
                insert(conn, "Attestations", attestation(bytes(0xb), 10_000 + i));
            }
        }
        final List<Long> descending = ids.reversed();

        final JsonArray first = AttestationServer.getAttestationHistoryJson(conn, hex(FINGERPRINT), alice,
                Long.MAX_VALUE);
        assertEquals(descending.subList(0, 20), ids(first));

        final long offsetId = ids(first).getLast() - 1;
        final JsonArray second = AttestationServer.getAttestationHistoryJson(conn, hex(FINGERPRINT), alice,
                offsetId);
        assertEquals(descending.subList(20, 25), ids(second));

        assertEquals(descending.subList(5, 25), ids(AttestationServer.getAttestationHistoryJson(conn,
                hex(FINGERPRINT), alice, descending.get(5))));
        assertThrows(GeneralSecurityException.class, () -> AttestationServer.getAttestationHistoryJson(conn,
                hex(FINGERPRINT), alice, ids.getFirst() - 1));
    }

    @Test
    void attestationHistoryRequiresOwnDevice() throws Exception {
        insert(conn, "Devices", fullDevice(alice));
        insert(conn, "Attestations", attestation(FINGERPRINT, 10_000));

        assertThrows(GeneralSecurityException.class, () -> AttestationServer.getAttestationHistoryJson(conn,
                hex(FINGERPRINT), bob, Long.MAX_VALUE));
        assertThrows(GeneralSecurityException.class, () -> AttestationServer.getAttestationHistoryJson(conn,
                hex(bytes(0xb)), alice, Long.MAX_VALUE));
        assertEquals(1, AttestationServer.getAttestationHistoryJson(conn, hex(FINGERPRINT), alice,
                Long.MAX_VALUE).size());
    }

    @Test
    void deleteDevice() throws Exception {
        insert(conn, "Devices", fullDevice(alice));
        insert(conn, "Devices", device(bytes(0xb), alice, 1_000));
        insert(conn, "Devices", device(bytes(0xc), bob, 1_000));

        assertFalse(AttestationServer.deleteDevice(conn, alice, bytes(0xc)));
        assertFalse(AttestationServer.deleteDevice(conn, alice, bytes(0xd)));
        assertFalse(AttestationServer.deleteDevice(conn, bob, FINGERPRINT));
        assertEquals(List.of(), queryStrings(conn, "SELECT fingerprint FROM Devices WHERE deletionTime IS NOT NULL"));

        final long before = System.currentTimeMillis();
        assertTrue(AttestationServer.deleteDevice(conn, alice, FINGERPRINT));
        final long after = System.currentTimeMillis();

        final long deletionTime = Long.parseLong(queryStrings(conn,
                "SELECT deletionTime FROM Devices WHERE deletionTime IS NOT NULL").getFirst());
        assertTrue(deletionTime >= before && deletionTime <= after);
        assertEquals(List.of(hex(bytes(0xb))), AttestationServer.getDevicesJson(conn, alice).stream()
                .map(device -> device.asJsonObject().getString("fingerprint")).toList());
        assertEquals(1, AttestationServer.getDevicesJson(conn, bob).size());
    }
}
