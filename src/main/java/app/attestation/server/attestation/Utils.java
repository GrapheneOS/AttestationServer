package app.attestation.server.attestation;

import org.bouncycastle.asn1.ASN1Boolean;

import java.math.BigInteger;

/**
 * Helper class for miscellaneous wrappers, compatibility layer and hardening,
 * such as more strict ASN1Parsing used in the old CTS library.
 */
class Utils {

    // https://github.com/GrapheneOS/Auditor/blob/40ee574f71786a6a97498f925615797e9e86ac4a/app/src/main/java/app/attestation/auditor/attestation/Asn1Utils.java#L166
    // strict parsing of bigInt to parse only non-negative integer
    static int intValueFromBigIntegerStrict(BigInteger bigInt) {
        if (bigInt.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0
                || bigInt.compareTo(BigInteger.ZERO) < 0) {
            throw new IllegalArgumentException("INTEGER out of bounds");
        }
        return bigInt.intValue();
    }

    // strict parsing used in the old CTS library for boolean values
    static boolean getBooleanFromAsn1Strict(ASN1Boolean booleanValue) {
        if (booleanValue.equals(ASN1Boolean.TRUE)) {
            return true;
        } else if (booleanValue.equals((ASN1Boolean.FALSE))) {
            return false;
        }
        throw new IllegalArgumentException("DER-encoded boolean values must contain either 0x00 or 0xFF");
    }

    private Utils() {}
}
