/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package app.attestation.server.attestation;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;

import java.security.cert.CertificateParsingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class AttestationApplicationId implements java.lang.Comparable<AttestationApplicationId> {
    private static final int PACKAGE_INFOS_INDEX = 0;
    private static final int SIGNATURE_DIGESTS_INDEX = 1;

    private final List<AttestationPackageInfo> packageInfos;
    private final List<byte[]> signatureDigests;

    public AttestationApplicationId(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence)) {
            throw new CertificateParsingException(
                    "Expected sequence for AttestationApplicationId, found "
                            + asn1Encodable.getClass().getName());
        }

        ASN1Sequence sequence = (ASN1Sequence) asn1Encodable;
        packageInfos = parseAttestationPackageInfos(sequence.getObjectAt(PACKAGE_INFOS_INDEX));
        // The infos must be sorted, the implementation of Comparable relies on it.
        packageInfos.sort(null);
        signatureDigests = parseSignatures(sequence.getObjectAt(SIGNATURE_DIGESTS_INDEX));
        // The digests must be sorted. the implementation of Comparable relies on it
        signatureDigests.sort(new ByteArrayComparator());
    }

    public List<AttestationPackageInfo> getAttestationPackageInfos() {
        return packageInfos;
    }

    public List<byte[]> getSignatureDigests() {
        return signatureDigests;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("AttestationApplicationId:");
        int noOfInfos = packageInfos.size();
        int i = 1;
        for (AttestationPackageInfo info : packageInfos) {
            sb.append("\n### Package info " + i + "/" + noOfInfos + " ###\n");
            sb.append(info);
        }
        i = 1;
        int noOfSigs = signatureDigests.size();
        for (byte[] sig : signatureDigests) {
            sb.append("\nSignature digest " + i++ + "/" + noOfSigs + ":");
            for (byte b : sig) {
                sb.append(String.format(" %02X", b));
            }
        }
        return sb.toString();
    }

    @Override
    public int compareTo(AttestationApplicationId other) {
        int res = Integer.compare(packageInfos.size(), other.packageInfos.size());
        if (res != 0) return res;
        for (int i = 0; i < packageInfos.size(); ++i) {
            res = packageInfos.get(i).compareTo(other.packageInfos.get(i));
            if (res != 0) return res;
        }
        res = Integer.compare(signatureDigests.size(), other.signatureDigests.size());
        if (res != 0) return res;
        ByteArrayComparator cmp = new ByteArrayComparator();
        for (int i = 0; i < signatureDigests.size(); ++i) {
            res = cmp.compare(signatureDigests.get(i), other.signatureDigests.get(i));
            if (res != 0) return res;
        }
        return res;
    }

    @Override
    public boolean equals(Object o) {
        return (o instanceof AttestationApplicationId)
                && (0 == compareTo((AttestationApplicationId) o));
    }

    private List<AttestationPackageInfo> parseAttestationPackageInfos(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Set)) {
            throw new CertificateParsingException(
                    "Expected set for AttestationApplicationsInfos, found "
                            + asn1Encodable.getClass().getName());
        }

        ASN1Set set = (ASN1Set) asn1Encodable;
        List<AttestationPackageInfo> result = new ArrayList<>();
        for (ASN1Encodable e : set) {
            result.add(new AttestationPackageInfo(e));
        }
        return result;
    }

    private List<byte[]> parseSignatures(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Set)) {
            throw new CertificateParsingException("Expected set for Signature digests, found "
                    + asn1Encodable.getClass().getName());
        }

        ASN1Set set = (ASN1Set) asn1Encodable;
        List<byte[]> result = new ArrayList<>();

        for (ASN1Encodable e : set) {
            result.add(Asn1Utils.getByteArrayFromAsn1(e));
        }
        return result;
    }

    private static class ByteArrayComparator implements java.util.Comparator<byte[]> {
        @Override
        public int compare(byte[] a, byte[] b) {
            int res = Integer.compare(a.length, b.length);
            if (res != 0) return res;
            for (int i = 0; i < a.length; ++i) {
                res = Byte.compare(a[i], b[i]);
                if (res != 0) return res;
            }
            return res;
        }
    }
}
