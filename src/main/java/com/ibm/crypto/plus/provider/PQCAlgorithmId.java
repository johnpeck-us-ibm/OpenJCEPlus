package com.ibm.crypto.plus.provider;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

public class PQCAlgorithmId extends sun.security.x509.AlgorithmId {
    public PQCAlgorithmId() {}

    public static final ObjectIdentifier ML_KEM_512_oid =
            ObjectIdentifier.of(PQCKnownOIDs.ML_KEM_512);
    public static final ObjectIdentifier ML_KEM_768_oid =
            ObjectIdentifier.of(PQCKnownOIDs.ML_KEM_768);
    public static final ObjectIdentifier ML_KEM_1024_oid =
            ObjectIdentifier.of(PQCKnownOIDs.ML_KEM_1024);

    public static final ObjectIdentifier ML_DSA_44_oid =
            ObjectIdentifier.of(PQCKnownOIDs.ML_DSA_44);
    public static final ObjectIdentifier ML_DSA_65_oid =
            ObjectIdentifier.of(PQCKnownOIDs.ML_DSA_65);
    public static final ObjectIdentifier ML_DSA_87_oid =
            ObjectIdentifier.of(PQCKnownOIDs.ML_DSA_87);

    public static final ObjectIdentifier SLH_DSA_SHA2_128s_oid =
            ObjectIdentifier.of(PQCKnownOIDs.SLH_DSA_SHA2_128s);
    public static final ObjectIdentifier SLH_DSA_SHAKE_128s_oid =
            ObjectIdentifier.of(PQCKnownOIDs.SLH_DSA_SHAKE_128s);
    public static final ObjectIdentifier SLH_DSA_SHA2_128f_oid =
            ObjectIdentifier.of(PQCKnownOIDs.SLH_DSA_SHA2_128f);
    public static final ObjectIdentifier SLH_DSA_SHAKE_128f_oid =
            ObjectIdentifier.of(PQCKnownOIDs.SLH_DSA_SHAKE_128f);
    public static final ObjectIdentifier SLH_DSA_SHA2_192s_oid =
            ObjectIdentifier.of(PQCKnownOIDs.SLH_DSA_SHA2_192s);
    public static final ObjectIdentifier SLH_DSA_SHAKE_192s_oid =
            ObjectIdentifier.of(PQCKnownOIDs.SLH_DSA_SHAKE_192s);
    public static final ObjectIdentifier SLH_DSA_SHA2_192f_oid =
            ObjectIdentifier.of(PQCKnownOIDs.SLH_DSA_SHA2_192f);
    public static final ObjectIdentifier SLH_DSA_SHAKE_192f_oid =
            ObjectIdentifier.of(PQCKnownOIDs.SLH_DSA_SHAKE_192f);
    public static final ObjectIdentifier SLH_DSA_SHA2_256s_oid =
            ObjectIdentifier.of(PQCKnownOIDs.SLH_DSA_SHA2_256s);
    public static final ObjectIdentifier SLH_DSA_SHAKE_256s_oid =
            ObjectIdentifier.of(PQCKnownOIDs.SLH_DSA_SHAKE_256s);
    public static final ObjectIdentifier SLH_DSA_SHA2_256f_oid =
            ObjectIdentifier.of(PQCKnownOIDs.SLH_DSA_SHA2_256f);
    public static final ObjectIdentifier SLH_DSA_SHAKE_256f_oid =
            ObjectIdentifier.of(PQCKnownOIDs.SLH_DSA_SHAKE_256f);

}
