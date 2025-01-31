/*
 * Copyright IBM Corp. 2024, 2025
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

@SuppressWarnings("deprecation")
public class PQCAlgorithmId extends sun.security.x509.AlgorithmId {

    public static final AlgorithmId ML_KEM_512_oid = new AlgorithmId(getOID("ML-KEM-512"));
    public static final AlgorithmId ML_KEM_768_oid = new AlgorithmId(getOID("ML-KEM-768"));
    public static final AlgorithmId ML_KEM_1024_oid = new AlgorithmId(getOID("ML-KEM-1024"));

    public static final AlgorithmId ML_DSA_44_oid = new AlgorithmId(getOID("ML-DSA-44"));
    public static final AlgorithmId ML_DSA_65_oid = new AlgorithmId(getOID("ML-DSA-65"));
    public static final AlgorithmId ML_DSA_87_oid = new AlgorithmId(getOID("ML-DSA-87"));

    public static final AlgorithmId SLH_DSA_SHA2_128s_oid = new AlgorithmId(getOID("SLH-DSA-SHA2-128s"));
    public static final AlgorithmId SLH_DSA_SHAKE_128s_oid = new AlgorithmId(getOID("SLH-DSA-SHAKE-128s"));
    public static final AlgorithmId SLH_DSA_SHA2_128f_oid = new AlgorithmId(getOID("SLH-DSA-SHA2-128f"));
    public static final AlgorithmId SLH_DSA_SHAKE_128f_oid = new AlgorithmId(getOID("SLH-DSA-SHAKE-128f"));
    public static final AlgorithmId SLH_DSA_SHA2_192s_oid = new AlgorithmId(getOID("SLH-DSA-SHA2-192s"));
    public static final AlgorithmId SLH_DSA_SHAKE_192s_oid = new AlgorithmId(getOID("SLH-DSA-SHAKE-192s"));
    public static final AlgorithmId SLH_DSA_SHA2_192f_oid = new AlgorithmId(getOID("SLH-DSA-SHA2-192f"));
    public static final AlgorithmId SLH_DSA_SHAKE_192f_oid = new AlgorithmId(getOID("SLH-DSA-SHAKE-192f"));
    public static final AlgorithmId SLH_DSA_SHA2_256s_oid = new AlgorithmId(getOID("SLH-DSA-SHA2-256s"));
    public static final AlgorithmId SLH_DSA_SHAKE_256s_oid = new AlgorithmId(getOID("SLH-DSA-SHAKE-256s"));
    public static final AlgorithmId SLH_DSA_SHA2_256f_oid = new AlgorithmId(getOID("SLH-DSA-SHA2-256f"));
    public static final AlgorithmId SLH_DSA_SHAKE_256f_oid = new AlgorithmId(getOID("SLH-DSA-SHAKE-256f"));

    public static final ObjectIdentifier getOID(String oidString) {
        try {
            ObjectIdentifier oid = ObjectIdentifier.of(PQCKnownOIDs.findMatch(oidString).value());
            return oid;
        } catch (Exception ex) {
            return null;
        }
    }

}
