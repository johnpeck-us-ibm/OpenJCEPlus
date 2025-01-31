/*
 * Copyright IBM Corp. 2025
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.security.internal.spec;

import java.security.spec.KeySpec;

/**
 * This is here for easier compatability with OpenJDK 21 and above.
 * 
 * This is a KeySpec that is used to specify a key by its byte array implementation. Since the
 * new PQC algs the bytes are defined as byte arrays.
 */
public class RawKeySpec implements KeySpec {
    private final byte[] keyBytes;
    /**
     * @param key contains the key as a byte array
     */
    public RawKeySpec(byte[] key) {
        keyBytes = key.clone();
    }

    /**
     * @return a copy of the key bits
     */
    public byte[] getKeyArr() {
        return keyBytes.clone();
    }
}