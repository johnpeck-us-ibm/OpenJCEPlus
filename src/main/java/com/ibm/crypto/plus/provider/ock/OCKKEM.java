/*
 * Copyright IBM Corp. 2025
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider.ock;

public final class OCKKEM implements Cloneable {
    private static final int OCK_KEY_SIZE = 32; // Size in bytes of protected key
    /*
     * ===========================================================================
     * Key Encapsulation interface to OCK.
     */

    public static void OCKKEM_encapsulate(OCKContext ockContext, byte[] publicKey, byte[] encapsulatedKey,
            byte[] keyMaterial) throws OCKException {
        NativeInterface.KEM_encapsulate(ockContext.getId(), publicKey, encapsulatedKey, keyMaterial);
    }

    public static byte[] OCKKEM_decapsulate(OCKContext ockContext, byte[] privateKey, byte[] encapsulatedKey)
            throws OCKException {
        byte[] keyMaterial = new byte[OCK_KEY_SIZE];
        NativeInterface.KEM_decapsulate(ockContext.getId(), privateKey, encapsulatedKey, keyMaterial);

        return keyMaterial.clone();
    }

}
