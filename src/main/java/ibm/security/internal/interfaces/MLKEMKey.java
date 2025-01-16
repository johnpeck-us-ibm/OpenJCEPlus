/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.security.internal.interfaces;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

public interface MLKEMKey {

    /**
     * Returns the parameters associated with this key.
     * The parameters are optional and may be either
     * explicitly specified or implicitly created during
     * key pair generation.
     *
     * @implSpec
     *           The default implementation returns {@code null}.
     *
     * @return the associated parameters, may be null
     * @since 21
     */
    default AlgorithmParameterSpec getParams() {
        return null;
    }
}
