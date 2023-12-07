/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.memstress;

import ibm.jceplus.junit.base.memstress.BaseTestMemStressDSAKeyFactory;
import ibm.jceplus.junit.openjceplus.Utils;
import junit.framework.Test;
import junit.framework.TestSuite;

public class TestMemStressDSAKeyFactory extends BaseTestMemStressDSAKeyFactory {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestMemStressDSAKeyFactory() {

        super(Utils.TEST_SUITE_PROVIDER_NAME, 2048);
    }

    //--------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        junit.textui.TestRunner.run(suite());
    }

    //--------------------------------------------------------------------------
    //
    //
    public static Test suite() {
        TestSuite suite = new TestSuite(TestMemStressDSAKeyFactory.class);
        return suite;
    }
}

