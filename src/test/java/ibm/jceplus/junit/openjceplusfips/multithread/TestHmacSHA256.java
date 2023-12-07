/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;


import ibm.jceplus.junit.base.BaseTestHmacSHA256;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestHmacSHA256 extends ibm.jceplus.junit.base.BaseTestHmacSHA256 {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestHmacSHA256() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    public void testHmacMD5() throws Exception {
        System.out.println("executing testHmacSHA256");
        BaseTestHmacSHA256 bt = new BaseTestHmacSHA256(providerName);
        bt.run();

    }

    public static void main(String[] args) {
        String[] nargs = {
                ibm.jceplus.junit.openjceplusfips.multithread.TestHmacSHA256.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

}

