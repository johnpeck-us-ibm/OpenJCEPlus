/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.memstress;

import java.security.KeyPairGenerator;
import ibm.jceplus.junit.base.BaseTest;

public class BaseTestMemStressRSAKeyPair extends BaseTest {

    // --------------------------------------------------------------------------
    //
    //



    int numTimes = 100;
    boolean printheapstats = false;
    int rsaSize = 2048;

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestMemStressRSAKeyPair(String providerName) {
        super(providerName);

    }

    public BaseTestMemStressRSAKeyPair(String providerName, int rsaSize) {
        super(providerName);
        this.rsaSize = rsaSize;
    }

    // --------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        printheapstats = Boolean
                .valueOf(System.getProperty("com.ibm.jceplus.memstress.printheapstats"));
        System.out.println("Testing RSAKeyPair ");
    }

    // --------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    // --------------------------------------------------------------------------
    //
    //

    public void testRSAKeyPair() throws Exception {

        Runtime rt = Runtime.getRuntime();
        long prevTotalMemory = 0;
        long prevFreeMemory = rt.freeMemory();
        long currentTotalMemory = 0;
        long currentFreeMemory = 0;
        long currentUsedMemory = 0;
        long prevUsedMemory = 0;

        for (int i = 0; i < numTimes; i++) {
            generateKeyPair(2048);
            currentTotalMemory = rt.totalMemory();
            currentFreeMemory = rt.freeMemory();
            currentUsedMemory = currentTotalMemory - currentFreeMemory;
            prevUsedMemory = prevTotalMemory - prevFreeMemory;
            if (currentTotalMemory != prevTotalMemory || currentFreeMemory != prevFreeMemory) {
                if (printheapstats) {
                    System.out.println("RSAKeyPair " + rsaSize + " Iteration = " + i + " "
                            + "Total: = " + currentTotalMemory + " " + "currentUsed: = "
                            + currentUsedMemory + " " + "freeMemory: " + currentFreeMemory
                            + " prevUsedMemory: " + prevUsedMemory);
                }
                prevTotalMemory = currentTotalMemory;
                prevFreeMemory = currentFreeMemory;
            }
        }
    }


    void generateKeyPair(int size) throws Exception {


        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        kpg.generateKeyPair();
    }
}
