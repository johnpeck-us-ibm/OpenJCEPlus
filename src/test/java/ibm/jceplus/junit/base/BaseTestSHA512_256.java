/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.security.MessageDigest;
import java.util.Arrays;

public class BaseTestSHA512_256 extends BaseTest {

    // Test vectors obtained from
    // http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA512_256.pdf

    public BaseTestSHA512_256(String providerName) {
        super(providerName);
    }

    public void testSHA512_256_SingleBlock() throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA-512/256", providerName);
        assertTrue(Arrays.equals(md.digest("abc".getBytes("UTF-8")),
                hexStrToBytes("53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23")));

    }

    public void testSHA512_256_TwoBlock() throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA-512/256", providerName);

        assertTrue(Arrays.equals(
                md.digest(("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                        + "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
                                .getBytes("UTF-8")),
                hexStrToBytes("3928E184FB8690F840DA3988121D31BE65CB9D3EF83EE6146FEAC861E19B563A")));
    }

    public void testSHA512_256_varmsgs() throws Exception {
        String calculatedDigests[] = {
                "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", //i=0
                "b988f846fe2989eb4e8ab3126404ea117ef9461ffec59b4c6519a1208b948e3c", //i = 2000
                "2717427c6682cb17a9ac27fa4425f25ef0e1c5245bd5a2442cb9918650e56a7a", //i = 4000
                "fa5722136cb05ab14be21a05f69235cd4d0208b6b0219d6c5650da2d1d211726", //i = 6000
                "5057563b0d908c3da8449ae5d976f5d1eb1df2c9460a0445162348ad9ea16e6b" //i = 8000
        };

        String msg = "";
        int j = 0;
        MessageDigest mdIBM = MessageDigest.getInstance("SHA-512/256", providerName);

        for (int i = 0; i < 10000; i++) {

            byte[] ibmDigest = mdIBM.digest(msg.getBytes("UTF-8"));

            if (i % 2000 == 0) {
                assertTrue(Arrays.equals(hexStrToBytes(calculatedDigests[j]), ibmDigest));
                j = j + 1;
            }
            msg = msg + String.valueOf(i);

        }


    }

    public void testSHA512_256_withUpdates() throws Exception {

        String calcDigest = "c171b3719fc985090fd9db086061e2b63539f326bc4d989bbe9ac37b7d038022";

        MessageDigest mdIBM = MessageDigest.getInstance("SHA-512/256", providerName);
        String msgarrays[] = {"Hello0", "Hello1", "Hello2", "Hello3", "Hello4", "longmessage5",
                "longermessage6,", "verylongmessage7"};
        for (int i = 0; i < msgarrays.length; i++) {
            mdIBM.update(msgarrays[i].getBytes("UTF-8"));
        }

        byte[] ibmDigest = mdIBM.digest();
        assertTrue(Arrays.equals(hexStrToBytes(calcDigest), ibmDigest));

    }

    /*
     * for printing binary.
     */
    String toHex(byte[] data) {
        String digits = "0123456789abcdef";
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xff;
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        return buf.toString();
    }

    static byte[] hexStrToBytes(String in) {
        int len = in.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) Integer.parseInt(in.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

}
