/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.util.Arrays;
import java.util.Random;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BaseTestHmacSHA256Interop extends BaseTestInterop {
    //--------------------------------------------------------------------------
    //
    //
    static boolean warmup = false;

    // test vectors from http://www.ietf.org/proceedings/02jul/I-D/draft-ietf-ipsec-ciph-sha-256-01.txt
    final byte[] key_1 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
            (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b,
            (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x11,
            (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
            (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d,
            (byte) 0x1e, (byte) 0x1f, (byte) 0x20};

    //"abc".getBytes();
    final byte[] data_1 = {(byte) 0x61, (byte) 0x62, (byte) 0x63};

    final byte[] digest_1 = {(byte) 0xa2, (byte) 0x1b, (byte) 0x1f, (byte) 0x5d, (byte) 0x4c,
            (byte) 0xf4, (byte) 0xf7, (byte) 0x3a, (byte) 0x4d, (byte) 0xd9, (byte) 0x39,
            (byte) 0x75, (byte) 0x0f, (byte) 0x7a, (byte) 0x06, (byte) 0x6a, (byte) 0x7f,
            (byte) 0x98, (byte) 0xcc, (byte) 0x13, (byte) 0x1c, (byte) 0xb1, (byte) 0x6a,
            (byte) 0x66, (byte) 0x92, (byte) 0x75, (byte) 0x90, (byte) 0x21, (byte) 0xcf,
            (byte) 0xab, (byte) 0x81, (byte) 0x81};

    final byte[] key_2 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
            (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b,
            (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x11,
            (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
            (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d,
            (byte) 0x1e, (byte) 0x1f, (byte) 0x20};

    //"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes();
    final byte[] data_2 = {(byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64, (byte) 0x62,
            (byte) 0x63, (byte) 0x64, (byte) 0x65, (byte) 0x63, (byte) 0x64, (byte) 0x65,
            (byte) 0x66, (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x65,
            (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x66, (byte) 0x67, (byte) 0x68,
            (byte) 0x69, (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x6a, (byte) 0x68,
            (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x69, (byte) 0x6a, (byte) 0x6b,
            (byte) 0x6c, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6b,
            (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e,
            (byte) 0x6f, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x70, (byte) 0x6e,
            (byte) 0x6f, (byte) 0x70, (byte) 0x71};

    final byte[] digest_2 = {(byte) 0x10, (byte) 0x4f, (byte) 0xdc, (byte) 0x12, (byte) 0x57,
            (byte) 0x32, (byte) 0x8f, (byte) 0x08, (byte) 0x18, (byte) 0x4b, (byte) 0xa7,
            (byte) 0x31, (byte) 0x31, (byte) 0xc5, (byte) 0x3c, (byte) 0xae, (byte) 0xe6,
            (byte) 0x98, (byte) 0xe3, (byte) 0x61, (byte) 0x19, (byte) 0x42, (byte) 0x11,
            (byte) 0x49, (byte) 0xea, (byte) 0x8c, (byte) 0x71, (byte) 0x24, (byte) 0x56,
            (byte) 0x69, (byte) 0x7d, (byte) 0x30};

    final byte[] key_3 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
            (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b,
            (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x11,
            (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
            (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d,
            (byte) 0x1e, (byte) 0x1f, (byte) 0x20};

    //"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes();
    final byte[] data_3 = {(byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64, (byte) 0x62,
            (byte) 0x63, (byte) 0x64, (byte) 0x65, (byte) 0x63, (byte) 0x64, (byte) 0x65,
            (byte) 0x66, (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x65,
            (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x66, (byte) 0x67, (byte) 0x68,
            (byte) 0x69, (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x6a, (byte) 0x68,
            (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x69, (byte) 0x6a, (byte) 0x6b,
            (byte) 0x6c, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6b,
            (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e,
            (byte) 0x6f, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x70, (byte) 0x6e,
            (byte) 0x6f, (byte) 0x70, (byte) 0x71, (byte) 0x61, (byte) 0x62, (byte) 0x63,
            (byte) 0x64, (byte) 0x62, (byte) 0x63, (byte) 0x64, (byte) 0x65, (byte) 0x63,
            (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x64, (byte) 0x65, (byte) 0x66,
            (byte) 0x67, (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x66,
            (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x67, (byte) 0x68, (byte) 0x69,
            (byte) 0x6a, (byte) 0x68, (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x69,
            (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c,
            (byte) 0x6d, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x6c,
            (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f,
            (byte) 0x70, (byte) 0x6e, (byte) 0x6f, (byte) 0x70, (byte) 0x71};

    final byte[] digest_3 = {(byte) 0x47, (byte) 0x03, (byte) 0x05, (byte) 0xfc, (byte) 0x7e,
            (byte) 0x40, (byte) 0xfe, (byte) 0x34, (byte) 0xd3, (byte) 0xee, (byte) 0xb3,
            (byte) 0xe7, (byte) 0x73, (byte) 0xd9, (byte) 0x5a, (byte) 0xab, (byte) 0x73,
            (byte) 0xac, (byte) 0xf0, (byte) 0xfd, (byte) 0x06, (byte) 0x04, (byte) 0x47,
            (byte) 0xa5, (byte) 0xeb, (byte) 0x45, (byte) 0x95, (byte) 0xbf, (byte) 0x33,
            (byte) 0xa9, (byte) 0xd1, (byte) 0xa3};

    final byte[] key_4 = {(byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b,
            (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b,
            (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b,
            (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b,
            (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b,
            (byte) 0x0b, (byte) 0x0b, (byte) 0x0b};

    final byte[] data_4 = {(byte) 0x48, (byte) 0x69, (byte) 0x20, (byte) 0x54, (byte) 0x68,
            (byte) 0x65, (byte) 0x72, (byte) 0x65};

    final byte[] digest_4 = {(byte) 0x19, (byte) 0x8a, (byte) 0x60, (byte) 0x7e, (byte) 0xb4,
            (byte) 0x4b, (byte) 0xfb, (byte) 0xc6, (byte) 0x99, (byte) 0x03, (byte) 0xa0,
            (byte) 0xf1, (byte) 0xcf, (byte) 0x2b, (byte) 0xbd, (byte) 0xc5, (byte) 0xba,
            (byte) 0x0a, (byte) 0xa3, (byte) 0xf3, (byte) 0xd9, (byte) 0xae, (byte) 0x3c,
            (byte) 0x1c, (byte) 0x7a, (byte) 0x3b, (byte) 0x16, (byte) 0x96, (byte) 0xa0,
            (byte) 0xb6, (byte) 0x8c, (byte) 0xf7};

    //"Jefe".getBytes();
    final byte[] key_5 = {(byte) 0x4a, (byte) 0x65, (byte) 0x66, (byte) 0x65};

    //"what do ya want for nothing?".getBytes();
    final byte[] data_5 = {(byte) 0x77, (byte) 0x68, (byte) 0x61, (byte) 0x74, (byte) 0x20,
            (byte) 0x64, (byte) 0x6f, (byte) 0x20, (byte) 0x79, (byte) 0x61, (byte) 0x20,
            (byte) 0x77, (byte) 0x61, (byte) 0x6e, (byte) 0x74, (byte) 0x20, (byte) 0x66,
            (byte) 0x6f, (byte) 0x72, (byte) 0x20, (byte) 0x6e, (byte) 0x6f, (byte) 0x74,
            (byte) 0x68, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x3f};

    final byte[] digest_5 = {(byte) 0x5b, (byte) 0xdc, (byte) 0xc1, (byte) 0x46, (byte) 0xbf,
            (byte) 0x60, (byte) 0x75, (byte) 0x4e, (byte) 0x6a, (byte) 0x04, (byte) 0x24,
            (byte) 0x26, (byte) 0x08, (byte) 0x95, (byte) 0x75, (byte) 0xc7, (byte) 0x5a,
            (byte) 0x00, (byte) 0x3f, (byte) 0x08, (byte) 0x9d, (byte) 0x27, (byte) 0x39,
            (byte) 0x83, (byte) 0x9d, (byte) 0xec, (byte) 0x58, (byte) 0xb9, (byte) 0x64,
            (byte) 0xec, (byte) 0x38, (byte) 0x43};

    final byte[] key_6 = {(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa};

    final byte[] data_6 = {(byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd};


    final byte[] digest_6 = {(byte) 0xcd, (byte) 0xcb, (byte) 0x12, (byte) 0x20, (byte) 0xd1,
            (byte) 0xec, (byte) 0xcc, (byte) 0xea, (byte) 0x91, (byte) 0xe5, (byte) 0x3a,
            (byte) 0xba, (byte) 0x30, (byte) 0x92, (byte) 0xf9, (byte) 0x62, (byte) 0xe5,
            (byte) 0x49, (byte) 0xfe, (byte) 0x6c, (byte) 0xe9, (byte) 0xed, (byte) 0x7f,
            (byte) 0xdc, (byte) 0x43, (byte) 0x19, (byte) 0x1f, (byte) 0xbd, (byte) 0xe4,
            (byte) 0x5c, (byte) 0x30, (byte) 0xb0};

    final byte[] key_7 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
            (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b,
            (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x11,
            (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
            (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c, (byte) 0x1d,
            (byte) 0x1e, (byte) 0x1f, (byte) 0x20, (byte) 0x21, (byte) 0x22, (byte) 0x23,
            (byte) 0x24, (byte) 0x25};

    final byte[] data_7 = {(byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd};

    final byte[] digest_7 = {(byte) 0xd4, (byte) 0x63, (byte) 0x3c, (byte) 0x17, (byte) 0xf6,
            (byte) 0xfb, (byte) 0x8d, (byte) 0x74, (byte) 0x4c, (byte) 0x66, (byte) 0xde,
            (byte) 0xe0, (byte) 0xf8, (byte) 0xf0, (byte) 0x74, (byte) 0x55, (byte) 0x6e,
            (byte) 0xc4, (byte) 0xaf, (byte) 0x55, (byte) 0xef, (byte) 0x7, (byte) 0x99,
            (byte) 0x85, (byte) 0x41, (byte) 0x46, (byte) 0x8e, (byte) 0xb4, (byte) 0x9b,
            (byte) 0xd2, (byte) 0xe9, (byte) 0x17};

    final byte[] key_8 = {(byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c,
            (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c,
            (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c,
            (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c,
            (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c,
            (byte) 0x0c, (byte) 0x0c, (byte) 0x0c};

    //"Test With Truncation".getBytes();
    final byte[] data_8 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20,
            (byte) 0x57, (byte) 0x69, (byte) 0x74, (byte) 0x68, (byte) 0x20, (byte) 0x54,
            (byte) 0x72, (byte) 0x75, (byte) 0x6e, (byte) 0x63, (byte) 0x61, (byte) 0x74,
            (byte) 0x69, (byte) 0x6f, (byte) 0x6e};

    final byte[] digest_8 = {(byte) 0x75, (byte) 0x46, (byte) 0xaf, (byte) 0x1, (byte) 0x84,
            (byte) 0x1f, (byte) 0xc0, (byte) 0x9b, (byte) 0x1a, (byte) 0xb9, (byte) 0xc3,
            (byte) 0x74, (byte) 0x9a, (byte) 0x5f, (byte) 0x1c, (byte) 0x17, (byte) 0xd4,
            (byte) 0xf5, (byte) 0x89, (byte) 0x66, (byte) 0x8a, (byte) 0x58, (byte) 0x7b,
            (byte) 0x27, (byte) 0x0, (byte) 0xa9, (byte) 0xc9, (byte) 0x7c, (byte) 0x11,
            (byte) 0x93, (byte) 0xcf, (byte) 0x42};

    final byte[] key_9 = {(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa};

    //"Test Using Larger Than Block-Size Key - Hash Key First".getBytes();//{0xcd};
    final byte[] data_9 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20,
            (byte) 0x55, (byte) 0x73, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x20,
            (byte) 0x4c, (byte) 0x61, (byte) 0x72, (byte) 0x67, (byte) 0x65, (byte) 0x72,
            (byte) 0x20, (byte) 0x54, (byte) 0x68, (byte) 0x61, (byte) 0x6e, (byte) 0x20,
            (byte) 0x42, (byte) 0x6c, (byte) 0x6f, (byte) 0x63, (byte) 0x6b, (byte) 0x2d,
            (byte) 0x53, (byte) 0x69, (byte) 0x7a, (byte) 0x65, (byte) 0x20, (byte) 0x4b,
            (byte) 0x65, (byte) 0x79, (byte) 0x20, (byte) 0x2d, (byte) 0x20, (byte) 0x48,
            (byte) 0x61, (byte) 0x73, (byte) 0x68, (byte) 0x20, (byte) 0x4b, (byte) 0x65,
            (byte) 0x79, (byte) 0x20, (byte) 0x46, (byte) 0x69, (byte) 0x72, (byte) 0x73,
            (byte) 0x74};

    final byte[] digest_9 = {(byte) 0x69, (byte) 0x53, (byte) 0x2, (byte) 0x5e, (byte) 0xd9,
            (byte) 0x6f, (byte) 0xc, (byte) 0x9, (byte) 0xf8, (byte) 0xa, (byte) 0x96, (byte) 0xf7,
            (byte) 0x8e, (byte) 0x65, (byte) 0x38, (byte) 0xdb, (byte) 0xe2, (byte) 0xe7,
            (byte) 0xb8, (byte) 0x20, (byte) 0xe3, (byte) 0xdd, (byte) 0x97, (byte) 0xe,
            (byte) 0x7d, (byte) 0xdd, (byte) 0x39, (byte) 0x9, (byte) 0x1b, (byte) 0x32,
            (byte) 0x35, (byte) 0x2f};

    final byte[] key_10 = {(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa};

    //"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".getBytes();
    final byte[] data_10 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20,
            (byte) 0x55, (byte) 0x73, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x20,
            (byte) 0x4c, (byte) 0x61, (byte) 0x72, (byte) 0x67, (byte) 0x65, (byte) 0x72,
            (byte) 0x20, (byte) 0x54, (byte) 0x68, (byte) 0x61, (byte) 0x6e, (byte) 0x20,
            (byte) 0x42, (byte) 0x6c, (byte) 0x6f, (byte) 0x63, (byte) 0x6b, (byte) 0x2d,
            (byte) 0x53, (byte) 0x69, (byte) 0x7a, (byte) 0x65, (byte) 0x20, (byte) 0x4b,
            (byte) 0x65, (byte) 0x79, (byte) 0x20, (byte) 0x61, (byte) 0x6e, (byte) 0x64,
            (byte) 0x20, (byte) 0x4c, (byte) 0x61, (byte) 0x72, (byte) 0x67, (byte) 0x65,
            (byte) 0x72, (byte) 0x20, (byte) 0x54, (byte) 0x68, (byte) 0x61, (byte) 0x6e,
            (byte) 0x20, (byte) 0x4f, (byte) 0x6e, (byte) 0x65, (byte) 0x20, (byte) 0x42,
            (byte) 0x6c, (byte) 0x6f, (byte) 0x63, (byte) 0x6b, (byte) 0x2d, (byte) 0x53,
            (byte) 0x69, (byte) 0x7a, (byte) 0x65, (byte) 0x20, (byte) 0x44, (byte) 0x61,
            (byte) 0x74, (byte) 0x61};

    final byte[] digest_10 = {(byte) 0x63, (byte) 0x55, (byte) 0xac, (byte) 0x22, (byte) 0xe8,
            (byte) 0x90, (byte) 0xd0, (byte) 0xa3, (byte) 0xc8, (byte) 0x48, (byte) 0x1a,
            (byte) 0x5c, (byte) 0xa4, (byte) 0x82, (byte) 0x5b, (byte) 0xc8, (byte) 0x84,
            (byte) 0xd3, (byte) 0xe7, (byte) 0xa1, (byte) 0xff, (byte) 0x98, (byte) 0xa2,
            (byte) 0xfc, (byte) 0x2a, (byte) 0xc7, (byte) 0xd8, (byte) 0xe0, (byte) 0x64,
            (byte) 0xc3, (byte) 0xb2, (byte) 0xe6};


    //--------------------------------------------------------------------------
    //
    //
    public BaseTestHmacSHA256Interop(String providerName, String interopProviderName) {
        super(providerName, interopProviderName);
        try {
            if (warmup == false) {
                warmup = true;
                warmup();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {}

    //--------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    //--------------------------------------------------------------------------
    //
    //
    public void test_data1() throws Exception {
        doHmac(data_1, providerName, interopProviderName);
        doHmac(data_1, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void test_data2() throws Exception {
        doHmac(data_2, providerName, interopProviderName);
        doHmac(data_2, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void test_data3() throws Exception {
        doHmac(data_3, providerName, interopProviderName);
        doHmac(data_3, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void test_data4() throws Exception {
        doHmac(data_4, providerName, interopProviderName);
        doHmac(data_4, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void test_data5() throws Exception {
        doHmac(data_5, providerName, interopProviderName);
        doHmac(data_5, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void test_data6() throws Exception {
        doHmac(data_6, providerName, interopProviderName);
        doHmac(data_6, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void test_data7() throws Exception {
        doHmac(data_7, providerName, interopProviderName);
        doHmac(data_7, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void test_data8() throws Exception {
        doHmac(data_8, providerName, interopProviderName);
        doHmac(data_8, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void test_data9() throws Exception {
        doHmac(data_9, providerName, interopProviderName);
        doHmac(data_9, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void test_data10() throws Exception {
        doHmac(data_10, providerName, interopProviderName);
        doHmac(data_10, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void test_payload_512() throws Exception {
        byte[] data_512 = new byte[512];
        Random r = new Random(10);
        r.nextBytes(data_512);
        doHmac(data_512, providerName, interopProviderName);
        doHmac(data_512, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void test_payload_2048() throws Exception {
        byte[] data_2048 = new byte[2048];
        Random r = new Random(10);
        r.nextBytes(data_2048);
        doHmac(data_2048, providerName, interopProviderName);
        doHmac(data_2048, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void test_payload_8192() throws Exception {
        byte[] data_8192 = new byte[8192];
        Random r = new Random(10);
        r.nextBytes(data_8192);
        doHmac(data_8192, providerName, interopProviderName);
        doHmac(data_8192, interopProviderName, providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    protected void doHmac(byte[] data, String provider, String interopProvider) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256", provider);
        SecretKey key = keyGen.generateKey();

        Mac mac = Mac.getInstance("HmacSHA256", provider);
        mac.init(key);
        mac.update(data);
        byte[] digest = mac.doFinal();

        Mac mac2 = Mac.getInstance("HmacSHA256", interopProvider);
        mac2.init(key);
        mac2.update(data);
        byte[] digest2 = mac2.doFinal();

        assertTrue("Mac digest did not equal expected", Arrays.equals(digest, digest2));
    }

    //--------------------------------------------------------------------------
    //
    //
    public void warmup() throws Exception {

        try {
            Mac mac = Mac.getInstance("HmacSHA256", providerName);
            SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA256");
            for (long i = 0; i < 10000; i++) {
                mac.init(key);
                mac.update(data_1);
                mac.doFinal();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

