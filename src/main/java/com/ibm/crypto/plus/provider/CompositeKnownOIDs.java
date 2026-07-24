/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry of OIDs and standard names for the composite signature algorithms
 * defined in draft-ietf-lamps-pq-composite-sigs.
 *
 * <p>Each enum constant's name (uppercased, underscores) is used as the lookup
 * key in addition to the dotted OID string and the human-friendly standard name.
 */
public enum CompositeKnownOIDs {

    // draft-ietf-lamps-pq-composite-sigs §12 OID assignments
    MLDSA44_RSA2048_PSS_SHA256(
            "2.16.840.1.114027.80.8.1.1",  "MLDSA44-RSA2048-PSS-SHA256"),
    MLDSA44_RSA2048_PKCS15_SHA256(
            "2.16.840.1.114027.80.8.1.2",  "MLDSA44-RSA2048-PKCS15-SHA256"),
    MLDSA44_Ed25519(
            "2.16.840.1.114027.80.8.1.3",  "MLDSA44-Ed25519"),
    MLDSA44_ECDSA_P256_SHA256(
            "2.16.840.1.114027.80.8.1.4",  "MLDSA44-ECDSA-P256-SHA256"),
    MLDSA65_RSA3072_PSS_SHA512(
            "2.16.840.1.114027.80.8.1.5",  "MLDSA65-RSA3072-PSS-SHA512"),
    MLDSA65_RSA3072_PKCS15_SHA512(
            "2.16.840.1.114027.80.8.1.6",  "MLDSA65-RSA3072-PKCS15-SHA512"),
    MLDSA65_ECDSA_P384_SHA384(
            "2.16.840.1.114027.80.8.1.8",  "MLDSA65-ECDSA-P384-SHA384"),
    MLDSA65_Ed25519(
            "2.16.840.1.114027.80.8.1.9",  "MLDSA65-Ed25519"),
    MLDSA87_ECDSA_P384_SHA384(
            "2.16.840.1.114027.80.8.1.11", "MLDSA87-ECDSA-P384-SHA384"),
    MLDSA87_ECDSA_P521_SHA512(
            "2.16.840.1.114027.80.8.1.12", "MLDSA87-ECDSA-P521-SHA512"),
    MLDSA87_Ed448(
            "2.16.840.1.114027.80.8.1.13", "MLDSA87-Ed448");

    private final String oid;
    private final String stdName;

    private static final ConcurrentHashMap<String, CompositeKnownOIDs> lookup =
            new ConcurrentHashMap<>();

    static {
        for (CompositeKnownOIDs entry : CompositeKnownOIDs.values()) {
            register(entry);
        }
    }

    CompositeKnownOIDs(String oid, String stdName) {
        this.oid = oid;
        this.stdName = stdName;
    }

    private static void register(CompositeKnownOIDs entry) {
        if (lookup.put(entry.oid, entry) != null) {
            throw new RuntimeException("Duplicate OID: " + entry.oid);
        }
        String key = entry.stdName.toUpperCase(Locale.ENGLISH).replace('-', '_');
        if (lookup.put(key, entry) != null) {
            throw new RuntimeException("Duplicate key: " + key);
        }
    }

    /**
     * Finds the matching entry by OID string or standard name (case-insensitive,
     * hyphens and underscores treated as equivalent).
     *
     * @param x OID string or algorithm name
     * @return matching entry, or {@code null} if not found
     */
    public static CompositeKnownOIDs findMatch(String x) {
        if (x == null) {
            return null;
        }
        return lookup.get(x.toUpperCase(Locale.ENGLISH).replace('-', '_'));
    }

    /** Returns the dotted OID string. */
    public String oidString() {
        return oid;
    }

    /**
     * Returns the human-friendly standard algorithm name
     * (e.g. {@code "MLDSA44-ECDSA-P256-SHA256"}).
     */
    public String stdName() {
        return stdName;
    }

}
