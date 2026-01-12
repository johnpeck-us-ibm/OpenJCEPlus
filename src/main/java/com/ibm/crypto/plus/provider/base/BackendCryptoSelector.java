/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.security.Provider;

/**
 * BackendCryptoSelector manages the selection and initialization of cryptographic backends.
 * It uses the NativeProvider attribute from Provider services to determine which backend 
 * to use (OCK or OpenSSL), and delegates all cryptographic operations to the selected backend.
 * 
 * Rules:
 * - No value, blank, or missing NativeProvider attribute defaults to OCK
 * - "OCK" explicitly selects OCK backend (case-insensitive)
 * - "OpenSSL" selects OpenSSL backend (case-insensitive)
 * - Each backend is initialized only once, on first use via initialize() method
 */
public class BackendCryptoSelector {
    
    /**
     * Enum representing the available cryptographic backends
     */
    public enum Backend {
        OCK,
        OPENSSL
    }
    
    // Backend implementation instances (will be set by concrete implementations)
    private static volatile BackendCryptoInterface ockBackend = null;
    private static volatile BackendCryptoInterface opensslBackend = null;
    
    // Track initialization state for each backend
    private static volatile boolean ockInitialized = false;
    private static volatile boolean opensslInitialized = false;
    
    // Locks for thread-safe initialization
    private static final Object ockLock = new Object();
    private static final Object opensslLock = new Object();
    
    /**
     * Sets the OCK backend implementation.
     * This should be called during system initialization.
     * 
     * @param backend the OCK backend implementation
     */
    public static void setOCKBackend(BackendCryptoInterface backend) {
        ockBackend = backend;
    }
    
    /**
     * Sets the OpenSSL backend implementation.
     * This should be called during system initialization.
     * 
     * @param backend the OpenSSL backend implementation
     */
    public static void setOpenSSLBackend(BackendCryptoInterface backend) {
        opensslBackend = backend;
    }
    
    /**
     * Gets the backend implementation for the specified backend type.
     * 
     * @param backend the backend type
     * @return the backend implementation, or null if not set
     */
    public static BackendCryptoInterface getBackend(Backend backend) {
        if (backend == Backend.OCK) {
            return ockBackend;
        } else if (backend == Backend.OPENSSL) {
            return opensslBackend;
        }
        return null;
    }
    
    /**
     * Determines which backend to use by querying the Provider service attribute.
     * Retrieves the NativeProvider attribute from provider.getService(type, algorithm).
     * 
     * @param provider the security provider
     * @param type the service type (e.g., "Cipher", "MessageDigest")
     * @param algorithm the algorithm name (e.g., "AES", "SHA-256")
     * @return the Backend to use
     */
    public static Backend selectBackend(Provider provider, String type, String algorithm) {
        if (provider == null || type == null || algorithm == null) {
            // Default to OCK if parameters are invalid
            return Backend.OCK;
        }
        
        Provider.Service service = provider.getService(type, algorithm);
        if (service == null) {
            // Service not found, default to OCK
            return Backend.OCK;
        }
        
        String nativeProviderValue = service.getAttribute("NativeProvider");
        return selectBackendFromAttribute(nativeProviderValue);
    }
    
    /**
     * Determines which backend to use based on the NativeProvider attribute value.
     * 
     * @param nativeProviderValue the value of the NativeProvider attribute
     * @return the Backend to use
     */
    private static Backend selectBackendFromAttribute(String nativeProviderValue) {
        if (nativeProviderValue == null || nativeProviderValue.trim().isEmpty()) {
            // Default to OCK when no value or blank
            return Backend.OCK;
        }
        
        String normalized = nativeProviderValue.trim().toUpperCase();
        
        if ("OPENSSL".equals(normalized)) {
            return Backend.OPENSSL;
        } else {
            // Default to OCK for any other value including "OCK"
            return Backend.OCK;
        }
    }
    
    /**
     * Initializes the specified backend if it hasn't been initialized yet.
     * This method is thread-safe and ensures initialization happens only once per backend.
     * Calls the initialize() method on the backend implementation.
     * 
     * @param backend the backend to initialize
     * @throws RuntimeException if initialization fails or backend is not set
     */
    public static void initializeBackend(Backend backend) {
        if (backend == Backend.OCK) {
            initializeOCK();
        } else if (backend == Backend.OPENSSL) {
            initializeOpenSSL();
        }
    }
    
    /**
     * Initializes the OCK backend if not already initialized.
     * Thread-safe with double-checked locking pattern.
     * Calls initialize() on the OCK backend implementation.
     */
    private static void initializeOCK() {
        if (!ockInitialized) {
            synchronized (ockLock) {
                if (!ockInitialized) {
                    try {
                        if (ockBackend == null) {
                            throw new IllegalStateException("OCK backend implementation not set");
                        }
                        ockBackend.initialize();
                        ockInitialized = true;
                    } catch (OCKException e) {
                        throw new RuntimeException("Failed to initialize OCK backend", e);
                    }
                }
            }
        }
    }
    
    /**
     * Initializes the OpenSSL backend if not already initialized.
     * Thread-safe with double-checked locking pattern.
     * Calls initialize() on the OpenSSL backend implementation.
     */
    private static void initializeOpenSSL() {
        if (!opensslInitialized) {
            synchronized (opensslLock) {
                if (!opensslInitialized) {
                    try {
                        if (opensslBackend == null) {
                            throw new IllegalStateException("OpenSSL backend implementation not set");
                        }
                        opensslBackend.initialize();
                        opensslInitialized = true;
                    } catch (OCKException e) {
                        throw new RuntimeException("Failed to initialize OpenSSL backend", e);
                    }
                }
            }
        }
    }
    
    /**
     * Checks if the OCK backend has been initialized.
     * 
     * @return true if OCK is initialized, false otherwise
     */
    public static boolean isOCKInitialized() {
        return ockInitialized;
    }
    
    /**
     * Checks if the OpenSSL backend has been initialized.
     * 
     * @return true if OpenSSL is initialized, false otherwise
     */
    public static boolean isOpenSSLInitialized() {
        return opensslInitialized;
    }
    
    /**
     * Convenience method to select and initialize a backend based on provider service attributes.
     * 
     * @param provider the security provider
     * @param type the service type (e.g., "Cipher", "MessageDigest")
     * @param algorithm the algorithm name (e.g., "AES", "SHA-256")
     * @return the Backend that was selected and initialized
     */
    public static Backend selectAndInitialize(Provider provider, String type, String algorithm) {
        Backend backend = selectBackend(provider, type, algorithm);
        initializeBackend(backend);
        return backend;
    }
    
    /**
     * Gets the initialized backend implementation for the given provider service.
     * Automatically selects and initializes the backend if needed.
     * 
     * @param provider the security provider
     * @param type the service type (e.g., "Cipher", "MessageDigest")
     * @param algorithm the algorithm name (e.g., "AES", "SHA-256")
     * @return the initialized backend implementation
     * @throws RuntimeException if backend cannot be initialized
     */
    public static BackendCryptoInterface getBackendForService(Provider provider, String type, String algorithm) {
        Backend backend = selectAndInitialize(provider, type, algorithm);
        BackendCryptoInterface impl = getBackend(backend);
        if (impl == null) {
            throw new IllegalStateException("Backend implementation not available for: " + backend);
        }
        return impl;
    }
    
    /**
     * Resets the initialization state. This is primarily for testing purposes.
     * WARNING: This should not be used in production code.
     */
    static void resetForTesting() {
        synchronized (ockLock) {
            synchronized (opensslLock) {
                ockInitialized = false;
                opensslInitialized = false;
                ockBackend = null;
                opensslBackend = null;
            }
        }
    }
}
