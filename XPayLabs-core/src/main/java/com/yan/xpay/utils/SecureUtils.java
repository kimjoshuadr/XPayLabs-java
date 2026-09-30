package com.yan.xpay.utils;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.symmetric.AES;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Wallet private-key encryption.
 *
 * v2 (write path): AES-256-GCM under a deployment master key that is NOT stored in the
 * database. Format:  v2:<b64(salt16)>:<b64(nonce12)>:<b64(ciphertext+tag)>
 * The per-record AES key is derived with HKDF-SHA256(masterKey, salt).
 *
 * legacy (read-only): AES/ECB/PKCS5 using a per-row key taken from the historical
 * t_address_pool.encrypt column. Kept so pre-migration rows still decrypt.
 *
 * Master key source: env XPAY_CRYPTO_MASTER_KEY (base64/hex, 32 bytes) or
 * -Dxpay.crypto.master-key. Fails closed if a v2 value is read without it.
 */
public class SecureUtils {

    private static final String PREFIX = "v2:";
    private static final byte[] INFO = "xpay-address-key".getBytes(StandardCharsets.UTF_8);
    private static final int SALT_LEN = 16;
    private static final int NONCE_LEN = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] masterKey() {
        String v = System.getenv("XPAY_CRYPTO_MASTER_KEY");
        if (v == null || v.isBlank()) {
            v = System.getProperty("xpay.crypto.master-key");
        }
        if (v == null || v.isBlank()) {
            throw new IllegalStateException("XPAY_CRYPTO_MASTER_KEY is not set");
        }
        byte[] k;
        try {
            k = Base64.getDecoder().decode(v.trim());
        } catch (IllegalArgumentException e) {
            k = SecureUtil.decode(v.trim());
        }
        if (k.length != 32) {
            throw new IllegalStateException("XPAY_CRYPTO_MASTER_KEY must decode to 32 bytes");
        }
        return k;
    }

    private static byte[] hkdf(byte[] master, byte[] salt) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(master, "HmacSHA256"));
        byte[] prk = mac.doFinal(salt);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(INFO);
        return Arrays.copyOf(mac.doFinal(new byte[]{1}), 32);
    }

    /** Encrypts key material with the deployment master key. */
    public static String encodePrivateKey(String plaintext) {
        try {
            byte[] salt = new byte[SALT_LEN];
            RANDOM.nextBytes(salt);
            byte[] nonce = new byte[NONCE_LEN];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(hkdf(masterKey(), salt), "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            Base64.Encoder b64 = Base64.getEncoder();
            return PREFIX + b64.encodeToString(salt) + ":" + b64.encodeToString(nonce) + ":" + b64.encodeToString(ct);
        } catch (Exception e) {
            throw new RuntimeException("key encryption failed", e);
        }
    }

    /** Decrypts v2 (master key) or legacy (per-row AES-ECB) key material. */
    public static String decodePrivateKey(String keystore, String encrypt) {
        if (keystore != null && keystore.startsWith(PREFIX)) {
            try {
                String[] parts = keystore.substring(PREFIX.length()).split(":");
                Base64.Decoder b64 = Base64.getDecoder();
                byte[] salt = b64.decode(parts[0]);
                byte[] nonce = b64.decode(parts[1]);
                byte[] ct = b64.decode(parts[2]);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec(hkdf(masterKey(), salt), "AES"),
                        new GCMParameterSpec(TAG_BITS, nonce));
                return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw new RuntimeException("key decryption failed", e);
            }
        }
        // legacy path (pre-migration rows only)
        byte[] key = SecureUtil.decode(encrypt);
        AES aes = SecureUtil.aes(key);
        return aes.decryptStr(keystore);
    }
}
