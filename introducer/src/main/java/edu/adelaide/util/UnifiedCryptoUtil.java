package edu.adelaide.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;

/**
 * Unified cryptographic utility class that integrates scattered encryption functionality in the project
 * Provides common functions such as RSA encryption, signing, AES encryption, etc.
 */
public final class UnifiedCryptoUtil {
    
    private static final Logger log = LoggerFactory.getLogger(UnifiedCryptoUtil.class);
    
    // Constant definitions
    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_TRANSFORM = "AES/GCM/NoPadding";
    private static final String RSA_OAEP_TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String RSA_PSS_ALGORITHM = "RSASSA-PSS";
    
    private static final int RSA_KEY_SIZE = 4096;
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    
    // Base64 encoder (URL-safe, no padding)
    private static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE64_URL_DECODER = Base64.getUrlDecoder();
    
    private UnifiedCryptoUtil() {}
    
    // ==================== RSA Key Generation ====================
    
    /**
     * Generate RSA key pair
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(RSA_KEY_SIZE);
        return keyGen.generateKeyPair();
    }
    
    /**
     * Load RSA public key from Base64URL string
     */
    public static RSAPublicKey loadRSAPublicKeyFromBase64Url(String base64UrlKey) throws Exception {
        byte[] keyBytes = BASE64_URL_DECODER.decode(base64UrlKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return (RSAPublicKey) keyFactory.generatePublic(spec);
    }
    
    /**
     * Load RSA private key from Base64URL string
     */
    public static RSAPrivateKey loadRSAPrivateKeyFromBase64Url(String base64UrlKey) throws Exception {
        byte[] keyBytes = BASE64_URL_DECODER.decode(base64UrlKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }
    
    /**
     * Load RSA private key from PEM string
     */
    public static RSAPrivateKey loadRSAPrivateKeyFromPemString(String pemString) throws Exception {
        // Remove PEM headers and footers
        String privateKeyPEM = pemString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        
        byte[] keyBytes = java.util.Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }
    
    /**
     * Encode public key to Base64URL string
     */
    public static String encodePublicKeyToBase64Url(PublicKey publicKey) {
        return BASE64_URL_ENCODER.encodeToString(publicKey.getEncoded());
    }
    
    /**
     * Encode private key to Base64URL string
     */
    public static String encodePrivateKeyToBase64Url(PrivateKey privateKey) {
        return BASE64_URL_ENCODER.encodeToString(privateKey.getEncoded());
    }
    
    // ==================== RSA Encryption/Decryption ====================
    
    /**
     * RSA encrypt with OAEP padding
     */
    public static byte[] rsaEncrypt(byte[] data, RSAPublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_OAEP_TRANSFORM);
        OAEPParameterSpec spec = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
        );
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, spec);
        return cipher.doFinal(data);
    }
    
    /**
     * RSA decrypt with OAEP padding
     */
    public static byte[] rsaDecrypt(byte[] encryptedData, RSAPrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_OAEP_TRANSFORM);
        OAEPParameterSpec spec = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
        );
        cipher.init(Cipher.DECRYPT_MODE, privateKey, spec);
        return cipher.doFinal(encryptedData);
    }
    
    // ==================== RSA Signing/Verification ====================
    
    /**
     * RSA sign with PSS padding
     */
    public static String rsaSign(byte[] data, RSAPrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(RSA_PSS_ALGORITHM);
        PSSParameterSpec spec = new PSSParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                32,
                1
        );
        signature.setParameter(spec);
        signature.initSign(privateKey);
        signature.update(data);
        byte[] signatureBytes = signature.sign();
        return BASE64_URL_ENCODER.encodeToString(signatureBytes);
    }
    
    /**
     * RSA sign string with PSS padding
     */
    public static String rsaSign(String data, RSAPrivateKey privateKey) throws Exception {
        return rsaSign(data.getBytes(StandardCharsets.UTF_8), privateKey);
    }
    
    /**
     * RSA verify with PSS padding
     */
    public static boolean rsaVerify(byte[] data, String signatureB64, RSAPublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(RSA_PSS_ALGORITHM);
        PSSParameterSpec spec = new PSSParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                32,
                1
        );
        signature.setParameter(spec);
        signature.initVerify(publicKey);
        signature.update(data);
        byte[] signatureBytes = BASE64_URL_DECODER.decode(signatureB64);
        return signature.verify(signatureBytes);
    }
    
    /**
     * RSA verify string with PSS padding
     */
    public static boolean rsaVerify(String data, String signatureB64, RSAPublicKey publicKey) throws Exception {
        return rsaVerify(data.getBytes(StandardCharsets.UTF_8), signatureB64, publicKey);
    }
    
    // ==================== AES Encryption/Decryption ====================
    
    /**
     * Generate AES key
     */
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGenerator.init(AES_KEY_SIZE);
        return keyGenerator.generateKey();
    }
    
    /**
     * Generate random IV for AES-GCM
     */
    public static byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
    
    /**
     * AES-GCM encrypt
     */
    public static byte[] aesEncrypt(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(data);
    }
    
    /**
     * AES-GCM decrypt
     */
    public static byte[] aesDecrypt(byte[] encryptedData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(encryptedData);
    }
    
    // ==================== Hash and Encoding ====================
    
    /**
     * SHA-256 hash
     */
    public static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }
    
    /**
     * SHA-256 hash string
     */
    public static byte[] sha256(String data) throws NoSuchAlgorithmException {
        return sha256(data.getBytes(StandardCharsets.UTF_8));
    }
    
    /**
     * Base64URL encode
     */
    public static String base64UrlEncode(byte[] data) {
        return BASE64_URL_ENCODER.encodeToString(data);
    }
    
    /**
     * Base64URL decode
     */
    public static byte[] base64UrlDecode(String data) {
        return BASE64_URL_DECODER.decode(data);
    }
    
    // ==================== Utility Methods ====================
    
    /**
     * Generate random bytes
     */
    public static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
    
    /**
     * Constant time string comparison
     */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
    
    /**
     * Extract public key from CRT private key
     */
    public static RSAPublicKey extractPublicKeyFromCRT(RSAPrivateKey privateKey) throws Exception {
        if (privateKey instanceof RSAPrivateCrtKey crtKey) {
            RSAPublicKeySpec spec = new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent());
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return (RSAPublicKey) keyFactory.generatePublic(spec);
        }
        throw new IllegalArgumentException("Private key is not a CRT key");
    }
}
