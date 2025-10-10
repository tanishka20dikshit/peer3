package edu.adelaide.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
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
     * RSA-OAEP encryption
     */
    public static String rsaEncrypt(String plaintext, RSAPublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_OAEP_TRANSFORM);
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        );
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return BASE64_URL_ENCODER.encodeToString(ciphertext);
    }
    
    /**
     * RSA-OAEP decryption
     */
    public static String rsaDecrypt(String base64Ciphertext, RSAPrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_OAEP_TRANSFORM);
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        );
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec);
        byte[] ciphertext = BASE64_URL_DECODER.decode(base64Ciphertext);
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }
    
    // ==================== RSA Signing/Verification ====================
    
    /**
     * RSA-PSS signing
     */
    public static String rsaSign(byte[] data, RSAPrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(RSA_PSS_ALGORITHM);
        PSSParameterSpec pssSpec = new PSSParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            32, // salt length
            1   // trailer field
        );
        signature.setParameter(pssSpec);
        signature.initSign(privateKey);
        signature.update(data);
        byte[] sigBytes = signature.sign();
        return BASE64_URL_ENCODER.encodeToString(sigBytes);
    }
    
    /**
     * RSA-PSS signing (string input)
     */
    public static String rsaSign(String data, RSAPrivateKey privateKey) throws Exception {
        return rsaSign(data.getBytes(StandardCharsets.UTF_8), privateKey);
    }
    
    /**
     * RSA-PSS verification
     */
    public static boolean rsaVerify(byte[] data, String base64Signature, RSAPublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(RSA_PSS_ALGORITHM);
        PSSParameterSpec pssSpec = new PSSParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            32, // salt length
            1   // trailer field
        );
        signature.setParameter(pssSpec);
        signature.initVerify(publicKey);
        signature.update(data);
        byte[] sigBytes = BASE64_URL_DECODER.decode(base64Signature);
        return signature.verify(sigBytes);
    }
    
    /**
     * RSA-PSS verification (string input)
     */
    public static boolean rsaVerify(String data, String base64Signature, RSAPublicKey publicKey) throws Exception {
        return rsaVerify(data.getBytes(StandardCharsets.UTF_8), base64Signature, publicKey);
    }
    
    // ==================== AES Encryption/Decryption ====================
    
    /**
     * Generate AES key
     */
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }
    
    /**
     * Generate random IV
     */
    public static byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
    
    /**
     * AES-GCM encryption
     */
    public static byte[] aesEncrypt(byte[] plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(plaintext);
    }
    
    /**
     * AES-GCM decryption
     */
    public static byte[] aesDecrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(ciphertext);
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
     * SHA-256 hash (string input)
     */
    public static byte[] sha256(String data) throws NoSuchAlgorithmException {
        return sha256(data.getBytes(StandardCharsets.UTF_8));
    }
    
    /**
     * Base64URL encoding
     */
    public static String base64UrlEncode(byte[] data) {
        return BASE64_URL_ENCODER.encodeToString(data);
    }
    
    /**
     * Base64URL decoding
     */
    public static byte[] base64UrlDecode(String base64Url) {
        return BASE64_URL_DECODER.decode(base64Url);
    }
    
    // ==================== Utility Methods ====================
    
    /**
     * Generate random byte array
     */
    public static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
    
    /**
     * Securely compare two byte arrays
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
    
    /**
     * Extract public key from CRT private key
     */
    public static RSAPublicKey extractPublicKeyFromCRT(RSAPrivateKey privateKey) throws Exception {
        if (privateKey instanceof java.security.interfaces.RSAPrivateCrtKey crtKey) {
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                crtKey.getModulus(),
                crtKey.getPublicExponent()
            );
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        } else {
            throw new IllegalArgumentException("Private key is not a CRT key");
        }
    }
}
