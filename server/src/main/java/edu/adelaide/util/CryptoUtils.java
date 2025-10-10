package edu.adelaide.util;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Utility for RSA-4096 encryption/decryption and signing/verification.
 * - RSA-4096
 * - RSA-OAEP with SHA-256
 * - RSASSA-PSS with SHA-256
 * - base64url (no padding) encoding for binary fields
 */
public class CryptoUtils {

    private static final String KEY_ALGO = "RSA";
    private static final int KEY_SIZE = 4096;

    private static final String CIPHER_TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String SIGNATURE_ALGO = "RSASSA-PSS";

    private static final Base64.Encoder base64UrlEncoder = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder base64UrlDecoder = Base64.getUrlDecoder();

    private static final int PBKDF2_ITERATIONS = 600000;
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 256;

    // ---------- Key generation ----------
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGO);
        kpg.initialize(KEY_SIZE);
        return kpg.generateKeyPair();
    }

    // ---------- Encryption / Decryption ----------
    public static String encrypt(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return base64UrlEncoder.encodeToString(ciphertext);
    }

    public static String decrypt(String base64Ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] ciphertext = base64UrlDecoder.decode(base64Ciphertext);
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    // ---------- Signing / Verification ----------
    public static String sign(String plaintext, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGO);
        PSSParameterSpec pssSpec = new PSSParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                32,
                1
        );
        signature.setParameter(pssSpec);
        signature.initSign(privateKey);
        signature.update(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] sigBytes = signature.sign();
        return base64UrlEncoder.encodeToString(sigBytes);
    }

    public static boolean verify(String plaintext, String base64Signature, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGO);
        PSSParameterSpec pssSpec = new PSSParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                32,
                1
        );
        signature.setParameter(pssSpec);
        signature.initVerify(publicKey);
        signature.update(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] sigBytes = base64UrlDecoder.decode(base64Signature);
        return signature.verify(sigBytes);
    }

    // ---------- Key encoding / decoding (X.509 / PKCS#8) ----------
    public static String encodeKey(Key key) {
        return base64UrlEncoder.encodeToString(key.getEncoded());
    }

    public static PublicKey publicKeyFromBase64(String base64) throws Exception {
        byte[] bytes = base64UrlDecoder.decode(base64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance(KEY_ALGO);
        return kf.generatePublic(spec);
    }

    public static PrivateKey privateKeyFromBase64(String base64) throws Exception {
        byte[] bytes = base64UrlDecoder.decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance(KEY_ALGO);
        return kf.generatePrivate(spec);
    }

    // ---------- Password hashing / verification ----------
    public static String hashPassword(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(
            password.toCharArray(),
            salt,
            PBKDF2_ITERATIONS,
            HASH_LENGTH
        );
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return base64UrlEncoder.encodeToString(hash);
    }

    public static boolean verifyPassword(String password, String storedHash, byte[] salt) throws Exception {
        String computedHash = hashPassword(password, salt);
        return computedHash.equals(storedHash);
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    // For testing locally
    public static void main(String[] args) throws Exception {
        KeyPair kp = generateRSAKeyPair();
        String message = "Hello Secure World!";

        String ciphertext = encrypt(message, kp.getPublic());
        String decrypted = decrypt(ciphertext, kp.getPrivate());

        String signature = sign(message, kp.getPrivate());
        boolean ok = verify(message, signature, kp.getPublic());

        System.out.println("Original: " + message);
        System.out.println("Ciphertext: " + ciphertext);
        System.out.println("Decrypted: " + decrypted);
        System.out.println("Signature: " + signature);
        System.out.println("Verified: " + ok);
    }
}
