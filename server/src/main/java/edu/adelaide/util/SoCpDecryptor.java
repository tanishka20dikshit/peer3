package edu.adelaide.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;

/**
 * SoCpDecryptor
 *
 * Utilities for:
 *  - RSA-OAEP (SHA-256, MGF1-SHA256) decryption
 *  - RSA-PSS (SHA-256, MGF1-SHA256, saltLen=32, trailer=1) verification
 *  - Canonical JSON generation (UTF-8 + sorted keys) for verification
 *  - Base64URL (no padding) decoding
 *  - Key loading (SPKI public key from base64url DER, private key from PEM)
 */
public final class SoCpDecryptor {

  private SoCpDecryptor(){}

  /** Canonical JSON: UTF-8 with keys sorted in dictionary order (same as Encryptor) */
  private static final ObjectMapper CANONICAL = new ObjectMapper()
      .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
      .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

  // -------------------- Base64URL --------------------

  /** Decode base64url (no padding) into bytes */
  public static byte[] db64u(String b64u) { return Base64.getUrlDecoder().decode(b64u); }

  // -------------------- Key loading --------------------

  /**
   * Load RSA public key from base64url-encoded SPKI (X.509) DER.
   */
  public static RSAPublicKey loadPublicKeyFromB64u(String spkiDerB64u) throws GeneralSecurityException {
    byte[] der = db64u(spkiDerB64u);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
    return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
  }

  /**
   * Load RSA private key from PEM string.
   * Supports both PKCS#8 ("BEGIN PRIVATE KEY") and PKCS#1 ("BEGIN RSA PRIVATE KEY").
   */
  public static RSAPrivateKey loadPrivateKeyFromPemString(String pem) throws GeneralSecurityException {
    String p = pem.replace("\r", "").trim();
    if (p.contains("BEGIN PRIVATE KEY")) {
      String base64 = p.replace("-----BEGIN PRIVATE KEY-----", "")
          .replace("-----END PRIVATE KEY-----", "")
          .replaceAll("\\s+","");
      byte[] der = Base64.getDecoder().decode(base64);
      return (RSAPrivateKey) KeyFactory.getInstance("RSA")
          .generatePrivate(new PKCS8EncodedKeySpec(der));
    } else if (p.contains("BEGIN RSA PRIVATE KEY")) {
      String base64 = p.replace("-----BEGIN RSA PRIVATE KEY-----", "")
          .replace("-----END RSA PRIVATE KEY-----", "")
          .replaceAll("\\s+","");
      byte[] pkcs1 = Base64.getDecoder().decode(base64);
      byte[] pkcs8 = wrapPkcs1ToPkcs8(pkcs1);
      return (RSAPrivateKey) KeyFactory.getInstance("RSA")
          .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }
    throw new GeneralSecurityException("Unsupported PEM format");
  }

  // -------------------- RSA-OAEP (SHA-256, MGF1-SHA256) decryption --------------------

  /**
   * Decrypt ciphertext using RSA/ECB/OAEPWithSHA-256AndMGF1Padding.
   * Accepts raw ciphertext bytes and returns plaintext bytes.
   */
  public static byte[] rsaDecryptOaep(byte[] ciphertext, RSAPrivateKey priv) {
    try {
      Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
      OAEPParameterSpec spec = new OAEPParameterSpec(
          "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
      c.init(Cipher.DECRYPT_MODE, priv, spec);
      return c.doFinal(ciphertext);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Decrypt base64url(ciphertext) and return plaintext bytes.
   */
  public static byte[] rsaDecryptOaepFromB64u(String ciphertextB64u, RSAPrivateKey priv) {
    return rsaDecryptOaep(db64u(ciphertextB64u), priv);
  }

  // -------------------- RSA-PSS (SHA-256, saltLen=32) verification --------------------

  /**
   * Verify RSASSA-PSS signature for the provided data.
   * Expects SHA-256, MGF1(SHA-256), saltLen=32, trailerField=1.
   */
  public static boolean verifyPss(byte[] data, RSAPublicKey pub, byte[] signature) {
    try {
      Signature s = Signature.getInstance("RSASSA-PSS");
      PSSParameterSpec p = new PSSParameterSpec(
          "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
      s.setParameter(p);
      s.initVerify(pub);
      s.update(data);
      return s.verify(signature);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Verify base64url(signature) for the provided data bytes.
   */
  public static boolean verifyPssB64u(byte[] data, RSAPublicKey pub, String signatureB64u) {
    return verifyPss(data, pub, db64u(signatureB64u));
  }

  /**
   * Verify signature for the canonical JSON of the envelope with "sig" removed.
   */
  public static boolean verifyEnvelopeCanonical(JsonNode envelopeWithoutSig, RSAPublicKey pub, String signatureB64u) {
    byte[] bytes = canonicalBytes(envelopeWithoutSig);
    return verifyPssB64u(bytes, pub, signatureB64u);
  }

  // -------------------- Canonical JSON --------------------

  /**
   * Serialize JSON node to canonical bytes (UTF-8, keys sorted).
   */
  public static byte[] canonicalBytes(JsonNode node) {
    try {
      return CANONICAL.writeValueAsString(node).getBytes(StandardCharsets.UTF_8);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // -------------------- Minimal PKCS#1 → PKCS#8 wrapper --------------------

  /**
   * Wrap a PKCS#1 RSAPrivateKey DER blob into a PKCS#8 PrivateKeyInfo.
   * This minimal ASN.1 builder works for typical 2048/3072/4096-bit keys.
   */
  private static byte[] wrapPkcs1ToPkcs8(byte[] pkcs1) {
    byte[] algoId = new byte[]{
        0x30, 0x0D,
        0x06, 0x09, 0x2A,(byte)0x86,0x48,(byte)0x86,(byte)0xF7,0x0D,0x01,0x01,0x01,
        0x05, 0x00
    };
    byte[] octet = derOctetString(pkcs1);
    int len = 3 + algoId.length + octet.length; // INTEGER(0) + algoId + octet
    return concat(new byte[]{0x30}, derLen(len),
        new byte[]{0x02,0x01,0x00}, algoId, octet);
  }

  private static byte[] derOctetString(byte[] v){ return concat(new byte[]{0x04}, derLen(v.length), v); }
  private static byte[] derLen(int len){
    if(len<128) return new byte[]{(byte)len};
    if(len<256) return new byte[]{(byte)0x81,(byte)len};
    return new byte[]{(byte)0x82,(byte)(len>>8),(byte)len};
  }
  private static byte[] concat(byte[]...arrs){
    int n=0; for(byte[]a:arrs) n+=a.length;
    byte[] r=new byte[n]; int p=0;
    for(byte[]a:arrs){ System.arraycopy(a,0,r,p,a.length); p+=a.length; }
    return r;
  }
}
