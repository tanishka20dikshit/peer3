package edu.adelaide.util;

import com.fasterxml.jackson.core.JsonProcessingException;
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
 * SoCpEncryptor
 *
 * Utilities for:
 *  - RSA-OAEP (SHA-256, MGF1-SHA256) encryption
 *  - RSA-PSS (SHA-256, MGF1-SHA256, saltLen=32, trailer=1) signing
 *  - Canonical JSON generation (UTF-8 + sorted keys)
 *  - Base64URL (no padding) encoding
 *  - Key loading (SPKI public key from base64url DER, private key from PEM)
 *
 * Notes:
 *  - All binary fields in SOCP should be base64url without padding.
 *  - Sign the canonical JSON of the entire envelope with the "sig" field removed.
 *  - RSA-4096 OAEP plaintext size limit is about 446 bytes. Use hybrid encryption for larger data.
 */
public final class SoCpEncryptor {

  private SoCpEncryptor() {}

  /** Canonical JSON: UTF-8 with keys sorted in dictionary order. */
  private static final ObjectMapper CANONICAL = new ObjectMapper()
      .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
      .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

  // --------------------------------------------------------------------------
  // Base64URL
  // --------------------------------------------------------------------------

  /** Encode bytes using base64url without padding. */
  public static String b64u(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  // --------------------------------------------------------------------------
  // Key loading
  // --------------------------------------------------------------------------

  /** Load RSA public key from base64url-encoded SPKI (X.509) DER. */
  public static RSAPublicKey loadPublicKeyFromB64u(String spkiDerB64u) throws GeneralSecurityException {
    byte[] der = Base64.getUrlDecoder().decode(spkiDerB64u);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
    return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
  }

  /** Alias for readability. */
  public static RSAPublicKey loadRsaPublicKeyFromB64Url(String spkiDerB64u) throws GeneralSecurityException {
    return loadPublicKeyFromB64u(spkiDerB64u);
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
          .replaceAll("\\s+", "");
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

  // --------------------------------------------------------------------------
  // RSA-OAEP (SHA-256, MGF1-SHA256) encryption
  // --------------------------------------------------------------------------

  /** Encrypt plaintext using RSA/ECB/OAEPWithSHA-256AndMGF1Padding. Returns raw ciphertext bytes. */
  public static byte[] rsaEncryptOaep(byte[] plaintext, RSAPublicKey pub) {
    try {
      Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
      OAEPParameterSpec spec = new OAEPParameterSpec(
          "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
      c.init(Cipher.ENCRYPT_MODE, pub, spec);
      return c.doFinal(plaintext);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  /** Encrypt plaintext and return base64url(ciphertext). */
  public static String rsaEncryptOaepB64u(byte[] plaintext, RSAPublicKey pub) {
    return b64u(rsaEncryptOaep(plaintext, pub));
  }

  // --------------------------------------------------------------------------
  // RSA-PSS (SHA-256, saltLen=32) signing
  // --------------------------------------------------------------------------

  /** Sign data using RSASSA-PSS with SHA-256, MGF1(SHA-256), saltLen=32, trailerField=1. Returns raw signature bytes. */
  public static byte[] signPss(byte[] data, RSAPrivateKey priv) {
    try {
      Signature s = Signature.getInstance("RSASSA-PSS");
      PSSParameterSpec p = new PSSParameterSpec(
          "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
      s.setParameter(p);
      s.initSign(priv);
      s.update(data);
      return s.sign();
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  /** Sign data and return base64url(signature). */
  public static String signPssB64u(byte[] data, RSAPrivateKey priv) {
    return b64u(signPss(data, priv));
  }

  /** Verify RSASSA-PSS signature (SHA-256, MGF1-SHA256, saltLen=32) where sig is base64url and pubkey is SPKI base64url. */
  public static boolean verifyPssB64u(byte[] data, String sigB64u, String spkiDerB64u) {
    try {
      RSAPublicKey pub = loadPublicKeyFromB64u(spkiDerB64u);
      return verifyPssB64u(sigB64u, data, pub);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  /** Overload: verify with already-parsed RSAPublicKey (preferred in server runtime). */
  public static boolean verifyPssB64u(String sigB64u, byte[] data, RSAPublicKey pub) {
    try {
      Signature s = Signature.getInstance("RSASSA-PSS");
      PSSParameterSpec p = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
      s.setParameter(p);
      s.initVerify(pub);
      s.update(data);
      byte[] sig = Base64.getUrlDecoder().decode(sigB64u);
      return s.verify(sig);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  // --------------------------------------------------------------------------
  // Canonical JSON helpers
  // --------------------------------------------------------------------------

  /** Serialize JSON node to canonical bytes (UTF-8, keys sorted). */
  public static byte[] canonicalBytes(JsonNode node) {
    try {
      return CANONICAL.writeValueAsString(node).getBytes(StandardCharsets.UTF_8);
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  /** Canonical bytes for an envelope JSON (string) with keys sorted. */
  public static byte[] canonicalBytesFromJson(String json) {
    try {
      JsonNode node = new ObjectMapper().readTree(json);
      return canonicalBytes(node);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /** Sign the canonical JSON bytes of an envelope with "sig" removed. Returns base64url(signature). */
  public static String signEnvelopeCanonicalB64u(JsonNode envelopeWithoutSig, RSAPrivateKey priv) {
    return signPssB64u(canonicalBytes(envelopeWithoutSig), priv);
  }

  /** Sign an envelope represented as arbitrary POJO/Map (must NOT contain 'sig' yet), return base64url(signature). */
  public static String signEnvelopeCanonicalB64u(Object envelopeWithoutSig, RSAPrivateKey priv) {
    try {
      ObjectMapper mapper = new ObjectMapper();
      JsonNode node = mapper.valueToTree(envelopeWithoutSig);
      return signEnvelopeCanonicalB64u(node, priv);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /** Verify signature of an envelope JSON string that contains a "sig" field against a pinned SPKI (base64url). */
  public static boolean verifyEnvelopeSignatureFromJson(String envelopeJson, String spkiB64u) {
    try {
      ObjectMapper mapper = new ObjectMapper();
      JsonNode root = mapper.readTree(envelopeJson);
      JsonNode sigNode = root.get("sig");
      if (sigNode == null || sigNode.isNull() || sigNode.asText().isBlank()) {
        throw new IllegalStateException("Envelope missing 'sig'");
      }
      String sigB64u = sigNode.asText();

      // Remove "sig" then canonicalize
      if (root.isObject()) ((com.fasterxml.jackson.databind.node.ObjectNode) root).remove("sig");
      byte[] canonical = canonicalBytes(root);

      return verifyPssB64u(canonical, sigB64u, spkiB64u);
    } catch (RuntimeException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // --------------------------------------------------------------------------
  // Minimal PKCS#1 → PKCS#8 wrapper
  // --------------------------------------------------------------------------

  /** Wrap a PKCS#1 RSAPrivateKey DER blob into a PKCS#8 PrivateKeyInfo. */
  private static byte[] wrapPkcs1ToPkcs8(byte[] pkcs1) {
    // PrivateKeyInfo ::= SEQUENCE {
    //   version INTEGER(0),
    //   algorithm AlgorithmIdentifier(rsaEncryption, NULL),
    //   privateKey OCTET STRING
    // }
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
