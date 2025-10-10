package edu.adelaide.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * SoCpSigner (minimal)
 *
 * What we support here:
 * - canonicalBytesFromJson(String json): Canonical JSON bytes (UTF-8, keys sorted).
 * - loadRsaPublicKeyFromB64Url(String spkiB64u): load RSA public key from base64url SPKI DER.
 * - signPssB64u(byte[] data, RSAPrivateKey priv): RSASSA-PSS (SHA-256, MGF1-SHA256, saltLen=32).
 * - verifyPssB64u(String sigB64u, byte[] data, RSAPublicKey pub): verify RSASSA-PSS.
 * - signEnvelopeCanonicalB64u(Object envelopeWithoutSig, RSAPrivateKey priv): convenience for signing a POJO/Map tree (without "sig").
 *
 * Notes:
 * - Base64URL encoding: no padding.
 * - Canonicalization: keys sorted; arrays keep order; numbers/strings unchanged.
 */
public final class SoCpSigner {

    private SoCpSigner() {}

    // Canonical mapper: sort keys
    private static final ObjectMapper CANONICAL = new ObjectMapper()
            .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    // ---------- base64url helpers ----------
    public static String b64u(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    public static byte[] b64uDecode(String b64u) {
        return Base64.getUrlDecoder().decode(b64u);
    }

    // ---------- canonical JSON ----------
    public static byte[] canonicalBytesFromJson(String json) {
        try {
            JsonNode node = new ObjectMapper().readTree(json);
            return canonicalBytes(node);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public static byte[] canonicalBytes(JsonNode node) {
        try {
            return CANONICAL.writeValueAsString(node).getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    // ---------- RSA key load ----------
    public static RSAPublicKey loadRsaPublicKeyFromB64Url(String spkiDerB64u) throws GeneralSecurityException {
        byte[] der = b64uDecode(spkiDerB64u);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        return (RSAPublicKey) java.security.KeyFactory.getInstance("RSA").generatePublic(spec);
        // (private key is injected by Spring; no loader here)
    }

    // ---------- RSASSA-PSS (SHA-256, MGF1-SHA256, saltLen=32) ----------
    public static String signPssB64u(byte[] data, RSAPrivateKey priv) {
        try {
            Signature s = Signature.getInstance("RSASSA-PSS");
            PSSParameterSpec p = new PSSParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA256, 32, 1);
            s.setParameter(p);
            s.initSign(priv);
            s.update(data);
            return b64u(s.sign());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    // --- FIX: Alias method required by ServerMainWsHandler ---
    /**
     * Alias for signPssB64u to match the expected signature in ServerMainWsHandler.
     * Signs the input data using RSASSA-PSS (SHA-256) and returns a Base64URL-encoded string.
     */
    public static String signB64u(byte[] data, RSAPrivateKey privateKey) {
        return signPssB64u(data, privateKey);
    }
    // --------------------------------------------------------

    public static boolean verifyPssB64u(String sigB64u, byte[] data, RSAPublicKey pub) {
        try {
            Signature s = Signature.getInstance("RSASSA-PSS");
            PSSParameterSpec p = new PSSParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA256, 32, 1);
            s.setParameter(p);
            s.initVerify(pub);
            s.update(data);
            return s.verify(b64uDecode(sigB64u));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ---------- convenience: sign a POJO/Map tree (WITHOUT "sig") ----------
    public static String signEnvelopeCanonicalB64u(Object envelopeWithoutSig, RSAPrivateKey priv) {
        try {
            JsonNode node = new ObjectMapper().valueToTree(envelopeWithoutSig);
            // IMPORTANT: the object passed in must NOT contain "sig"
            return signPssB64u(canonicalBytes(node), priv);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}