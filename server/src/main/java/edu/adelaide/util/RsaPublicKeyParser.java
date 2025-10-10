package edu.adelaide.util;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class RsaPublicKeyParser {

  public static RSAPublicKey parse(String pub) throws Exception {
    if (pub == null) throw new IllegalArgumentException("pub is null");

    String cleaned = pub.trim();

    if (cleaned.startsWith("-----BEGIN")) {
      cleaned = cleaned
          .replace("-----BEGIN PUBLIC KEY-----", "")
          .replace("-----END PUBLIC KEY-----", "")
          .replaceAll("\\s+", "");
      byte[] der = Base64.getMimeDecoder().decode(cleaned);
      return buildFromX509(der);
    }

    cleaned = cleaned.replaceAll("\\s+", "");

    boolean looksBase64Url = cleaned.contains("-") || cleaned.contains("_");

    byte[] der;
    if (looksBase64Url) {
      String b64 = cleaned.replace('-', '+').replace('_', '/');
      int mod = b64.length() % 4;
      if (mod == 2)      b64 += "==";
      else if (mod == 3) b64 += "=";
      else if (mod != 0) throw new IllegalArgumentException("Bad Base64URL length");
      der = Base64.getDecoder().decode(b64);
    } else {
      der = Base64.getDecoder().decode(cleaned);
    }

    return buildFromX509(der);
  }

  private static RSAPublicKey buildFromX509(byte[] spkiDer) throws Exception {
    X509EncodedKeySpec spec = new X509EncodedKeySpec(spkiDer);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return (RSAPublicKey) kf.generatePublic(spec);
  }

  public static void main(String[] args) throws Exception {
    String s = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApeqCIbQ8eqHGvrIAX5Ki6jPG6k6ClkJLfk-1cpifXEbyaZ2IPHao9q8WFuQPu0-p0ULmC_VumF5scARh3aWBcDD-MWq6oKBZKI-qHuJnLs7sU1xd7K-mLFXOOCRRIf5geIAsP9uOkguq052a1b3W0wCDUmoGd5m62CXFh_Au9gN89SGKoVoSmDS6L3YKhmfV2bblQpqcKh86V3vhSvRy6oMnOFCey6swE9kIcjyaGgMXL_BMZIPB-oucmZsyb8ksda4YtQNFChC3JrGkM7WP2qSo_p2It5lu-HfIInHSaQBCSJSxYyyjfxUCkr4Kv8U8nEJI-UOltWLJCSYVdJFwg8eGPR4WYQ4bf7-oqCd6lU4SKKqvqeqvMO9N3cOA4l7e3lkNiEcia-G1BfOMO5mlzgacXZWWOq-jr79p9MB4RIgIJL5R4qlyG0L0Lz8sKS6zBAsgu_cq0970y_ae_lnu8M8LrW92wATp7SnrKNqMd3xj_hR2eCveFSHVRq2gyD3iEgMLSQ95EOCpt4A9xV4HdCDzds9MtwqZfpe3GGHYN2mt2JBUblaSVE6CO9JMLrdVCupwTk9XSOREe1j4TIi_V7nsGdLL8ENJAfGHj3A0Y8q0ccDrpS86DHoVtFymliy6lcSA4v3wUiaJw3jhffVnvSdlGJnh63ZIgYU9trcDV2sCAwEAAQ";
    RSAPublicKey k = parse(s);
    System.out.println("OK, modulus bits = " + k.getModulus().bitLength());
    System.out.println("e = " + k.getPublicExponent());
  }

}
