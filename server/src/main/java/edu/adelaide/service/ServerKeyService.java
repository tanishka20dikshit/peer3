package edu.adelaide.service;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface ServerKeyService{
    String getServerId();

    PublicKey getPublicKey();

    PrivateKey getPrivateKey();

    String getPublicKeyBase64();

    String signPayload(String data);

    boolean verifyPayload(String data, String signature, PublicKey key);
}
