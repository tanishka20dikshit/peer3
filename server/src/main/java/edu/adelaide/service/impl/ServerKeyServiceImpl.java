package edu.adelaide.service.impl;

import edu.adelaide.service.ServerKeyService;
import edu.adelaide.util.CryptoUtils;

import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

@Service
public class ServerKeyServiceImpl implements ServerKeyService{
    private final String serverId = UUID.randomUUID().toString();

    private final KeyPair keyPair;

    public ServerKeyServiceImpl(){
        try{
            this.keyPair = CryptoUtils.generateRSAKeyPair();
        } catch (NoSuchAlgorithmException e){
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }

    @Override
    public String getServerId(){
        return serverId;
    }

    @Override
    public PublicKey getPublicKey(){
        return keyPair.getPublic();
    }

    @Override
    public PrivateKey getPrivateKey(){
        return keyPair.getPrivate();
    }

    @Override
    public String getPublicKeyBase64(){
        return CryptoUtils.encodeKey(keyPair.getPublic());
    }

    @Override
    public String signPayload(String data){
        try{
            return CryptoUtils.sign(data, keyPair.getPrivate());
        } catch (Exception e){
            throw new RuntimeException("Signing failed", e);
        }
    }

    @Override
    public boolean verifyPayload(String data, String signature, PublicKey key){
        try{
            return CryptoUtils.verify(data, signature, key);
        } catch (Exception e){
            throw new RuntimeException("Verification failed", e);
        }
    }

}
