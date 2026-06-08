package com.example.networkrestricted;

import javax.crypto.Cipher;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class RSAUtil {

    // generate and save key pair (use on recipient device once)
    public static void generateAndSaveKeyPair(String pubPath, String privPath) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        try (FileOutputStream fos = new FileOutputStream(pubPath)) {
            fos.write(kp.getPublic().getEncoded());
        }
        try (FileOutputStream fos = new FileOutputStream(privPath)) {
            fos.write(kp.getPrivate().getEncoded());
        }
    }

    public static PublicKey loadPublicKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static PrivateKey loadPrivateKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    // Encrypt AES key bytes using recipient's public key. Returns Base64 string.
    public static String encryptAESKey(byte[] aesKeyBytes, PublicKey recipientPub) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, recipientPub);
        byte[] enc = cipher.doFinal(aesKeyBytes);
        return Base64.getEncoder().encodeToString(enc);
    }

    // Decrypt AES key (Base64) using recipient private key -> returns raw AES key bytes
    public static byte[] decryptAESKey(String encryptedBase64, PrivateKey privateKey) throws Exception {
        byte[] enc = Base64.getDecoder().decode(encryptedBase64);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(enc);
    }
}
