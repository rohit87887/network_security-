package com.example.networkrestricted;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.Map;
import org.json.JSONObject;

public class Decryptor {
    public static void main(String[] args) {
        try {
            System.out.println("Starting Network-Restricted Decryptor...");

            // Load payload
            String content = new String(Files.readAllBytes(Paths.get("encrypted_payload.json")));
            JSONObject payload = new JSONObject(content);

            String cipherText = payload.getString("cipherText");
            String encryptedAESKey = payload.getString("encryptedAESKey");

            // load saved fingerprint from payload (if present)
            Map<String,Integer> savedFingerprint = null;
            if (payload.has("wifiFingerprint")) {
                JSONObject jfp = payload.getJSONObject("wifiFingerprint");
                savedFingerprint = new java.util.LinkedHashMap<>();
                for (String k : jfp.keySet()) savedFingerprint.put(k, jfp.getInt(k));
            } else {
                // fallback: try load local saved file (if sender shared it separately)
                try { savedFingerprint = WifiScanner.loadFingerprint("wifi_fingerprint.json"); } catch (Exception ignore) { }
            }

            if (savedFingerprint == null || savedFingerprint.isEmpty()) {
                System.out.println("No saved Wi-Fi fingerprint available in payload or local file. Aborting.");
                return;
            }

            // scan current environment
            Map<String,Integer> current = WifiScanner.getWifiFingerprint();

            // compare with threshold (0.75-0.85 recommended)
            double threshold = 0.75;
            boolean ok = WifiScanner.compareFingerprints(savedFingerprint, current, threshold);
            if (!ok) {
                System.out.println("Network environment mismatch. Access denied.");
                return;
            }

            System.out.println("Network environment verified. Proceeding to decrypt AES key...");

            // load recipient private key (kept secret on recipient)
            PrivateKey priv = RSAUtil.loadPrivateKey("recipient_private.der");

            byte[] aesBytes = RSAUtil.decryptAESKey(encryptedAESKey, priv);
            SecretKey aesKey = AESUtil.fromBytes(aesBytes);

            String decrypted = AESUtil.decrypt(cipherText, aesKey);
            System.out.println("Decryption successful. Plaintext:");
            System.out.println(decrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
