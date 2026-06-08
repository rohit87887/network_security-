package com.example.networkrestricted;

import org.json.JSONObject;

import java.util.Map;

public class PayloadUtil {

    // Create payload JSON string
    // cipherText - iv:cipher (Base64), encryptedAESKey - base64 string, optional wifi fingerprint added
    public static String createPayload(String cipherText, String encryptedAESKey, Map<String,Integer> wifiFingerprint) {
        JSONObject obj = new JSONObject();
        obj.put("cipherText", cipherText);
        obj.put("encryptedAESKey", encryptedAESKey);
        if (wifiFingerprint != null) obj.put("wifiFingerprint", wifiFingerprint);
        return obj.toString(4);
    }
}
