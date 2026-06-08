package com.example.networkrestricted;

import org.json.JSONObject;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class WifiScanner {

    // Scan using platform-specific commands. Returns Map<BSSID, SignalPercent>
    public static Map<String, Integer> getWifiFingerprint() throws IOException {
        Map<String, Integer> fingerprint = new LinkedHashMap<>();
        String osName = System.getProperty("os.name").toLowerCase();
        boolean isWindows = osName.contains("win");
        
        System.out.println("\nScanning Wi-Fi networks on " + System.getProperty("os.name") + "...");
        try {
            if (isWindows) {
                // Use netsh on Windows
                Process process = Runtime.getRuntime().exec(new String[] { "netsh", "wlan", "show", "networks", "mode=bssid" });
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), "UTF-8"))) {
                    String line;
                    String currentBssid = null;
                    int currentSignal = 0;
                    
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (line.startsWith("BSSID")) {
                            if (currentBssid != null && currentSignal != 0) {
                                fingerprint.put(currentBssid, currentSignal);
                            }
                            currentBssid = line.substring(line.indexOf(":") + 1).trim();
                            currentSignal = 0;
                        } else if (line.contains("Signal")) {
                            String signalStr = line.substring(line.indexOf(":") + 1).trim();
                            try {
                                // Windows reports signal as percentage
                                currentSignal = Integer.parseInt(signalStr.replace("%", ""));
                            } catch (NumberFormatException ignored) { }
                        }
                    }
                    // Add the last entry if exists
                    if (currentBssid != null && currentSignal != 0) {
                        fingerprint.put(currentBssid, currentSignal);
                    }
                }
                
                if (fingerprint.isEmpty()) {
                    System.out.println("Warning: No Wi-Fi networks found using netsh command");
                } else {
                    System.out.println("Found " + fingerprint.size() + " Wi-Fi networks");
                }
            } else {
                // First find wireless interface name on Linux
                System.out.println("Searching for wireless interface...");
                Process ifconfigProc = Runtime.getRuntime().exec(new String[] { "sh", "-c", "iwconfig 2>/dev/null | grep IEEE | cut -d' ' -f1" });
                BufferedReader ifconfigReader = new BufferedReader(new InputStreamReader(ifconfigProc.getInputStream()));
                String wifiInterface = ifconfigReader.readLine();
                
                if (wifiInterface == null || wifiInterface.trim().isEmpty()) {
                    System.out.println("No wireless interface found");
                    return fingerprint;
                }

                // Now scan for networks using iwlist on Linux
                Process process = Runtime.getRuntime().exec(new String[] { "sudo", "iwlist", wifiInterface.trim(), "scan" });
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), "UTF-8"))) {
                    String line;
                    String currentBssid = null;
                    int currentSignal = 0;
                    
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (line.contains("Address:")) {
                            if (currentBssid != null && currentSignal != 0) {
                                fingerprint.put(currentBssid, currentSignal);
                            }
                            currentBssid = line.substring(line.indexOf("Address:") + 8).trim();
                            currentSignal = 0;
                        } else if (line.contains("Signal level=")) {
                            String signalStr = line.substring(line.indexOf("Signal level=") + 13);
                            try {
                                // Convert dBm to percentage (typical range: -100 dBm to -50 dBm)
                                int dBm = Integer.parseInt(signalStr.split(" ")[0]);
                                currentSignal = Math.min(100, Math.max(0, (dBm + 100) * 2));
                            } catch (NumberFormatException ignored) { }
                        }
                    }
                    // Add the last entry if exists
                    if (currentBssid != null && currentSignal != 0) {
                        fingerprint.put(currentBssid, currentSignal);
                    }
                }
            }
        } catch (IOException e) {
            System.out.println("Warning: failed to capture Wi-Fi fingerprint: " + e.getMessage());
        }
        return fingerprint;
    }

    // Save fingerprint map to JSON file
    public static void saveFingerprint(Map<String, Integer> fp, String filePath) throws IOException {
        JSONObject json = new JSONObject(fp);
        Files.write(Paths.get(filePath), json.toString(4).getBytes("UTF-8"));
        System.out.println("Saved Wi-Fi fingerprint -> " + filePath);
    }

    // Load fingerprint from JSON file
    public static Map<String, Integer> loadFingerprint(String filePath) throws IOException {
        String s = new String(Files.readAllBytes(Paths.get(filePath)));
        JSONObject json = new JSONObject(s);
        Map<String, Integer> map = new LinkedHashMap<>();
        for (String k : json.keySet()) map.put(k, json.getInt(k));
        return map;
    }

    // symmetric similarity (0.0 - 1.0). Considers both missing and extra networks.
    public static double calculateSimilarity(Map<String,Integer> saved, Map<String,Integer> current) {
        if (saved == null || current == null || saved.isEmpty()) return 0.0;

        int matches = 0;
        for (String b : saved.keySet()) if (current.containsKey(b)) {
            int sR = saved.get(b);
            int cR = current.get(b);
            int diff = Math.abs(sR - cR);
            if (diff <= 12) matches++;
        }

        double denom = (saved.size() + current.size()) / 2.0;
        if (denom <= 0) denom = saved.size();
        return (double) matches / denom;
    }

    public static boolean compareFingerprints(Map<String,Integer> saved, Map<String,Integer> current, double threshold) {
        double sim = calculateSimilarity(saved, current);
        System.out.printf("Wi-Fi similarity = %.1f%%%n", sim * 100.0);
        return sim >= threshold;
    }
}
