package com.cybersafe.service;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashSet;
import java.util.Set;

@Service
public class PhishingListService {

    private final Set<String> realTimePhishingList = new HashSet<>();

    public Set<String> getRealTimeList() {
        return realTimePhishingList;
    }

    @PostConstruct
    public void init() {
        // initial load on startup (best-effort)
        updatePhishingList();
    }

    // Updates every 24 hours
    @Scheduled(fixedRate = 86400000)
    public void updatePhishingList() {
        System.out.println("⏳ Updating phishing list...");

        String[] sources = {
                "https://phishing.army/download/phishing_army_blocklist.txt",
                "https://openphish.com/feed.txt"
        };

        Set<String> tempSet = new HashSet<>();

        for (String src : sources) {
            try {
                System.out.println("Downloading from: " + src);

                URL url = new URL(src);
                URLConnection connection = url.openConnection();
                connection.setConnectTimeout(8000);
                connection.setReadTimeout(8000);
                connection.setRequestProperty("User-Agent", "Mozilla/5.0");

                try (BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        line = line.trim().toLowerCase();

                        if (line.isEmpty() || line.startsWith("#")) continue;

                        // remove protocol and www
                        line = line.replaceFirst("^https?://", "");
                        line = line.replaceFirst("^www\\.", "");

                        // Some lists include paths; keep domain portion
                        int slashIndex = line.indexOf('/');
                        if (slashIndex > 0) line = line.substring(0, slashIndex);

                        if (!line.isEmpty()) tempSet.add(line);
                    }
                }

            } catch (Exception e) {
                System.out.println("⚠ Failed to load from: " + src + " | Error: " + e.getMessage());
            }
        }

        if (!tempSet.isEmpty()) {
            realTimePhishingList.clear();
            realTimePhishingList.addAll(tempSet);
            System.out.println("✔ Real-time phishing list updated. Total blocked domains: " + realTimePhishingList.size());
        } else {
            System.out.println("⚠ No data downloaded; keeping existing list (if any).");
        }
    }
}
