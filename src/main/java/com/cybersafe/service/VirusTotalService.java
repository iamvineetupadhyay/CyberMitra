package com.cybersafe.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Service
public class VirusTotalService {

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${virustotal.api.key:}")
    private String apiKey;

    @Value("${virustotal.poll.interval.ms:2000}")
    private int pollInterval;

    @Value("${virustotal.poll.maxAttempts:15}")
    private int maxAttempts;

    public boolean isEnabled() {
        return apiKey != null && !apiKey.isBlank();
    }

    /**
     * Scans the given URL using VirusTotal v3:
     * 1) POST /api/v3/urls (form urlencoded "url=...")
     * 2) Extract analysis id
     * 3) Poll GET /api/v3/analyses/{id} until status is completed
     * 4) Parse stats and return summary map
     */
    public Map<String, Object> scanUrl(String urlToScan) {
        Map<String, Object> out = new HashMap<>();
        if (!isEnabled()) {
            out.put("error", "VirusTotal API key not configured");
            return out;
        }

        try {
            // 1) POST url
            String form = "url=" + URLEncoder.encode(urlToScan, StandardCharsets.UTF_8);
            HttpRequest postReq = HttpRequest.newBuilder()
                    .uri(URI.create("https://www.virustotal.com/api/v3/urls"))
                    .timeout(Duration.ofSeconds(15))
                    .header("x-apikey", apiKey)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();

            HttpResponse<String> postResp = httpClient.send(postReq, HttpResponse.BodyHandlers.ofString());
            if (postResp.statusCode() / 100 != 2) {
                out.put("error", "VirusTotal returned status " + postResp.statusCode());
                out.put("raw", postResp.body());
                return out;
            }

            JsonNode postJson = mapper.readTree(postResp.body());
            // analysis id location: data.id (VT returns analysis id)
            String analysisId = null;
            if (postJson.has("data") && postJson.get("data").has("id")) {
                analysisId = postJson.get("data").get("id").asText();
            }

            if (analysisId == null) {
                out.put("error", "Could not get analysis id from VirusTotal response");
                out.put("raw", postResp.body());
                return out;
            }

            // 2) Poll analyses endpoint until finished
            String analysisUrl = "https://www.virustotal.com/api/v3/analyses/" + analysisId;
            int attempts = 0;
            while (attempts < maxAttempts) {
                attempts++;
                HttpRequest getReq = HttpRequest.newBuilder()
                        .uri(URI.create(analysisUrl))
                        .timeout(Duration.ofSeconds(15))
                        .header("x-apikey", apiKey)
                        .GET()
                        .build();

                HttpResponse<String> getResp = httpClient.send(getReq, HttpResponse.BodyHandlers.ofString());
                if (getResp.statusCode() / 100 != 2) {
                    // continue/poll; but capture raw for debugging
                    out.put("raw_poll_response_code", getResp.statusCode());
                    out.put("raw_poll_body", getResp.body());
                    Thread.sleep(pollInterval);
                    continue;
                }

                JsonNode getJson = mapper.readTree(getResp.body());
                // The analysis attributes.status may show "completed"
                JsonNode statusNode = getJson.at("/data/attributes/status");
                if (statusNode != null && statusNode.isTextual()) {
                    String status = statusNode.asText();
                    if ("completed".equalsIgnoreCase(status) || "completed".equalsIgnoreCase(status)) {
                        // extract stats if present: data.attributes.stats
                        JsonNode stats = getJson.at("/data/attributes/stats");
                        int malicious = 0, suspicious = 0, harmless = 0, undetected = 0;
                        if (!stats.isMissingNode()) {
                            malicious = stats.path("malicious").asInt(0);
                            suspicious = stats.path("suspicious").asInt(0);
                            harmless = stats.path("harmless").asInt(0);
                            undetected = stats.path("undetected").asInt(0);
                        } else {
                            // Some VT endpoints place verdict at another path; try scanning
                            JsonNode results = getJson.at("/data/attributes/results");
                            if (!results.isMissingNode()) {
                                // fallback try to count malicious entries
                                malicious = (int) results.spliterator().getExactSizeIfKnown(); // fallback
                            }
                        }

                        out.put("analysis_id", analysisId);
                        out.put("malicious", malicious);
                        out.put("suspicious", suspicious);
                        out.put("harmless", harmless);
                        out.put("undetected", undetected);
                        out.put("verdict", (malicious > 0 || suspicious > 0) ? "malicious" : "clean");
                        return out;
                    }
                }

                // not completed yet — wait then retry
                Thread.sleep(pollInterval);
            }

            out.put("error", "VirusTotal polling timed out after " + attempts + " attempts");
            out.put("analysis_id", analysisId);
            return out;

        } catch (Exception e) {
            out.put("error", "Exception: " + e.getMessage());
            return out;
        }
    }
}
