package com.cybersafe.controller;

import com.cybersafe.service.PhishingListService;
import com.cybersafe.service.VirusTotalService;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/phish-check")
public class PhishingController {

    private final PhishingListService phishingListService;
    private final VirusTotalService virusTotalService;

    public PhishingController(PhishingListService phishingListService, VirusTotalService virusTotalService) {
        this.phishingListService = phishingListService;
        this.virusTotalService = virusTotalService;
    }

    private static final List<String> KEYWORDS = List.of(
            "free","offer","login","verify","secure","update","password","bank","gift",
            "congratulations","urgent","click here","limited","account","restricted",
            "discount","deal","sale","reward","bonus","cashback","coupon","win","winner",
            "prize","jackpot","lottery","claim now","redeem","limited time","exclusive offer",
            "special offer","act now","free trial","zero cost","security alert","reset password",
            "suspended","locked","unauthorized","identity","authentication","otp","confirm","validate",
            "kyc","credit","debit","loan","investment","fund","transaction","payment failed","billing",
            "refund","tax","invoice","financial","wallet","upi","pan","important","immediately",
            "attention","warning","alert","action required","final notice","last chance","expire soon",
            "deadline","risk","critical","tap here","visit link","open link","download","install",
            "access","continue","proceed","unsubscribe","opt-out","package","shipment","delivery failed",
            "tracking","order update","courier","parcel","reschedule","subscribe","exclusive","upgrade",
            "best price","offer ends soon","ieccet.edu.in"
    );

    @PostMapping
    public Map<String, Object> checkUrl(@RequestBody Map<String, String> request) {
        String raw = Optional.ofNullable(request.get("url")).orElse("").trim();
        String urlLower = raw.toLowerCase();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("url", raw);

        // 1. keyword matches
        List<String> matchedKeywords = new ArrayList<>();
        for (String k : KEYWORDS) if (urlLower.contains(k)) matchedKeywords.add(k);

        // 2. real-time reported list (match domain substring)
        boolean reported = phishingListService.getRealTimeList().stream()
                .anyMatch(urlLower::contains);

        // build reasons
        List<String> reasons = new ArrayList<>();
        if (!matchedKeywords.isEmpty()) reasons.add("keywords: " + String.join(", ", matchedKeywords));
        if (reported) reasons.add("reported in real-time feeds");

        // 3. If neither matched and VirusTotal is enabled, call VirusTotal
        Map<String, Object> vt = null;
        if (!reported && matchedKeywords.isEmpty() && virusTotalService.isEnabled()) {
            vt = virusTotalService.scanUrl(raw);
            // if vt says malicious or suspicious, add to reasons
            if (vt != null && vt.containsKey("verdict")) {
                String verdict = vt.getOrDefault("verdict","").toString();
                if ("malicious".equalsIgnoreCase(verdict) || vt.getOrDefault("malicious",0).toString().equals("0")==false) {
                    reasons.add("virusTotal: " + verdict);
                }
            } else if (vt != null && vt.containsKey("malicious")) {
                Object m = vt.get("malicious");
                if (m instanceof Integer && ((Integer)m) > 0) reasons.add("virusTotal: malicious count " + m.toString());
            } else if (vt != null && vt.containsKey("error")) {
                reasons.add("virusTotal_error: " + vt.get("error"));
            }
        } else if (!virusTotalService.isEnabled()) {
            reasons.add("virusTotal: not configured");
        }

        // determine status
        String status;
        if (reported) status = "⚠ Reported phishing (Checked On Internet Found Phishing Reported!!)";
        else if (!matchedKeywords.isEmpty()) status = "⚠ Suspicious (Do Not Visit)";
        else if (vt != null && "malicious".equalsIgnoreCase(String.valueOf(vt.getOrDefault("verdict","")))) status = "⚠ VirusTotal: malicious";
        else status = "✔ Safe (no issues found , Go Ahead!!)";

        result.put("status", status);
        if (!reasons.isEmpty()) result.put("reasons", reasons);
        if (vt != null) result.put("virusTotal", vt);

        return result;
    }
}
