package com.cybersafe.controller;

import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/password-check")
public class PasswordController {

    @PostMapping
    public Map<String, Object> checkPassword(@RequestBody Map<String, String> request) {

        String password = request.get("password");

        int score = 0;

        if (password.length() >= 8) score++;
        if (password.matches(".*[A-Z].*")) score++;
        if (password.matches(".*[a-z].*")) score++;
        if (password.matches(".*\\d.*")) score++;
        if (password.matches(".*[!@#$%^&*()].*")) score++;

        String status =
                (score <= 2) ? "Weak" :
                        (score == 3) ? "Medium" :
                                (score == 4) ? "Strong" :
                                        "Very Strong";

        return Map.of(
                "status", status,
                "score", score,
                "strength", status   // keeps your old field also
        );
    }
}
