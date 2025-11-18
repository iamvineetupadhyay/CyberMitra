package com.cybersafe;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class CybersafeApplication {
    public static void main(String[] args) {
        SpringApplication.run(CybersafeApplication.class, args);
        System.out.println("🚀 CyberSafe Backend is running...");
    }
}
