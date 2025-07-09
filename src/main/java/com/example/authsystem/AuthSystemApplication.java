package com.example.authsystem;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class AuthSystemApplication {

    public static void main(String[] args) {
        // Enable virtual threads for better performance
        System.setProperty("spring.threads.virtual.enabled", "true");
        SpringApplication.run(AuthSystemApplication.class, args);
    }
}
