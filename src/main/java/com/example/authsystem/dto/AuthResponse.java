package com.example.authsystem.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthResponse(
    String accessToken,
    String refreshToken,
    String tokenType,
    Long expiresIn,
    String message,
    UserInfo userInfo,
    LocalDateTime timestamp
) {
    
    // Factory methods for different response types
    public static AuthResponse success(String accessToken, String refreshToken, Long expiresIn, UserInfo userInfo) {
        return new AuthResponse(
            accessToken,
            refreshToken,
            "Bearer",
            expiresIn,
            "Authentication successful",
            userInfo,
            LocalDateTime.now()
        );
    }
    
    public static AuthResponse error(String message) {
        return new AuthResponse(
            null,
            null,
            null,
            null,
            message,
            null,
            LocalDateTime.now()
        );
    }
    
    // Nested record for user information
    public record UserInfo(
        Long id,
        String firstName,
        String lastName,
        String email,
        String role
    ) {
        public String fullName() {
            return STR."\{firstName} \{lastName}";
        }
    }
}