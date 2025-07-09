package com.example.authsystem.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

// JDK 21 Record for immutable DTOs
public sealed interface AuthRequest permits SignUpRequest, LoginRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    String email();

    @NotBlank(message = "Password is required")
    String password();
}

public record SignUpRequest(
        @NotBlank(message = "First name is required")
        @Size(max = 50, message = "First name must be less than 50 characters")
        String firstName,
        @NotBlank(message = "Last name is required")
        @Size(max = 50, message = "Last name must be less than 50 characters")
        String lastName,
        @NotBlank(message = "Email is required")
        @Email(message = "Email should be valid")
        @Size(max = 100, message = "Email must be less than 100 characters")
        String email,
        @NotBlank(message = "Password is required")
        @Size(min = 6, max = 100, message = "Password must be between 6 and 100 characters")
        String password
        ) implements AuthRequest {

    // Custom validation method using JDK 21 features
    public boolean isValid() {
        return firstName != null && !firstName.isBlank()
                && lastName != null && !lastName.isBlank()
                && email != null && email.contains("@")
                && password != null && password.length() >= 6;
    }

    // Full name using string templates
    public String fullName() {
        return STR.



    "\{firstName} \{lastName}";
    }
}

public record LoginRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email should be valid")
        String email,
        @NotBlank(message = "Password is required")
        String password
        ) implements AuthRequest {

}
