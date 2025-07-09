package com.example.authsystem.entity;

public enum Role {
    USER("User"),
    ADMIN("Administrator");

    private final String displayName;

    Role(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    // JDK 21 Pattern matching for role hierarchy
    public boolean hasPermission(String permission) {
        return switch (this) {
            case ADMIN ->
                true; // Admin has all permissions
            case USER ->
                switch (permission) {
                    case "READ_PROFILE", "UPDATE_PROFILE" ->
                        true;
                    default ->
                        false;
                };
        };
    }
}
