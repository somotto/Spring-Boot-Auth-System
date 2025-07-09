package com.example.authsystem.service;

import com.example.authsystem.dto.AuthRequest;
import com.example.authsystem.dto.AuthResponse;
import com.example.authsystem.dto.LoginRequest;
import com.example.authsystem.dto.SignUpRequest;
import com.example.authsystem.entity.User;
import com.example.authsystem.exception.EmailAlreadyExistsException;
import com.example.authsystem.exception.InvalidTokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Service
@Transactional
public class AuthService {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    
    public AuthService(
            UserService userService,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            AuthenticationManager authenticationManager
    ) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }
    
    public AuthResponse authenticate(AuthRequest request) {
        return switch (request) {
            case SignUpRequest signUpReq -> signUp(signUpReq);
            case LoginRequest loginReq -> login(loginReq);
        };
    }
    
    private AuthResponse signUp(SignUpRequest request) {
        logger.info("Attempting to register user with email: {}", request.email());
        
        if (userService.existsByEmail(request.email())) {
            throw new EmailAlreadyExistsException(STR."Email already exists: \{request.email()}");
        }
        
        var user = new User(
                request.firstName(),
                request.lastName(),
                request.email(),
                passwordEncoder.encode(request.password())
        );
        
        User savedUser = userService.save(user);
        
        // Generate tokens
        var accessToken = jwtService.generateToken(savedUser, new JwtService.AccessToken());
        var refreshToken = jwtService.generateToken(savedUser, new JwtService.RefreshToken());
        
        var userInfo = new AuthResponse.UserInfo(
                savedUser.getId(),
                savedUser.getFirstName(),
                savedUser.getLastName(),
                savedUser.getEmail(),
                savedUser.getRole().name()
        );
        
        logger.info("Successfully registered user: {}", savedUser.getEmail());
        
        return AuthResponse.success(
                accessToken,
                refreshToken,
                Duration.ofMillis(86400000).toSeconds(), // 24 hours
                userInfo
        );
    }
    
    private AuthResponse login(LoginRequest request) {
        logger.info("Attempting to authenticate user: {}", request.email());
        
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );
        
        User user = userService.findByEmail(request.email())
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        // Update last login
        user.updateLastLogin();
        userService.save(user);
        
        // Add custom claims
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole().name());
        claims.put("fullName", user.getFullName());
        
        var accessToken = jwtService.generateToken(claims, user, new JwtService.AccessToken());
        var refreshToken = jwtService.generateToken(user, new JwtService.RefreshToken());
        
        var userInfo = new AuthResponse.UserInfo(
                user.getId(),
                user.getFirstName(),
                user.getLastName(),
                user.getEmail(),
                user.getRole().name()
        );
        
        logger.info("Successfully authenticated user: {}", user.getEmail());
        
        return AuthResponse.success(
                accessToken,
                refreshToken,
                Duration.ofMillis(86400000).toSeconds(),
                userInfo
        );
    }
    
    public AuthResponse refreshToken(String refreshToken) {
        logger.info("Attempting to refresh token");
        
        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new InvalidTokenException("Invalid refresh token");
        }
        
        // JDK 21 Pattern matching for token validation
        return switch (jwtService.validateToken(refreshToken)) {
            case JwtService.Valid(String userEmail) -> {
                User user = userService.findByEmail(userEmail)
                        .orElseThrow(() -> new RuntimeException("User not found"));
                
                var newAccessToken = jwtService.generateToken(user, new JwtService.AccessToken());
                var newRefreshToken = jwtService.generateToken(user, new JwtService.RefreshToken());
                
                var userInfo = new AuthResponse.UserInfo(
                        user.getId(),
                        user.getFirstName(),
                        user.getLastName(),
                        user.getEmail(),
                        user.getRole().name()
                );
                
                logger.info("Successfully refreshed token for user: {}", userEmail);
                
                yield AuthResponse.success(
                        newAccessToken,
                        newRefreshToken,
                        Duration.ofMillis(86400000).toSeconds(),
                        userInfo
                );
            }
            case JwtService.Expired(String userEmail) -> {
                logger.warn("Refresh token expired for user: {}", userEmail);
                throw new InvalidTokenException("Refresh token expired");
            }
            case JwtService.Invalid(String reason) -> {
                logger.warn("Invalid refresh token: {}", reason);
                throw new InvalidTokenException("Invalid refresh token");
            }
        };
    }
}