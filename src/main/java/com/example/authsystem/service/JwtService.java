package com.example.authsystem.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secretKey;

    @Value("${app.jwt.expiration}")
    private long jwtExpiration;

    @Value("${app.jwt.refresh-expiration}")
    private long refreshExpiration;

    // JDK 21 Pattern matching for token type
    public sealed interface TokenType permits AccessToken, RefreshToken {
    }

    public record AccessToken() implements TokenType {
    }

    public record RefreshToken() implements TokenType {
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Enhanced token generation with JDK 21 features
    public String generateToken(UserDetails userDetails, TokenType tokenType) {
        return generateToken(new HashMap<>(), userDetails, tokenType);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails, TokenType tokenType) {
        var expiration = switch (tokenType) {
            case AccessToken() ->
                jwtExpiration;
            case RefreshToken() ->
                refreshExpiration;
        };

        return buildToken(extraClaims, userDetails, expiration, tokenType);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration,
            TokenType tokenType
    ) {
        var now = Instant.now();
        var expirationTime = now.plus(expiration, ChronoUnit.MILLIS);

        var claimsBuilder = Jwts.claims()
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expirationTime));

        // Add token type to claims
        claimsBuilder.add("token_type", switch (tokenType) {
            case AccessToken() ->
                "access";
            case RefreshToken() ->
                "refresh";
        });

        // Add extra claims
        extraClaims.forEach(claimsBuilder::add);

        return Jwts.builder()
                .claims(claimsBuilder.build())
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    public boolean isRefreshToken(String token) {
        try {
            String tokenType = extractClaim(token, claims -> claims.get("token_type", String.class));
            return "refresh".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = secretKey.getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // JDK 21 Pattern matching for token validation result
    public sealed interface TokenValidationResult permits Valid, Invalid, Expired {
    }

    public record Valid(String username) implements TokenValidationResult {

    }

    public record Invalid(String reason) implements TokenValidationResult {

    }

    public record Expired(String username) implements TokenValidationResult {

    }

    public TokenValidationResult validateToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            String username = claims.getSubject();

            if (claims.getExpiration().before(new Date())) {
                return new Expired(username);
            }

            return new Valid(username);
        } catch (Exception e) {
            return new Invalid(e.getMessage());
        }
    }
}
