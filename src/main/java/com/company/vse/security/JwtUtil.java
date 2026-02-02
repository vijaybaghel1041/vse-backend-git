package com.company.vse.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

/**
 * JwtUtil is a helper/utility class.
 * It handles all JWT-related operations:
 * - Token creation
 * - Token validation
 * - Reading data from token
 */
@Component
public class JwtUtil {

    // Secret key used to sign JWT
    // (Must be same while generating & validating token)
    private static final String SECRET =
            "mysecretkeymysecretkeymysecretkeymysecretkey";

    // Token validity time (1 hour)
    private static final long EXPIRATION_TIME = 60 * 60 * 1000;

    // Create signing key using secret
    private final Key key = Keys.hmacShaKeyFor(SECRET.getBytes());

    /**
     * Called from AuthController after successful login
     */
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)                // store username inside token
                .setIssuedAt(new Date())              // token creation time
                .setExpiration(
                        new Date(System.currentTimeMillis() + EXPIRATION_TIME)
                )
                .signWith(key, SignatureAlgorithm.HS256) // sign token
                .compact();
    }

    /**
     * Called from JwtAuthFilter
     * Used to read username from token
     */
    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * Called from JwtAuthFilter
     * Checks if token is valid or expired
     */
    public boolean isTokenValid(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // Internal method to parse token
    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
