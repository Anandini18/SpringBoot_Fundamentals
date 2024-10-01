package com.springsecurity.demo.jwt;

import io.jsonwebtoken.ExpiredJwtException; // Exception thrown when JWT token has expired
import io.jsonwebtoken.Jwts; // The main class used for creating and parsing JWTs
import io.jsonwebtoken.MalformedJwtException; // Exception thrown when JWT token structure is incorrect
import io.jsonwebtoken.UnsupportedJwtException; // Exception thrown when JWT token is in an unsupported format
import io.jsonwebtoken.io.Decoders; // Utility class for decoding data, in this case for decoding Base64 strings
import io.jsonwebtoken.security.Keys; // Utility class to generate a cryptographic key
import jakarta.servlet.http.HttpServletRequest; // Interface to access HTTP request information
import org.slf4j.Logger; // Interface for logging messages for debugging purposes
import org.slf4j.LoggerFactory; // Factory to create Logger instances
import org.springframework.beans.factory.annotation.Value; // Annotation used to inject properties from configuration files
import org.springframework.security.core.userdetails.UserDetails; // Interface to represent a user in the security system
import org.springframework.stereotype.Component; // Annotation to denote a Spring-managed component (bean)
import javax.crypto.SecretKey; // Interface representing a secret key in cryptography
import java.security.Key; // Interface representing a general cryptographic key
import java.util.Date; // Class to manage date and time values

@Component // This class is managed by Spring's Dependency Injection Container
// This class JwtUtils provides utility methods to generate, extract, and validate JWT tokens in a Spring Security-based application. It uses the io.jsonwebtoken library for working with JWTs.
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class); // Logger instance for logging errors, debug info, etc.

    @Value("${spring.app.jwtSecret}") // Injecting the JWT secret from application.properties
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}") // Injecting JWT expiration time in milliseconds from application.properties
    private int jwtExpirationMs;

    // This method extracts the JWT token from the Authorization header in the HTTP request
    public String getJwtFromHeader(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization"); // Retrieve the Authorization header
        logger.debug("Authorization Header: {}",bearerToken); // Log the header for debugging
        if(bearerToken!=null && bearerToken.startsWith("Bearer ")){ // Check if the token starts with "Bearer "
            return bearerToken.substring(7); // Return the token without the "Bearer " prefix
        }
        return null; // If the token is missing or doesn't start with "Bearer", return null
    }

    // This method generates a JWT token using the user's username and expiration time
    public String generateTokenFromUsername(UserDetails userDetails){
        String username = userDetails.getUsername(); // Get the username from the UserDetails object
        return Jwts.builder() // Build the JWT token
                .subject(username) // Set the username as the subject
                .issuedAt(new Date()) // Set the current date as the issued date
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs)) // Set the expiration date based on the jwtExpirationMs value
                .signWith(key()) // Sign the token using a cryptographic key
                .compact(); // Generate and return the JWT token as a String
    }

    // This method retrieves the username from the JWT token
    public String getUserNameFromJwtToken(String token){
        return Jwts.parser() // Create a JWT parser instance
                .verifyWith((SecretKey) key()) // Verify the signature using the secret key
                .build() // Build the parser
                .parseSignedClaims(token) // Parse the JWT token and extract the claims
                .getPayload() // Get the payload (the claims)
                .getSubject(); // Return the subject, which is the username
    }

    // This method creates the cryptographic key used to sign and verify the JWT token
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret)); // Decode the Base64-encoded secret key and create a cryptographic key
    }

    // This method validates the JWT token
    public boolean validateJwtToken(String authToken){
        try {
            Jwts.parser() // Create a JWT parser instance
                    .verifyWith((SecretKey) key()) // Verify the signature using the secret key
                    .build() // Build the parser
                    .parseSignedClaims(authToken); // Parse the token to check if it is valid
            return true; // If no exceptions are thrown, the token is valid
        } catch (MalformedJwtException e) { // Catch an exception for an invalid JWT structure
            logger.error("Invalid JWT token: {}", e.getMessage()); // Log the error message
        } catch (ExpiredJwtException e) { // Catch an exception when the JWT has expired
            logger.error("JWT token is expired: {}", e.getMessage()); // Log the error message
        } catch (UnsupportedJwtException e) { // Catch an exception when the JWT is unsupported
            logger.error("JWT token is unsupported: {}", e.getMessage()); // Log the error message
        } catch (IllegalArgumentException e) { // Catch an exception for an empty JWT claims string
            logger.error("JWT claims string is empty: {}", e.getMessage()); // Log the error message
        }

        return false; // If any exception is caught, return false indicating the token is invalid
    }
}
