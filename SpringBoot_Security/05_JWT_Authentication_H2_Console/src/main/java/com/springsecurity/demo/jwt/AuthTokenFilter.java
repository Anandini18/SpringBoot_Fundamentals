package com.springsecurity.demo.jwt;

import jakarta.servlet.FilterChain; // Interface that allows filtering HTTP requests as part of a chain of filters
import jakarta.servlet.ServletException; // Exception thrown by the servlet for issues with request handling
import jakarta.servlet.http.HttpServletRequest; // Provides information about an HTTP request
import jakarta.servlet.http.HttpServletResponse; // Provides information about an HTTP response
import org.slf4j.Logger; // Interface for logging messages for debugging purposes
import org.slf4j.LoggerFactory; // Factory to create Logger instances
import org.springframework.beans.factory.annotation.Autowired; // Annotation to inject dependencies managed by Spring
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken; // Represents an authentication request with username and password
import org.springframework.security.core.context.SecurityContextHolder; // Provides access to the security context which holds authentication info
import org.springframework.security.core.userdetails.UserDetails; // Interface that represents a user in the security system
import org.springframework.security.core.userdetails.UserDetailsService; // Interface to load user-specific data
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource; // Builds authentication details from an HTTP request
import org.springframework.stereotype.Component; // Marks this class as a Spring-managed component (bean)
import org.springframework.web.filter.OncePerRequestFilter; // Ensures a single execution of the filter per request

import java.io.IOException; // Exception thrown when an I/O error occurs

@Component // This class is managed by Spring's Dependency Injection Container
// This filter is responsible for handling JWT-based authentication. It checks every HTTP request for a valid JWT token and, if valid, authenticates the user by setting the SecurityContext.OncePerRequestFilter: Ensures the filter is executed only once per request, avoiding multiple authentication attempts on a single request.
public class AuthTokenFilter extends OncePerRequestFilter { // A filter that executes once per request to authenticate JWT tokens

    @Autowired
    private JwtUtils jwtUtils; // Injecting the JwtUtils class for JWT-related operations

    @Autowired
    private UserDetailsService userDetailsService; // Injecting UserDetailsService to load user information from the database

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class); // Logger instance for logging errors and debug information

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI()); // Log the current request URI for debugging

        try {
            String jwt = parseJwt(request); // Extract the JWT token from the request header
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) { // Check if the JWT token exists and is valid
                String username = jwtUtils.getUserNameFromJwtToken(jwt); // Extract the username from the valid JWT token
                UserDetails userDetails = userDetailsService.loadUserByUsername(username); // Load the user details from the database using the username

                // Create an authentication token with the user's details and their authorities (roles)
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                logger.debug("Roles from JWT: {}", userDetails.getAuthorities()); // Log the user's roles (authorities) for debugging

                // Set additional details from the current request
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authentication token in the security context for the current session/request
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e); // Log any exceptions that occur during the authentication process
        }

        // Continue with the remaining filters in the filter chain
        filterChain.doFilter(request, response);
    }

    // Method to parse the JWT from the Authorization header in the HTTP request
    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request); // Use JwtUtils to extract the JWT token from the request
        logger.debug("AuthTokenFilter.java: {}", jwt); // Log the JWT token for debugging
        return jwt; // Return the extracted JWT token
    }
}
