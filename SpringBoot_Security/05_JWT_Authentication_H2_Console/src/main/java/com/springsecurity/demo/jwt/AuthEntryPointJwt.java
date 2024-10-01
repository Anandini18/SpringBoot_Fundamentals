package com.springsecurity.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper; // Class for converting Java objects into JSON and vice versa
import jakarta.servlet.ServletException; // Exception thrown for issues during servlet processing
import jakarta.servlet.http.HttpServletRequest; // Interface providing details of the HTTP request
import jakarta.servlet.http.HttpServletResponse; // Interface providing details of the HTTP response
import org.slf4j.Logger; // Interface for logging messages for debugging and error tracking
import org.slf4j.LoggerFactory; // Factory to create Logger instances
import org.springframework.http.MediaType; // Constants for media (MIME) types, e.g., application/json
import org.springframework.security.core.AuthenticationException; // Exception for handling authentication issues
import org.springframework.security.web.AuthenticationEntryPoint; // Interface for handling unauthorized access
import org.springframework.stereotype.Component;

import java.io.IOException; // Exception for handling input/output operations
import java.util.HashMap; // Implementation of a map (key-value pairs) using hash table
import java.util.Map; // Interface for a collection of key-value pairs

//  This class implements the AuthenticationEntryPoint interface, which is used to handle unauthorized access in Spring Security. When an unauthenticated user tries to access a protected resource, the commence method is invoked to return an appropriate error response.
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint { // This class handles unauthorized access attempts

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class); // Logger for logging errors and info

    // The commence method is triggered whenever an unauthenticated user tries to access a secured resource
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        logger.error("Unauthorized error: {}", authException.getMessage()); // Log the unauthorized access error
        System.out.println(authException); // Print the exception message for additional debugging

        // Set the response content type to JSON and HTTP status to 401 Unauthorized
        response.setContentType(MediaType.APPLICATION_JSON_VALUE); // Set content type as application/json
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // Set HTTP status code to 401 (Unauthorized)

        // Create a response body with details of the error (status, error type, message, and the request path)
        final Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED); // Set the HTTP status code
        body.put("error", "Unauthorized"); // Set a general error description
        body.put("message", authException.getMessage()); // Set the exception message (why the authentication failed)
        body.put("path", request.getServletPath()); // Include the requested path to show where the error occurred

        // Convert the body map to a JSON response and write it to the output stream
        final ObjectMapper mapper = new ObjectMapper(); // ObjectMapper to convert Java objects to JSON
        mapper.writeValue(response.getOutputStream(), body); // Write the body map as JSON to the response output stream
    }
}
