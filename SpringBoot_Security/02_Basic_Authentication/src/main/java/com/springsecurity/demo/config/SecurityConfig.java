package com.springsecurity.demo.config;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

/*
Configuration - Tells spring that this class provides configuration to the application context
EnableWebSecurity - Tells spring boot to enable security features in the application, using this we can customize the security configuration
SecurityFilterChain -  Must be a bean.
withDefautls() - enable security with the default settings

Difference b/w form and basic authentication
- When using form-based login in Spring Boot, the login details are handled automatically, so we don't need to send extra data (payload). However, with custom authentication, we have to manually manage and send the data (payload) needed for login.
- PayLoad : In the context of authentication, payload refers to the data sent during a login attempt. For example, in custom authentication, this includes the username and password that are sent from the client to the server to verify the user's identity.

In headers, we can see "Authentication" header as, Authorization: Basic YWRtaW46MTIzNA==
- The pass & username is encoded in some value as Authentication obj, & passed in this header for checking.
- This is encoded in base64.
- username:password -> admin:1234 -> Encoded in base 64 -> Will become the Authentication Header

*/

// Making our own custom security config filter
@Configuration // configuration class for security
@EnableWebSecurity // specifying that security is being enabled here
public class SecurityConfig {

    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // All the requests must be authenticated
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        // If we don't use form-login then, the credentials will be taken in popup
        // If we don't use formLogin, then logout functionality will also not work.
        // For logout, we just have to close the session, by closing the tab.
        // http.formLogin(withDefaults());

        // This will make our request STATELESS
        // If we add this line, no cookies will be available for our requests
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.httpBasic(withDefaults());
        return http.build();
    }

}
