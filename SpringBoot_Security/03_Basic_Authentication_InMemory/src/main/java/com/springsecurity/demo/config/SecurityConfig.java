package com.springsecurity.demo.config;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        // http.formLogin(withDefaults());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.httpBasic(withDefaults());
        return http.build();
    }

    /*
      UserDetailsService
      - It is an interface of Spring Security used to retrieve user-related data.
      - It has a single method, loadUserByUsername(String username), which is used to look up user details by their username.

      InMemory Authentication
      - This means user details (username, password, roles, etc.) are stored in the application’s memory, not in an external database.

      InMemoryUserDetailsManage
      - This is the implementation of "UserDetailsService" interface.
      - Manages user details in application memory.

      UserDetails
      - Interface, helps to pass the core user info to the InMemoryUserDetailsManager

      "{noop} password1"
      - Prefix, tells that this password "password1" shld be saved as plain text.
     */


    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 = User.withUsername("user1")
                .password("{noop}password1")
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password("{noop}adminPass")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user1,admin);
    }

}
