package com.springsecurity.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

/*
Drawbacks of Basic Auth :
- No advance features like expiration time.
- Can be decoded easily.
- Shld go for "Custom token system".
 */

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    // Automatically set ups the dataSource bean, coz of Jpa added in pom.xml
    @Autowired
    DataSource dataSource;

    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                // This can be used to ignore the authentication form that appears before h2-console
                .requestMatchers("/h2-console/**").permitAll() // This will allow all the endpts that matches with the given pattern
                .anyRequest().authenticated());
        // http.formLogin(withDefaults());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.httpBasic(withDefaults());

        // We are allowing the headers from the same origin
        // Means that the page can only be framed by another page on the same origin (i.e., the same domain). This is a security measure to prevent clickjacking attacks.
        http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

        // This line disables Cross-Site Request Forgery (CSRF) protection.
        http.csrf(csrf -> csrf.disable());
        return http.build();
    }

    /*
      - For creating the schema : Go to "Spring Security Github" -> Search "users.ddl" -> 3 lines of code :
        create table users(username varchar_ignorecase(50) not null primary key,password varchar_ignorecase(500) not null,enabled boolean not null);
        create table authorities (username varchar_ignorecase(50) not null,authority varchar_ignorecase(50) not null,constraint fk_authorities_users foreign key(username) references users(username));
        create unique index ix_auth_username on authorities (username,authority);
      - Now make a new file : "schema.sql", then paste these 3 lines .
     */

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user1")
                // here we used the passwordEncoder obj to encode our password
                // due to this, password is not readable anymore!
                .password(passwordEncoder().encode("password1"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder().encode("adminPass"))
                .roles("ADMIN")
                .build();

        // Create a new JdbcUserDetailsManager object, which manages user details using a JDBC data source.
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);

        // Add a user (user1) to the database using the userDetailsManager.
        userDetailsManager.createUser(user1);

        // Add an admin user (admin) to the database using the userDetailsManager.
        userDetailsManager.createUser(admin);

        // Return the userDetailsManager object.
        return userDetailsManager;

    }

    /*
      - Spring Security relies on a PasswordEncoder to compare user-entered passwords with the stored hashed passwords during authentication.
      - Passwords should never be stored in plaintext. Using BCryptPasswordEncoder ensures that passwords are securely hashed before being stored in the database.
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        // Create and return a new instance of BCryptPasswordEncoder, which is an implementation of PasswordEncoder.
        // BCryptPasswordEncoder is used to hash passwords using the BCrypt hashing algorithm, which is strong and secure.
        return new BCryptPasswordEncoder();
    }

}
