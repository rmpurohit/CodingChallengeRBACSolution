package com.globalside.codingchallenge.rbac.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Central security configuration for the Products API.
 *
 * Design choices:
 * Configures HTTP Basic authentication, stateless session management,
 * role-based authorization rules, and JSON responses for security errors.
 *
 * Credentials are stored in memory per the challenge requirements. The storage is
 * hidden behind the UserDetailsService interface, so a database backed or LDAP
 * implementation could replace this bean without touching anything else.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    public static final String ROLE_ADMIN = "ADMIN";
    public static final String ROLE_USER = "USER";

    /**
     * Configures the Spring Security filter chain.
     *
     * The API uses HTTP Basic authentication with stateless sessions.
     * Read operations are available to USER and ADMIN roles, while write
     * operations are restricted to ADMIN users.
     *
     * @param http the HTTP security configuration
     * @param authenticationEntryPoint handler for authentication failures
     * @param accessDeniedHandler handler for authorization failures
     * @return configured security filter chain
     * @throws Exception if security configuration fails
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   RestAuthenticationEntryPoint authenticationEntryPoint,
                                                   RestAccessDeniedHandler accessDeniedHandler) throws Exception {
        return http
                // We have Stateless API with no cookie based session, so CSRF is not needed.
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Read access for every authenticated role.
                        .requestMatchers(HttpMethod.GET, "/products", "/products/*")
                        .hasAnyRole(ROLE_USER, ROLE_ADMIN)
                        // Write access for admins only.
                        .requestMatchers(HttpMethod.POST, "/products").hasRole(ROLE_ADMIN)
                        .requestMatchers(HttpMethod.PUT, "/products/*").hasRole(ROLE_ADMIN)
                        .requestMatchers(HttpMethod.DELETE, "/products/*").hasRole(ROLE_ADMIN)
                        // Fail closed, anything not listed above requires authentication.
                        .anyRequest().authenticated())
                .httpBasic(basic -> basic.authenticationEntryPoint(authenticationEntryPoint))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .build();
    }

    /**
     * Creates the password encoder used for storing user passwords.
     *
     * Uses Spring Security's delegating password encoder which stores the
     * encoding algorithm identifier together with the password hash. This
     * allows changing the hashing algorithm in the future without changing
     * existing stored passwords.
     *
     * @return configured password encoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * Creates the application's user store.
     *
     * The challenge requires credentials to be stored in memory, therefore
     * this implementation uses InMemoryUserDetailsManager.
     *
     * User passwords are encoded using the configured PasswordEncoder and
     * are never stored as plain text.
     *
     * The UserDetailsService abstraction allows replacing this implementation
     * later with database-backed users, LDAP, or an external identity provider
     * without changing the authorization configuration.
     *
     * @param passwordEncoder encoder used to hash user passwords
     * @return user details service containing application users
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.withUsername("user")
                .password(passwordEncoder.encode("userPass"))
                .roles(ROLE_USER)
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder.encode("adminPass"))
                .roles(ROLE_ADMIN)
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }
}