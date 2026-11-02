package com.mazen.security.config;

import com.mazen.security.enums.Role;
import com.mazen.security.filters.JwtAuthenticationFilter;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@AllArgsConstructor
@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // enables @PreAuthorize on controllers
public class SecurityConfig {

    private static final String API = "/api/v1";

    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config
    ) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        var provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .sessionManagement(c ->
                        c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(c -> c

                        // ---------- AUTH (public) ----------
                        .requestMatchers(HttpMethod.POST, API + "/auth/register").permitAll()
                        .requestMatchers(HttpMethod.POST, API + "/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, API + "/auth/refresh").permitAll()

                        // ---------- EVENTS ----------
                        .requestMatchers(HttpMethod.GET,   API + "/events").permitAll()
                        .requestMatchers(HttpMethod.GET,   API + "/events/{id}").permitAll()
                        .requestMatchers(HttpMethod.GET,   API + "/events/my").hasRole(Role.organizer.name())
                        .requestMatchers(HttpMethod.POST,  API + "/events").hasRole(Role.organizer.name())
                        .requestMatchers(HttpMethod.PUT,   API + "/events/{id}").hasRole(Role.organizer.name())
                        .requestMatchers(HttpMethod.PATCH, API + "/events/{id}/publish").hasRole(Role.organizer.name())
                        .requestMatchers(HttpMethod.PATCH, API + "/events/{id}/cancel").hasRole(Role.organizer.name())

                        // ---------- VENUES ----------
                        .requestMatchers(HttpMethod.GET,    API + "/venues").permitAll()
                        .requestMatchers(HttpMethod.GET,    API + "/venues/{id}").permitAll()
                        .requestMatchers(HttpMethod.POST,   API + "/venues").hasRole(Role.organizer.name())
                        .requestMatchers(HttpMethod.PUT,    API + "/venues/{id}").hasRole(Role.organizer.name())
                        .requestMatchers(HttpMethod.DELETE, API + "/venues/{id}").hasRole(Role.admin.name())

                        // ---------- SEATS ----------
                        .requestMatchers(HttpMethod.GET, API + "/events/{eventId}/seats")
                        .hasAnyRole(Role.customer.name(), Role.organizer.name())
                        .requestMatchers(HttpMethod.GET, API + "/events/{eventId}/seats/available")
                        .hasAnyRole(Role.customer.name(), Role.organizer.name())

                        // ---------- RESERVATIONS ----------
                        .requestMatchers(HttpMethod.POST,  API + "/reservations").hasRole(Role.customer.name())
                        .requestMatchers(HttpMethod.GET,   API + "/reservations/my").hasRole(Role.customer.name())
                        .requestMatchers(HttpMethod.GET,   API + "/reservations/{id}").hasRole(Role.customer.name())
                        .requestMatchers(HttpMethod.PATCH, API + "/reservations/{id}/cancel").hasRole(Role.admin.name())

                        // ---------- PAYMENTS ----------
                        .requestMatchers(HttpMethod.POST, API + "/reservations/{reservationId}/payment")
                        .hasRole(Role.customer.name())

                        // ---------- ORGANIZER ----------
                        .requestMatchers(HttpMethod.GET, API + "/events/{eventId}/sales-summary")
                        .hasRole(Role.organizer.name())
                        .requestMatchers(HttpMethod.GET, API + "/organizer/sales")
                        .hasRole(Role.organizer.name())

                        // ---------- ADMIN ----------
                        .requestMatchers(API + "/admin/**").hasRole(Role.admin.name())

                        // ---------- fallback ----------
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(c -> {
                    c.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
                    c.accessDeniedHandler((request, response, ex) ->
                            response.setStatus(HttpStatus.FORBIDDEN.value()));
                });

        return http.build();
    }
}
