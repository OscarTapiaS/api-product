package com.product.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.product.config.jwt.JwtAuthFilter;

@Configuration
@EnableWebSecurity 
public class SecurityConfig {

    @Autowired
    private JwtAuthFilter jwtFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, CorsConfig corsConfig) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(
                auth -> auth
                .requestMatchers("/error", "/swagger-ui/**","/swagger-ui.html", "/v3/api-docs/**", "/actuator/info", "/actuator/health").permitAll()
                
                // CATEGORY
                .requestMatchers(HttpMethod.GET, "/category").permitAll()
                .requestMatchers(HttpMethod.GET, "/category/active").hasAnyAuthority("ADMIN", "CUSTOMER")
                .requestMatchers("/category/**").hasAuthority("ADMIN") 
                
                // PRODUCT
                .requestMatchers(HttpMethod.GET, "/product").hasAnyAuthority("ADMIN", "CUSTOMER")
                .requestMatchers(HttpMethod.GET, "/product/{id}").hasAnyAuthority("ADMIN", "CUSTOMER") 
                .requestMatchers(HttpMethod.POST, "/product").hasAuthority("ADMIN")              
                .requestMatchers(HttpMethod.DELETE, "/product/{id}").hasAuthority("ADMIN")
                .requestMatchers(HttpMethod.PATCH, "/product/{id}/enable").hasAuthority("ADMIN")
                .requestMatchers(HttpMethod.PATCH, "/product/{id}/disable").hasAuthority("ADMIN")
                
                // PRODUCT IMAGES
                .requestMatchers(HttpMethod.POST, "/product/{id}/image").hasAuthority("ADMIN")
                .requestMatchers(HttpMethod.GET, "/product/{id}/image").hasAuthority("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/product/{id}/image/{product_image_id}").hasAuthority("ADMIN")
                
                
                .anyRequest().authenticated()
                )
        .cors(cors -> cors.configurationSource(corsConfig))
        .httpBasic(AbstractHttpConfigurer::disable)
        .formLogin(form -> form.disable())
        .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}