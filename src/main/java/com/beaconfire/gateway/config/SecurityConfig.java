package com.beaconfire.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
@Slf4j
public class SecurityConfig {

    @Value("${app.originsUrl}")
    private String originsUrl;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf().disable()
                .cors().configurationSource(corsConfigurationSource())
                .and()
                .authorizeExchange()
                .pathMatchers("/actuator/**").permitAll()
                .pathMatchers("/webjars/**").permitAll()
                .pathMatchers("/favicon.ico").permitAll()
                .pathMatchers(
                        "/api/employee/openapi/**",
                        "/api/email/openapi/**",
                        "/api/application/openapi/**",
                        "/api/housing/openapi/**",
                        "/api/composite/openapi/**",
                        "/openapi/api-docs",
                        "/openapi/api-docs/swagger-config",
                        "/api/employee/actuator/**",
                        "/api/email/actuator/**",
                        "/api/application/actuator/**",
                        "/api/housing/actuator/**",
                        "/api/composite/actuator/**",
                        "/api/employee/swagger-ui/**",
                        "/api/email/swagger-ui/**",
                        "/api/application/swagger-ui/**",
                        "/api/housing/swagger-ui/**",
                        "/api/composite/swagger-ui/**"
                ).permitAll()
                .anyExchange().authenticated()
                .and()
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter()))
                .and()
                .and()
                .build();
    }

    private Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        return jwt -> {
            log.info("jwt authentication: {}", jwt.getClaims());
            List<String> roles = jwt.getClaimAsStringList("roles");
            Collection<GrantedAuthority> authorities = roles != null
                    ? roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
                    : Collections.emptyList();

            return new UsernamePasswordAuthenticationToken(jwt.getClaims(), "n/a", authorities);
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Collections.singletonList(originsUrl));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Collections.singletonList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder(@Value("${spring.security.oauth2.resourceserver.jwt.secret}") String secret) {
        byte[] decodedSecret = java.util.Base64.getDecoder().decode(secret);
        SecretKeySpec secretKey = new SecretKeySpec(decodedSecret, "HmacSHA256");
        return NimbusReactiveJwtDecoder.withSecretKey(secretKey).build();
    }
}
