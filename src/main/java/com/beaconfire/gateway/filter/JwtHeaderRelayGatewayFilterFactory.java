package com.beaconfire.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class JwtHeaderRelayGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> {

    public JwtHeaderRelayGatewayFilterFactory() {
        super(Object.class);
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            // Check if the request path is for actuator or openapi endpoints that should bypass JWT processing
            String path = exchange.getRequest().getPath().value();
            if (path.contains("/actuator/") || path.contains("/openapi/") || path.contains("/swagger-ui/")) {
                log.info("Bypassing JWT header injection for path: {}", path);
                return chain.filter(exchange);
            }

            return ReactiveSecurityContextHolder.getContext()
                    .cast(org.springframework.security.core.context.SecurityContext.class)
                    .flatMap(ctx -> {
                        Authentication auth = ctx.getAuthentication();
                        log.info("We are trying to inject headers from JWT: {}", auth);
                        if (auth != null && auth.getPrincipal() instanceof Map) {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> claims = (Map<String, Object>) auth.getPrincipal();

                            String userId = String.valueOf(claims.get("sub"));
                            String username = String.valueOf(claims.get("username"));

                            @SuppressWarnings("unchecked")
                            List<String> roles = (List<String>) claims.get("roles");

                            log.info("Injecting headers: userId={}, username={}, roles={}", userId, username, roles);

                            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                    .header("X-User-Id", userId)
                                    .header("X-Username", username)
                                    .header("X-Roles", roles != null ? String.join(",", roles) : "")
                                    .build();

                            return chain.filter(exchange.mutate().request(mutatedRequest).build());
                        } else {
                            log.warn("Authentication object missing or invalid.");
                            return chain.filter(exchange);
                        }
                    })
                    .onErrorResume(throwable -> {
                        log.warn("Error processing JWT context: {}", throwable.getMessage());
                        return chain.filter(exchange);
                    });
        };
    }
}