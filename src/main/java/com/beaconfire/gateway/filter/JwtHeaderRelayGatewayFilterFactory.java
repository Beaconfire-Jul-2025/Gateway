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
        return (exchange, chain) ->
                ReactiveSecurityContextHolder.getContext()
                        .flatMap(ctx -> {
                            Authentication auth = ctx.getAuthentication();
                            if (auth != null && auth.getPrincipal() instanceof Map) {
                                Map<String, Object> claims = (Map<String, Object>) auth.getPrincipal();

                                String userId = String.valueOf(claims.get("sub"));
                                String username = String.valueOf(claims.get("username"));
                                List<String> roles = (List<String>) claims.get("roles");

                                log.info("Injecting headers: userId={}, username={}, roles={}", userId, username, roles);

                                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                        .header("X-User-Id", userId)
                                        .header("X-Username", username)
                                        .header("X-Roles", String.join(",", roles))
                                        .build();

                                return chain.filter(exchange.mutate().request(mutatedRequest).build());
                            } else {
                                log.warn("Authentication object missing or invalid.");
                                return chain.filter(exchange);
                            }
                        });
    }
}