package com.beaconfire.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class JwtHeaderRelayGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> {

    public JwtHeaderRelayGatewayFilterFactory() {
        super(Object.class);
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof Map) {
                Map<String, Object> claims = (Map<String, Object>) auth.getPrincipal();

                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                        .header("X-User-Id", String.valueOf(claims.get("sub")))
                        .header("X-Username", String.valueOf(claims.get("username")))
                        .header("X-Roles", String.join(",", (List<String>) claims.get("roles")))
                        .build();

                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            }
            return chain.filter(exchange);
        };
    }
}
