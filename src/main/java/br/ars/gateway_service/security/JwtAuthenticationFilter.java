package br.ars.gateway_service.security;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

@Component
@Order(0)
public class JwtAuthenticationFilter implements GlobalFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Value("${jwt.secret}")
    private String secretKey;

    // 🟢 Endpoints públicos exatos
    private static final List<String> openEndpoints = List.of(
        "/api/users/login",
        "/api/users/register"
    );

    private boolean isPublicPath(String path) {
        String cleanPath = path.split("\\?")[0].replaceAll("/+$", "").toLowerCase();
        return openEndpoints.stream()
                .anyMatch(endpoint -> cleanPath.equalsIgnoreCase(endpoint));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();
        HttpMethod method = exchange.getRequest().getMethod();

        // ✅ Libera CORS pré-flight automaticamente
        if (HttpMethod.OPTIONS.equals(method)) {
            logger.debug("🟡 Requisição OPTIONS liberada automaticamente: {}", path);
            exchange.getResponse().setStatusCode(HttpStatus.OK);
            return exchange.getResponse().setComplete();
        }

        // ✅ Libera login e register
        if (isPublicPath(path)) {
            logger.debug("🔓 Endpoint público liberado: {}", path);
            return chain.filter(exchange);
        }

        // 🔐 Verifica token para demais rotas
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.warn("❌ Token ausente ou mal formatado para rota: {}", path);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        try {
            Jwts.parserBuilder()
                .setSigningKey(secretKey.getBytes(StandardCharsets.UTF_8))
                .build()
                .parseClaimsJws(token);

            return chain.filter(exchange);

        } catch (JwtException e) {
            logger.error("❌ Token inválido ou expirado: {}", e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }
}
