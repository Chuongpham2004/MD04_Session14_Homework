package org.example.gatewayservice.filter;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@Slf4j
@Component
public class TokenBlacklistGlobalFilter implements GlobalFilter, Ordered {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String KEY_PREFIX = "blacklist:";

    private final ReactiveStringRedisTemplate redisTemplate;
    private final Key signingKey;

    public TokenBlacklistGlobalFilter(ReactiveStringRedisTemplate redisTemplate,
                                      @Value("${app.jwt.secret}") String secret) {
        this.redisTemplate = redisTemplate;
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 1. Lấy token từ Header "Authorization: Bearer <token>"
        String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return chain.filter(exchange);
        }

        // 2. Parse JWT để lấy jti
        String jti;
        try {
            jti = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(header.substring(BEARER_PREFIX.length()).trim())
                    .getBody()
                    .getId();
        } catch (JwtException | IllegalArgumentException e) {
            // Token sai chữ ký / hết hạn / sai định dạng: Gateway chỉ lo blacklist, service phía sau sẽ trả 401
            return chain.filter(exchange);
        }
        if (jti == null) {
            return chain.filter(exchange);
        }

        // 3. Hỏi Redis (non-blocking) xem token đã bị logout chưa
        return redisTemplate.hasKey(KEY_PREFIX + jti)
                .flatMap(blacklisted -> {
                    if (Boolean.TRUE.equals(blacklisted)) {
                        // 4. Đã bị blacklist -> 401 ngay tại Gateway, không chuyển tiếp vào service
                        log.warn("Blocked blacklisted token {} on {}", jti, exchange.getRequest().getPath());
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }
                    // 5. Chưa bị blacklist -> cho đi tiếp
                    return chain.filter(exchange);
                });
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
