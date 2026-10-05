package org.example.gatewayservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@Slf4j
@Component
public class JwtAuthenticationGlobalFilter implements GlobalFilter, Ordered {

    public static final String USER_ROLE_HEADER = "X-User-Role";

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String ROLE_CLAIM = "role";
    private static final PathPattern PROTECTED_PATH = PathPatternParser.defaultInstance.parse("/api/courses/**");

    private final Key signingKey;

    public JwtAuthenticationGlobalFilter(@Value("${app.jwt.secret}") String secret) {
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        // Chỉ chặn các request đi xuống Course-Service
        if (!PROTECTED_PATH.matches(request.getPath().pathWithinApplication())) {
            return chain.filter(exchange);
        }

        // 1. Lấy token từ Header "Authorization: Bearer <token>"
        String header = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return unauthorized(exchange, "Missing access token");
        }

        // 2. Giải mã JWT bằng Secret Key dùng chung với Identity-Service
        Claims claims;
        try {
            claims = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(header.substring(BEARER_PREFIX.length()).trim())
                    .getBody();
        } catch (JwtException | IllegalArgumentException e) {
            // Token hết hạn / sai chữ ký / sai định dạng -> chặn ngay tại Gateway
            log.warn("Rejected token on {}: {}", request.getPath(), e.getMessage());
            return unauthorized(exchange, "Invalid or expired access token");
        }

        String role = claims.get(ROLE_CLAIM, String.class);
        if (role == null || role.isBlank()) {
            return unauthorized(exchange, "Access token has no role");
        }

        // 3. Gắn role vào Header X-User-Role (set = ghi đè, client không tự giả mạo header này được)
        ServerHttpRequest mutated = request.mutate()
                .headers(headers -> headers.set(USER_ROLE_HEADER, role))
                .build();
        return chain.filter(exchange.mutate().request(mutated).build());
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        DataBuffer body = response.bufferFactory()
                .wrap(("{\"status\":401,\"message\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(body));
    }

    @Override
    public int getOrder() {
        // Chạy trước TokenBlacklistGlobalFilter (-1): token phải hợp lệ rồi mới kiểm tra blacklist
        return -2;
    }
}
