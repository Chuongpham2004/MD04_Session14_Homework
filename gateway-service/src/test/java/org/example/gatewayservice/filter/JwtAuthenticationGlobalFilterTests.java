package org.example.gatewayservice.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class JwtAuthenticationGlobalFilterTests {

    private static final String SECRET = "test_secret_key_at_least_32_characters_long";
    private static final String OTHER_SECRET = "another_secret_key_at_least_32_characters!!";

    private final JwtAuthenticationGlobalFilter filter = new JwtAuthenticationGlobalFilter(SECRET);
    private final AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();
    private final GatewayFilterChain chain = exchange -> {
        forwarded.set(exchange);
        return Mono.empty();
    };

    @Test
    void missingTokenIsRejected() {
        MockServerWebExchange exchange = exchange("/api/courses", null);

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        assertNull(forwarded.get());
    }

    @Test
    void expiredTokenIsRejected() {
        MockServerWebExchange exchange = exchange("/api/courses/1", token(SECRET, "USER", -60_000));

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        assertNull(forwarded.get());
    }

    @Test
    void wrongSignatureIsRejected() {
        MockServerWebExchange exchange = exchange("/api/courses", token(OTHER_SECRET, "ADMIN", 60_000));

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        assertNull(forwarded.get());
    }

    @Test
    void validTokenForwardsRoleHeaderAndOverridesClientValue() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/courses")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(SECRET, "USER", 60_000))
                .header(JwtAuthenticationGlobalFilter.USER_ROLE_HEADER, "ADMIN"));

        filter.filter(exchange, chain).block();

        assertNotNull(forwarded.get());
        assertEquals(java.util.List.of("USER"), forwarded.get().getRequest().getHeaders()
                .get(JwtAuthenticationGlobalFilter.USER_ROLE_HEADER));
    }

    @Test
    void otherPathsAreNotIntercepted() {
        MockServerWebExchange exchange = exchange("/api/auth/login", null);

        filter.filter(exchange, chain).block();

        assertNotNull(forwarded.get());
        assertNull(exchange.getResponse().getStatusCode());
    }

    private static MockServerWebExchange exchange(String path, String token) {
        MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get(path);
        if (token != null) {
            request.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        return MockServerWebExchange.from(request);
    }

    private static String token(String secret, String role, long ttlMillis) {
        Date now = new Date();
        return Jwts.builder()
                .setSubject("tester")
                .claim("role", role)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + ttlMillis))
                .signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
    }
}
