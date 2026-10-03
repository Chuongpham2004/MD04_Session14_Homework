package org.example.productservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.example.productservice.config.JwtProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Collection;
import java.util.List;

@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String ROLE_PREFIX = "ROLE_";

    private final Key signingKey;

    public JwtAuthenticationFilter(JwtProperties jwtProperties) {
        this.signingKey = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // 1. Lấy chuỗi JWT từ Header "Authorization: Bearer <token>"
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length()).trim();
            try {
                // 2. Verify chữ ký bằng Secret Key dùng chung với Identity-Service
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(signingKey)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                // 3. Trích xuất "username" (subject) và "role" từ Claims
                String username = claims.getSubject();
                Object roleClaim = claims.get("role");

                // 4. Chuyển Role(s) thành danh sách SimpleGrantedAuthority
                List<SimpleGrantedAuthority> authorities = toAuthorities(roleClaim);

                // 5. Tạo Authentication và nạp vào SecurityContextHolder
                if (username != null) {
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (JwtException | IllegalArgumentException e) {
                // Token sai chữ ký / hết hạn / sai định dạng -> coi như chưa đăng nhập (401)
                log.warn("Invalid JWT: {}", e.getMessage());
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Hỗ trợ cả claim dạng chuỗi ("ROLE_ADMIN") lẫn dạng mảng (["ADMIN"]).
     * Luôn chuẩn hóa về tiền tố "ROLE_" để dùng được với hasRole('ADMIN').
     */
    private List<SimpleGrantedAuthority> toAuthorities(Object roleClaim) {
        if (roleClaim == null) {
            return List.of();
        }
        Collection<?> roles = roleClaim instanceof Collection<?> c ? c : List.of(roleClaim);
        return roles.stream()
                .map(String::valueOf)
                .map(r -> r.startsWith(ROLE_PREFIX) ? r : ROLE_PREFIX + r)
                .map(SimpleGrantedAuthority::new)
                .toList();
    }
}
