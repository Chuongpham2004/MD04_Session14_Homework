package org.example.courseservice.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Gateway đã verify JWT và gắn role vào Header X-User-Role,
 * nên ở đây chỉ đọc Header chứ không giải mã JWT lần nữa.
 */
public class HeaderAuthenticationFilter extends OncePerRequestFilter {

    public static final String USER_ROLE_HEADER = "X-User-Role";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // 1. Lấy role từ Header do Gateway truyền xuống
        String header = request.getHeader(USER_ROLE_HEADER);
        if (header != null && !header.isBlank()) {
            // 2. Chuyển Role(s) thành danh sách SimpleGrantedAuthority (giữ nguyên tên để dùng với hasAuthority)
            List<SimpleGrantedAuthority> authorities = Arrays.stream(header.split(","))
                    .map(String::trim)
                    .filter(r -> !r.isEmpty())
                    .map(SimpleGrantedAuthority::new)
                    .toList();

            // 3. Tạo Authentication và nạp vào SecurityContextHolder
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(header, null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }
}
