package org.example.productservice.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * @PreAuthorize từ chối (vd: token ROLE_USER gọi DELETE /api/products/{id})
     * sẽ ném AuthorizationDeniedException (lớp con của AccessDeniedException).
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : "anonymous";
        List<String> roles = auth != null
                ? auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()
                : List.of();

        Map<String, Object> body = base(HttpStatus.FORBIDDEN,
                "Bạn không có quyền thực hiện thao tác này", request);
        body.put("username", username);
        body.put("roles", roles);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    private Map<String, Object> base(HttpStatus status, String message, HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        body.put("path", request.getMethod() + " " + request.getRequestURI());
        return body;
    }
}
