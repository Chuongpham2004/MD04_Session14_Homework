package org.example.identityservice.service;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.example.identityservice.config.JwtProperties;
import org.example.identityservice.dto.AuthResponse;
import org.example.identityservice.dto.LoginRequest;
import org.example.identityservice.dto.RegisterRequest;
import org.example.identityservice.entity.RefreshToken;
import org.example.identityservice.entity.Role;
import org.example.identityservice.entity.User;
import org.example.identityservice.exception.TokenRefreshException;
import org.example.identityservice.repository.UserRepository;
import org.example.identityservice.security.JwtUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final JwtProperties jwtProperties;
    private final TokenBlacklistService tokenBlacklistService;

    @Transactional
    public AuthResponse login(LoginRequest request) {
        // 1. Xác thực username/password (sai sẽ ném AuthenticationException)
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));

        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // 2. Access Token: JWT, sống ngắn
        String accessToken = jwtUtils.generateAccessToken(user);

        // 3. Refresh Token: UUID, sống dài, lưu DB
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        // 4. Trả về cả hai
        return new AuthResponse(
                accessToken,
                refreshToken.getToken(),
                "Bearer",
                jwtProperties.getAccessTokenExpiration(),
                user.getUsername(),
                user.getRole().name());
    }

    @Transactional
    public AuthResponse refreshToken(String requestToken) {
        // 1. Tìm Refresh Token trong DB
        RefreshToken oldToken = refreshTokenService.findByToken(requestToken)
                .orElseThrow(() -> new TokenRefreshException(requestToken, "Refresh token is not in database"));

        // 2. Token đã hết hạn -> từ chối
        if (oldToken.getExpiryDate().isBefore(Instant.now())) {
            throw new TokenRefreshException(requestToken, "Refresh token was expired. Please login again");
        }

        // 3. Rotation: hủy token cũ, mỗi Refresh Token chỉ dùng được đúng 1 lần
        refreshTokenService.delete(oldToken);

        // 4. Access Token mới cho chủ sở hữu token cũ
        User user = oldToken.getUser();
        String accessToken = jwtUtils.generateAccessToken(user);

        // 5. Refresh Token hoàn toàn mới
        RefreshToken newToken = refreshTokenService.createRefreshToken(user.getId());

        // 6. Trả về cặp token mới
        return new AuthResponse(
                accessToken,
                newToken.getToken(),
                "Bearer",
                jwtProperties.getAccessTokenExpiration(),
                user.getUsername(),
                user.getRole().name());
    }

    public void logout(String token) {
        // 1. Giải mã token để lấy jti và exp
        Claims claims = jwtUtils.parseClaims(token);

        // 2. TTL = thời gian sống còn lại của token
        Duration ttl = Duration.between(Instant.now(), claims.getExpiration().toInstant());

        // 3 + 4. Lưu "blacklist:{jti}" = "revoked" vào Redis, tự xóa sau đúng TTL
        if (!ttl.isNegative() && !ttl.isZero()) {
            tokenBlacklistService.blacklist(claims.getId(), ttl);
        }

        // 5. Xóa luôn Refresh Token của user trong PostgreSQL để không xin được Access Token mới
        refreshTokenService.deleteByUserId(claims.get("userId", Number.class).longValue());
    }

    @Transactional
    public User register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Username is already taken");
        }
        if (request.email() != null && userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email is already in use");
        }
        // Không cho tự đăng ký quyền ADMIN
        Role role = request.role() != null ? request.role() : Role.ROLE_USER;
        if (role == Role.ROLE_ADMIN) {
            throw new IllegalArgumentException("Cannot register with role ROLE_ADMIN");
        }

        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .email(request.email())
                .role(role)
                .build();
        return userRepository.save(user);
    }
}
