package org.example.identityservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private static final String KEY_PREFIX = "blacklist:";
    private static final String REVOKED = "revoked";

    private final StringRedisTemplate redisTemplate;

    // Key tự bị Redis xóa sau đúng TTL, tức là cùng lúc token hết hạn tự nhiên
    public void blacklist(String jti, Duration ttl) {
        redisTemplate.opsForValue().set(KEY_PREFIX + jti, REVOKED, ttl);
    }

    public boolean isBlacklisted(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(KEY_PREFIX + jti));
    }
}
