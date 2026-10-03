package org.example.identityservice.repository;

import org.example.identityservice.entity.RefreshToken;
import org.example.identityservice.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    // Lấy luôn User sở hữu token trong cùng một query
    @EntityGraph(attributePaths = "user")
    Optional<RefreshToken> findByToken(String token);

    void deleteByUser(User user);
}
