package org.example.identityservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.example.identityservice.entity.Role;

public record RegisterRequest(
        @NotBlank @Size(min = 3, max = 50) String username,
        @NotBlank @Size(min = 6) String password,
        @Email String email,
        // Tùy chọn: STUDENT hoặc INSTRUCTOR. Bỏ trống -> ROLE_USER
        Role role
) {
}
