package org.example.identityservice.entity;

public enum Role {
    ROLE_USER,
    ROLE_ADMIN,
    // Dùng cho Course-Service: hasAuthority('STUDENT') / hasAuthority('INSTRUCTOR')
    STUDENT,
    INSTRUCTOR
}
