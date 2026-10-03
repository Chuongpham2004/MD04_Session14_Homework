package org.example.identityservice.exception;

public class TokenRefreshException extends RuntimeException {

    public TokenRefreshException(String token, String message) {
        super(String.format("Refresh token [%s]: %s", token, message));
    }
}
