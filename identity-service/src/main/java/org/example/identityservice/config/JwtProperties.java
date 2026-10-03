package org.example.identityservice.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {

    private String secret;

    /** Thời gian sống của Access Token (ms) */
    private long accessTokenExpiration;

    /** Thời gian sống của Refresh Token (ms) */
    private long refreshTokenExpiration;
}
