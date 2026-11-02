package com.mazen.security.config;

import io.jsonwebtoken.security.Keys;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Configuration
@ConfigurationProperties(prefix = "spring.jwt")
@Data
public class JwtConfig {
    //TODO : move to env
    private String secret = "D6XS+MhETXi9XHrOPSv5t1BTRvkprbCzHjMLc70jtjo=";
    private int accessTokenExpiration = 60*60*60*24;
    private int refreshTokenExpiration = 60*60*60*24*7;

    public SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }
}
