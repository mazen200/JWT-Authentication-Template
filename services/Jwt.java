package com.mazen.security.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

public class Jwt {
    private final Claims claims;
    private final SecretKey key;

    public Jwt(Claims claims, SecretKey key) {
        this.claims = claims;
        this.key = key;
    }

    public UUID getId() {
        return UUID.fromString(claims.getSubject());
    }

    public String getRole() {
        return claims.get("role", String.class);
    }

    public boolean isExpired() {
        return claims.getExpiration().before(new Date());
    }

    public String toString() {
        return Jwts.builder().claims(claims).signWith(key).compact();
    }
}
