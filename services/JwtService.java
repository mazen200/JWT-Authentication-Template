package com.mazen.security.services;

import com.mazen.security.config.JwtConfig;
import com.mazen.security.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

@AllArgsConstructor
@Service
public class JwtService {

    private final JwtConfig jwtConfig;

    public Jwt generateAccessToken(User user) {
        String fullName = user.getFirstName() + " " + user.getLastName();
        return generateToken(user.getId(), user.getEmail(), fullName,
                user.getRole().name(), jwtConfig.getAccessTokenExpiration());
    }

    public Jwt generateRefreshToken(User user) {
        String fullName = user.getFirstName() + " " + user.getLastName();
        return generateToken(user.getId(), user.getEmail(), fullName,
                user.getRole().name(), jwtConfig.getRefreshTokenExpiration());
    }

    public Jwt parse(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(jwtConfig.getSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return new Jwt(claims, jwtConfig.getSecretKey());
        } catch (JwtException | IllegalArgumentException e) {
            System.out.println("Error parsing token: " + e.getMessage());
            return null;
        }
    }

    private Jwt generateToken(UUID id, String email, String name, String role, long tokenExpirationSeconds) {
        var claims = Jwts.claims()
                .subject(id.toString())
                .add("name", name)
                .add("email", email)
                .add("role", role)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + tokenExpirationSeconds * 1000))
                .build();
        return new Jwt(claims, jwtConfig.getSecretKey());
    }
}
