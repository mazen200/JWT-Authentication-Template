package com.mazen.security.services;

import com.mazen.security.dtos.LoginRequest;
import com.mazen.security.dtos.RegisterRequest;
import com.mazen.security.dtos.TokenPair;
import com.mazen.security.entities.User;
import com.mazen.security.enums.Role;
import com.mazen.security.repos.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@AllArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public User register(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already in use");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPhoneNumber(request.getPhoneNumber());
        user.setRole(Role.customer);

        return userRepository.save(user);
    }

    public TokenPair login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password."));

        return new TokenPair(
                jwtService.generateAccessToken(user).toString(),
                jwtService.generateRefreshToken(user).toString()
        );
    }

    public TokenPair refresh(String refreshToken) {
        Jwt jwt = jwtService.parse(refreshToken);
        if (jwt == null || jwt.isExpired() || jwt.getId() == null) {
            throw new IllegalArgumentException("Invalid or expired refresh token");
        }

        UUID userId = jwt.getId();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return new TokenPair(
                jwtService.generateAccessToken(user).toString(),
                jwtService.generateRefreshToken(user).toString()
        );
    }

}
