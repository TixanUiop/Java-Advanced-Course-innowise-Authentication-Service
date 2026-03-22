package com.innowise.authentication_service.controller;

import com.innowise.authentication_service.dto.AuthRequest;
import com.innowise.authentication_service.dto.AuthResponse;
import com.innowise.authentication_service.entity.UserAuth;
import com.innowise.authentication_service.service.AuthService;
import com.innowise.authentication_service.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;


    @PostMapping("/register")
    public AuthResponse register(@RequestBody AuthRequest request) {
        UserAuth user = authService.register(
                request.getLogin(),
                request.getPassword()
        );

        String accessToken = jwtUtil.generateToken(user.getId(), user.getRole());
        String refreshToken = jwtUtil.generateRefreshToken(user.getId());

        return new AuthResponse(accessToken, refreshToken);
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody AuthRequest request) {
        UserAuth user = authService.authenticate(request.getLogin(), request.getPassword());

        String accessToken = jwtUtil.generateToken(user.getId(), user.getRole());
        String refreshToken = jwtUtil.generateRefreshToken(user.getId());

        return new AuthResponse(accessToken, refreshToken);
    }

    @PostMapping("/validate")
    public String validateToken(@RequestParam String token) {
        jwtUtil.validateToken(token);
        return "valid";
    }

    @PostMapping("/refresh")
    public AuthResponse refreshToken(@RequestParam String refreshToken) {
        Long userId = jwtUtil.extractUserId(refreshToken);
        jwtUtil.validateToken(refreshToken);
        UserAuth user = authService.findById(userId);

        String newAccess = jwtUtil.generateToken(user.getId(), user.getRole());

        return new AuthResponse(newAccess, refreshToken);
    }
}
