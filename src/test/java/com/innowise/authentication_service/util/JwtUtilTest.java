package com.innowise.authentication_service.util;

import com.innowise.authentication_service.entity.enums.AuthRole;
import com.innowise.authentication_service.exception.InvalidOrExpiredToken;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;

import static org.junit.jupiter.api.Assertions.*;


class JwtUtilTest {


    private JwtUtil jwtUtil;

    @BeforeEach
    void setup() {
        jwtUtil = new JwtUtil("01234567890123456789012345678901");
    }

    @Test
    void shouldGenerateValidAccessToken() {
        String token = jwtUtil.generateToken(1L, AuthRole.USER);

        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void shouldGenerateValidRefreshToken() {
        String token = jwtUtil.generateRefreshToken(1L);

        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void shouldValidateTokenSuccessfully() {
        String token = jwtUtil.generateToken(1L, AuthRole.USER);

        Claims result = jwtUtil.validateToken(token);

        assertEquals("1", result.getSubject());
        assertEquals("USER", result.get("role"));
    }

    @Test
    void shouldThrowExceptionForInvalidToken() {
        String token = "invalid token";
        assertThrows(InvalidOrExpiredToken.class, () -> jwtUtil.validateToken(token));
    }

    @Test
    void shouldCorrectExtractUserId() {
        String token = jwtUtil.generateToken(1L, AuthRole.USER);
        Long l = jwtUtil.extractUserId(token);


        assertNotNull(l);
        assertEquals(1L, l.longValue());
    }

    @Test
    void shouldExtractRole() {
        String token = jwtUtil.generateToken(5L, AuthRole.ADMIN);

        String role = jwtUtil.extractRole(token);

        assertEquals("ADMIN", role);
    }

    @Test
    void shouldFailIfTokenTampered() {
        String token = jwtUtil.generateToken(1L, AuthRole.USER);

        String tampered = token + "abc";

        assertThrows(InvalidOrExpiredToken.class, () -> {
            jwtUtil.validateToken(tampered);
        });
    }

}