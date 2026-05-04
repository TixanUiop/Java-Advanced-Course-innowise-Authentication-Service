package com.innowise.authentication_service.security;

import com.innowise.authentication_service.entity.enums.AuthRole;
import com.innowise.authentication_service.util.JwtUtil;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

    private JwtUtil jwtUtil;

    private JwtAuthFilter filter;

    @BeforeEach
    void setup() {
        jwtUtil = new JwtUtil("01234567890123456789012345678901");
        filter = new JwtAuthFilter(jwtUtil);
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldSkipFilterIfNoHeader() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(chain).doFilter(request, response);
    }

    @Test
    void shouldIgnoreRefreshToken() throws Exception {
        String refreshToken = jwtUtil.generateRefreshToken(1L);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + refreshToken);

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(chain).doFilter(request, response);
    }

    @Test
    void shouldSetAuthenticationIfTokenValid() throws Exception {

        String token = jwtUtil.generateToken(1L, AuthRole.USER);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        var auth = SecurityContextHolder.getContext().getAuthentication();

        assertNotNull(auth);
        assertEquals(1L, auth.getPrincipal());
    }

    @Test
    void shouldClearContextIfTokenInvalid() throws Exception {
        JwtUtil jwtUtil = new JwtUtil("01234567890123456789012345678901");
        JwtAuthFilter filter = new JwtAuthFilter(jwtUtil);

        MockHttpServletRequest request = new MockHttpServletRequest();

        request.addHeader("Authorization", "Bearer invalid.token.here");

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(chain).doFilter(request, response);
    }

}