package com.innowise.authentication_service.service;

import com.innowise.authentication_service.entity.UserAuth;
import com.innowise.authentication_service.entity.enums.AuthRole;
import com.innowise.authentication_service.exception.InvalidCredentials;
import com.innowise.authentication_service.exception.UserAlreadyExistsException;
import com.innowise.authentication_service.exception.UserNotFoundException;
import com.innowise.authentication_service.repository.UserAuthRepository;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserAuthRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    private UserAuth userAuth;

    @BeforeEach
    void setUp() {
        userAuth = UserAuth.builder()
                .id(1L)
                .login("login")
                .passwordHash("passwordHash")
                .role(AuthRole.USER)
                .build();
    }


    @Test
    void shouldReturnCorrectUserAuthFindById() {

        when(userRepository.findById(1L)).thenReturn(Optional.of(userAuth));

        UserAuth result = authService.findById(1L);

        assertEquals(userAuth, result);
        verify(userRepository).findById(1L);
    }

    @Test
    void shouldThrowExceptionWhenUserNotFound() {
        when(userRepository.findById(1L)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> authService.findById(1L));

        verify(userRepository).findById(1L);
    }


    @Test
    void shouldThrowIfUserAlreadyExists() {
        when(userRepository.findByLogin("login")).thenReturn(Optional.of(userAuth));

        assertThrows(UserAlreadyExistsException.class,
                () -> authService.register("login", "password"));

        verify(userRepository).findByLogin("login");
        verify(userRepository, never()).save(any());
    }

    @Test
    void shouldRegisterUserSuccessfully() {
        when(userRepository.findByLogin("login")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("password")).thenReturn("encodedPassword");

        when(userRepository.save(any(UserAuth.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        UserAuth result = authService.register("login", "password");

        assertEquals("login", result.getLogin());
        assertEquals("encodedPassword", result.getPasswordHash());
        assertEquals(AuthRole.USER, result.getRole());

        verify(userRepository).findByLogin("login");
        verify(passwordEncoder).encode("password");
        verify(userRepository).save(any(UserAuth.class));
    }

    @Test
    void shouldThrowIfUserNotFoundDuringAuth() {
        when(userRepository.findByLogin("login")).thenReturn(Optional.empty());

        assertThrows(InvalidCredentials.class,
                () -> authService.authenticate("login", "password"));

        verify(userRepository).findByLogin("login");
    }

    @Test
    void shouldThrowIfPasswordIncorrect() {
        when(userRepository.findByLogin("login")).thenReturn(Optional.of(userAuth));
        when(passwordEncoder.matches("password", "passwordHash")).thenReturn(false);

        assertThrows(InvalidCredentials.class,
                () -> authService.authenticate("login", "password"));

        verify(passwordEncoder).matches("password", "passwordHash");
    }

    @Test
    void shouldAuthenticateSuccessfully() {
        when(userRepository.findByLogin("login")).thenReturn(Optional.of(userAuth));
        when(passwordEncoder.matches("password", "passwordHash")).thenReturn(true);

        UserAuth result = authService.authenticate("login", "password");

        assertEquals(userAuth, result);

        verify(userRepository).findByLogin("login");
        verify(passwordEncoder).matches("password", "passwordHash");

    }
}