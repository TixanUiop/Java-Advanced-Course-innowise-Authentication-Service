package com.innowise.authentication_service.service;

import com.innowise.authentication_service.entity.UserAuth;
import com.innowise.authentication_service.entity.enums.AuthRole;
import com.innowise.authentication_service.exception.InvalidCredentials;
import com.innowise.authentication_service.exception.UserAlreadyExistsException;
import com.innowise.authentication_service.exception.UserNotFoundException;
import com.innowise.authentication_service.repository.UserAuthRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    private UserAuthRepository userRepository;
    private PasswordEncoder passwordEncoder;

    @Autowired
    public AuthService(UserAuthRepository userRepository, PasswordEncoder passwordEncoder)
    {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public UserAuth findById(Long id)
    {
        Optional<UserAuth> byId = userRepository.findById(id);
        if (byId.isPresent()) {
            return byId.get();
        }
        throw new UserNotFoundException(id);
    }

    public UserAuth register(String login, String password) {

        if (userRepository.findByLogin(login).isPresent()) {
            throw new UserAlreadyExistsException();
        }

        UserAuth user = UserAuth.builder()
                .login(login)
                .passwordHash(passwordEncoder.encode(password))
                .role(AuthRole.USER)
                .build();
        return userRepository.save(user);
    }

    public UserAuth authenticate(String login, String password) {
        UserAuth user = userRepository.findByLogin(login)
                .orElseThrow(() -> new InvalidCredentials());

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new InvalidCredentials();
        }

        return user;
    }

}
