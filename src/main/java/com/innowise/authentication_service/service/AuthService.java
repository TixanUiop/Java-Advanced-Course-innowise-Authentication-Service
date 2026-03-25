package com.innowise.authentication_service.service;

import com.innowise.authentication_service.entity.UserAuth;
import com.innowise.authentication_service.entity.enums.AuthRole;
import com.innowise.authentication_service.exception.InvalidCredentials;
import com.innowise.authentication_service.exception.UserAlreadyExistsException;
import com.innowise.authentication_service.exception.UserNotFoundException;
import com.innowise.authentication_service.repository.UserAuthRepository;
import jakarta.annotation.PostConstruct;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
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

    @PostConstruct
    public void createAdminIfNotExists() {
        if (userRepository.findByLogin("admin").isEmpty()) {
            UserAuth admin = UserAuth.builder()
                    .login("admin")
                    .passwordHash(passwordEncoder.encode("admin123"))
                    .role(AuthRole.ADMIN)
                    .build();
            userRepository.save(admin);
            log.info("Created admin");
        }
    }

    public void makeAdmin(Long id) {
        UserAuth user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));

        user.setRole(AuthRole.ADMIN);
        userRepository.save(user);
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
