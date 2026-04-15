package com.innowise.authentication_service.service;

import com.innowise.authentication_service.entity.UserAuth;
import com.innowise.authentication_service.entity.enums.AuthRole;
import com.innowise.authentication_service.exception.InvalidCredentials;
import com.innowise.authentication_service.exception.UserAlreadyExistsException;
import com.innowise.authentication_service.exception.UserNotFoundException;
import com.innowise.authentication_service.repository.UserAuthRepository;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

@Slf4j
@Service
public class AuthService {

    private UserAuthRepository userRepository;
    private PasswordEncoder passwordEncoder;

    private final Environment env;

    @Value("${internal.secret}")
    private String internalKey;

    @Autowired
    public AuthService(UserAuthRepository userRepository, PasswordEncoder passwordEncoder, Environment env)
    {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.env = env;
    }

    public void delete(Long id, String key) {

        if (!internalKey.equals(key)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid internal key");
        }

        userRepository.deleteById(id);
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
    public void createDefaultAdmin() {
        String activeProfile = env.getActiveProfiles().length > 0 ? env.getActiveProfiles()[0] : "";
        if (!activeProfile.equals("prod")) {
            UserAuth admin = userRepository.findByLogin("admin").orElseGet(() -> {
                UserAuth newAdmin = UserAuth.builder()
                        .login(env.getProperty("admin.login", "admin"))
                        .passwordHash(passwordEncoder.encode(env.getProperty("admin.password", "changeme")))
                        .role(AuthRole.ADMIN)
                        .build();
                return userRepository.save(newAdmin);
            });
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
