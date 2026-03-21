package com.innowise.authentication_service.repository;

import com.innowise.authentication_service.entity.UserAuth;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserAuthRepository extends JpaRepository<UserAuth, Long> {
    Optional<UserAuth> findByLogin(String login);
}
