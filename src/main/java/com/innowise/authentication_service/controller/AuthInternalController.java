package com.innowise.authentication_service.controller;

import com.innowise.authentication_service.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth/internal")
@RequiredArgsConstructor
public class AuthInternalController {

    private final AuthService authService;

    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable Long id, @RequestHeader("X-Internal-Key") String key) {

        authService.delete(id, key);
    }
}
