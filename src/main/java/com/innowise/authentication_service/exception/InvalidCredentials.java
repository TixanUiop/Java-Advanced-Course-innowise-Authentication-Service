package com.innowise.authentication_service.exception;

public class InvalidCredentials extends RuntimeException {
    public InvalidCredentials() {
        super("Invalid credentials");
    }
}
