package com.innowise.authentication_service.exception;

public class InvalidOrExpiredToken extends RuntimeException {
    public InvalidOrExpiredToken() {
        super("Invalid or expired token");
    }
}
