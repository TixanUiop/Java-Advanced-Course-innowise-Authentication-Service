package com.innowise.authentication_service.exception;

public class RoleMissingInToken extends RuntimeException {
    public RoleMissingInToken() {
        super("Role missing in token");
    }
}
