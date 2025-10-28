package com.hs.site.auth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice(basePackages = "com.hs.site.auth")
public class AuthExceptionHandler {

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, String>> handleAuthExceptions(RuntimeException ex) {
        String code = ex.getMessage();

        HttpStatus status = switch (code) {
            case "USERNAME_EXISTS", "EMAIL_EXISTS", "VALIDATION_ERROR" -> HttpStatus.BAD_REQUEST;   // 400
            case "INVALID_CREDENTIALS", "EMAIL_NOT_VERIFIED" -> HttpStatus.UNAUTHORIZED;           // 401
            case "USER_NOT_FOUND" -> HttpStatus.NOT_FOUND;                                         // 404
            case "CURRENT_PASSWORD_INCORRECT" -> HttpStatus.BAD_REQUEST;                           // 400
            case "INVALID_REFRESH_TOKEN", "REFRESH_TOKEN_EXPIRED_OR_REVOKED" -> HttpStatus.UNAUTHORIZED; // 401
            default -> HttpStatus.INTERNAL_SERVER_ERROR;                                           // 500
        };

        return ResponseEntity.status(status).body(Map.of("code", code));
    }
}
