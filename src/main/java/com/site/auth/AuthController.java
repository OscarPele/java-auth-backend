package com.site.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import com.site.auth.password.PasswordResetService;
import com.site.auth.user.UserService;
import com.site.auth.verification.EmailVerificationService;
import com.site.security.JWTService;

import static com.site.security.JwtUtils.getUid;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final PasswordResetService passwordResetService;
    private final EmailVerificationService emailVerificationService;
    private final JWTService jwtService;

    public AuthController(UserService userService,
                          PasswordResetService passwordResetService,
                          EmailVerificationService emailVerificationService,
                          JWTService jwtService) {
        this.userService = userService;
        this.passwordResetService = passwordResetService;
        this.emailVerificationService = emailVerificationService;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        var user = userService.register(body.get("username"), body.get("email"), body.get("password"));
        emailVerificationService.send(user);
        return ResponseEntity.ok(Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "email", user.getEmail(),
                "enabled", user.isEnabled(),
                "createdAt", user.getCreatedAt()
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        var user = userService.authenticate(body.get("usernameOrEmail"), body.get("password"));
        String access = jwtService.generate(user.getUsername(), Map.of("uid", user.getId()));
        return ResponseEntity.ok(Map.of(
                "tokenType", "Bearer",
                "accessToken", access,
                "expiresIn", jwtService.getExpirationSeconds()
        ));
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll() {
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(@RequestBody Map<String, String> body) {
        passwordResetService.requestReset(body.getOrDefault("email", ""));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(@RequestBody Map<String, String> body) {
        passwordResetService.reset(body.get("token"), body.get("newPassword"));
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/users/me/password")
    public ResponseEntity<Void> changeOwnPassword(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody Map<String, String> body
    ) {
        Long uid = getUid(jwt);
        if (uid == null) throw new org.springframework.security.access.AccessDeniedException("JWT sin uid");

        String current = body.getOrDefault("currentPassword", "");
        String next = body.getOrDefault("newPassword", "");

        userService.changePassword(uid, current, next);

        return ResponseEntity.noContent().build();
    }
}
