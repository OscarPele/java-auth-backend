package com.site.auth.password;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.site.auth.user.User;
import com.site.auth.user.UserService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

@Service
@Transactional
public class PasswordResetService {

    private final PasswordResetTokenRepository repo;     // lo creamos después
    private final UserService userService;
    private final int expirationMinutes;
    private final SecureRandom random = new SecureRandom();

    public PasswordResetService(PasswordResetTokenRepository repo,
                                UserService userService,
                                @Value("${app.password-reset.expiration-minutes:30}") int expirationMinutes) {
        this.repo = repo;
        this.userService = userService;
        this.expirationMinutes = expirationMinutes;
    }

    /** Solicita reset: siempre 204 en el controller. No revela si el email existe. */
    public void requestReset(String email) {
        userService.findByEmailIgnoreCase(email).ifPresent(user -> {
            // invalidar solicitudes previas del usuario (simple: borrar)
            repo.deleteAllByUserId(user.getId());

            String plain = generateOpaqueToken();
            String hash = sha256Url(plain);

            var prt = new PasswordResetToken();
            prt.setUser(user);
            prt.setTokenHash(hash);
            prt.setExpiresAt(Instant.now().plus(Duration.ofMinutes(expirationMinutes)));
            repo.save(prt);

            // Aquí enviarías el email con el "plain"
            // e.g., mailService.sendPasswordReset(user.getEmail(), plain);
        });
    }

    /** Aplica el cambio de contraseña usando un token de un solo uso. */
    public void reset(String tokenPlain, String newPassword) {
        String hash = sha256Url(tokenPlain);
        var prt = repo.findByTokenHashFetchUser(hash)
                .orElseThrow(() -> new RuntimeException("RESET_TOKEN_INVALID"));

        if (prt.isUsed() || prt.getExpiresAt().isBefore(Instant.now())) {
            throw new RuntimeException("RESET_TOKEN_EXPIRED");
        }

        User u = prt.getUser();
        userService.forceChangePassword(u.getId(), newPassword);

        // Marcar token como usado
        prt.setUsed(true);
        repo.save(prt);
    }

    // --- utilidades privadas ---

    private String generateOpaqueToken() {
        byte[] bytes = new byte[48]; // 384 bits
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String sha256Url(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("CANNOT_COMPUTE_SHA256", e);
        }
    }
}
