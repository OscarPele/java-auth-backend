package com.hs.site.auth.token;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.hs.site.auth.user.User;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

@Service
@Transactional
public class RefreshTokenService {

    private final RefreshTokenRepository repository;
    private final int maxSessionsPerUser;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(
            RefreshTokenRepository repository,
            @Value("${app.jwt.max-sessions-per-user:5}") int maxSessionsPerUser
    ) {
        this.repository = repository;
        this.maxSessionsPerUser = maxSessionsPerUser;
    }

    /** DTO mínimo para controller */
    public record UserRef(long id, String username) {}

    /** Crea y devuelve el refresh en claro (persistimos solo el hash). */
    public String create(User user) {
        String plain = generateOpaqueToken();
        String hash = sha256Url(plain);

        RefreshToken rt = new RefreshToken();
        rt.setUser(user);
        rt.setTokenHash(hash);
        repository.save(rt);

        enforceUserSessionCap(user.getId());
        return plain;
    }

    /** Valida y devuelve referencia de usuario (para /refresh, /logout-all). */
    public UserRef validateAndGetUserRef(String tokenPlain) {
        String hash = sha256Url(tokenPlain);
        RefreshToken rt = repository.findByTokenHashFetchUser(hash)
                .orElseThrow(() -> new RuntimeException("INVALID_REFRESH_TOKEN"));
        var u = rt.getUser();
        return new UserRef(u.getId(), u.getUsername());
    }

    /** Logout de un dispositivo: elimina el token. */
    public void revoke(String tokenPlain) {
        String hash = sha256Url(tokenPlain);
        repository.findByTokenHash(hash).ifPresent(repository::delete);
    }

    /** Logout de todos los dispositivos: elimina todos los tokens del usuario. */
    public void revokeAllByUserId(long userId) {
        repository.deleteAllByUserId(userId);
    }

    // --- utilidades privadas ---

    private String generateOpaqueToken() {
        byte[] bytes = new byte[64]; // 512 bits
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** SHA-256 + Base64url sin padding (~43-44 chars) */
    static String sha256Url(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("CANNOT_COMPUTE_SHA256", e);
        }
    }

    /** Limitar sesiones por usuario (borra las más antiguas si excede). */
    private void enforceUserSessionCap(long userId) {
        if (maxSessionsPerUser <= 0) return;
        long count = repository.countByUserId(userId);
        if (count <= maxSessionsPerUser) return;

        int extras = (int) (count - maxSessionsPerUser);
        List<Long> oldestIds = repository.findIdsByUserOldestFirst(userId);
        if (oldestIds.size() >= extras) {
            repository.deleteAllByIdInBatch(oldestIds.subList(0, extras));
        }
    }
}
