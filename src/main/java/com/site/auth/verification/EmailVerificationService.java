package com.site.auth.verification;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.site.auth.mail.MailSenderPort;
import com.site.auth.user.User;
import com.site.auth.user.UserRepository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

@Service
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokens;
    private final UserRepository users;
    private final MailSenderPort mail;
    private final SecureRandom rnd = new SecureRandom();

    private final Duration ttl;
    private final String backendVerifyUrl;
    private final String frontendSuccessUrl;
    private final String frontendErrorUrl;

    public EmailVerificationService(
            EmailVerificationTokenRepository tokens,
            UserRepository users,
            MailSenderPort mail,
            @Value("${app.verify-email.ttl-hours:24}") long ttlHours,
            @Value("${app.verify-email.backend-verify-url:}") String backendVerifyUrl,
            @Value("${app.verify-email.frontend-success-url:https://opsimulator.com/verified}") String frontendSuccessUrl,
            @Value("${app.verify-email.frontend-error-url:https://opsimulator.com/verify-error}") String frontendErrorUrl
    ) {
        this.tokens = tokens;
        this.users = users;
        this.mail = mail;
        this.ttl = Duration.ofHours(ttlHours);
        this.backendVerifyUrl = backendVerifyUrl == null ? "" : backendVerifyUrl.trim();
        this.frontendSuccessUrl = frontendSuccessUrl;
        this.frontendErrorUrl = frontendErrorUrl;
    }

    /** Enviar (o reenviar) verificación al usuario (idempotente). */
    @Transactional
    public void send(User u) {
        tokens.deleteByUser_IdAndUsedAtIsNull(u.getId());

        String plain = randomToken();
        String hash = sha256(plain);

        var t = new EmailVerificationToken();
        t.setUser(u);
        t.setTokenHash(hash);
        t.setExpiresAt(Instant.now().plus(ttl));
        tokens.save(t);

        String link = buildVerifyLink(plain);

        String html = """
            <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;line-height:1.5">
              <h2>Confirma tu correo</h2>
              <p>Para activar tu cuenta, haz clic aquí:</p>
              <p><a href="%s" style="display:inline-block;padding:10px 16px;background:#2563eb;color:#fff;text-decoration:none;border-radius:6px">Verificar correo</a></p>
              <p>Si no funciona, copia y pega el enlace en tu navegador:<br><code>%s</code></p>
              <p>Caduca en %d horas.</p>
            </div>
        """.formatted(link, link, ttl.toHours());

        mail.send(u.getEmail(), "Verifica tu correo", html);
    }

    /** Confirma token (modo API). Lanza códigos para tu AuthExceptionHandler. */
    @Transactional
    public void confirm(String plainToken) {
        String hash = sha256(plainToken);
        var t = tokens.findByTokenHash(hash)
                .orElseThrow(() -> new RuntimeException("INVALID_TOKEN"));

        if (t.isUsed())     throw new RuntimeException("TOKEN_ALREADY_USED");
        if (t.isExpired())  throw new RuntimeException("TOKEN_EXPIRED");

        t.setUsedAt(Instant.now());
        tokens.save(t);

        var u = t.getUser();
        u.setEnabled(true);
        users.save(u);

        tokens.deleteByUser_IdAndUsedAtIsNull(u.getId());
    }

    /** Confirma y devuelve URL de redirección (éxito/error). */
    @Transactional
    public String confirmAndGetRedirectUrl(String plainToken) {
        String hash = sha256(plainToken);
        var opt = tokens.findByTokenHash(hash);

        if (opt.isEmpty()) {
            return frontendErrorUrl + "?reason=INVALID_TOKEN";
        }

        var t = opt.get();

        if (t.isExpired()) {
            tokens.delete(t);
            return frontendErrorUrl + "?reason=TOKEN_EXPIRED";
        }

        if (t.isUsed()) {
            return frontendErrorUrl + "?reason=TOKEN_ALREADY_USED";
        }

        t.setUsedAt(Instant.now());
        tokens.save(t);

        var u = t.getUser();
        u.setEnabled(true);
        users.save(u);

        tokens.deleteByUser_IdAndUsedAtIsNull(u.getId());

        return frontendSuccessUrl;
    }

    // ===== helpers =====
    private String randomToken() {
        byte[] b = new byte[32];
        rnd.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private String sha256(String s) {
        try {
            var md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(d);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String buildVerifyLink(String plainToken) {
        if (!backendVerifyUrl.isBlank()) {
            return backendVerifyUrl + "?token=" + plainToken;
        }
        String base = frontendSuccessUrl.replace("/verified", "/verify");
        return base + "?token=" + plainToken;
    }

    public String getFrontendSuccessUrl() { return frontendSuccessUrl; }
    public String getFrontendErrorUrl() { return frontendErrorUrl; }
}
