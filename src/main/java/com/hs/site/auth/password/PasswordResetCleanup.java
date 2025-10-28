package com.hs.site.auth.password;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class PasswordResetCleanup {
    private static final Logger log = LoggerFactory.getLogger(PasswordResetCleanup.class);
    private final PasswordResetTokenRepository repo;

    public PasswordResetCleanup(PasswordResetTokenRepository repo) { this.repo = repo; }

    /** Cada hora (zona Madrid). */
    @Transactional
    @Scheduled(cron = "0 0 * * * *", zone = "Europe/Madrid")
    public void clean() {
        int removed = repo.deleteExpired(Instant.now());
        if (removed > 0) log.info("PasswordResetCleanup: eliminados {} tokens caducados", removed);
        else log.debug("PasswordResetCleanup: nada que eliminar.");
    }
}
