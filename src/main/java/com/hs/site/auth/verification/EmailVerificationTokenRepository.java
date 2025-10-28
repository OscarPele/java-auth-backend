package com.hs.site.auth.verification;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {
    Optional<EmailVerificationToken> findByTokenHash(String tokenHash);
    void deleteByUser_Id(Long userId);
    void deleteByUser_IdAndUsedAtIsNull(Long userId);
}
