package com.site.auth.password;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    @Query("select t from PasswordResetToken t join fetch t.user where t.tokenHash = :hash")
    Optional<PasswordResetToken> findByTokenHashFetchUser(@Param("hash") String tokenHash);

    // Elimina todas las solicitudes de un usuario (se usa al crear una nueva).
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from PasswordResetToken t where t.user.id = :userId")
    void deleteAllByUserId(@Param("userId") long userId);

    // Limpieza: borra tokens caducados o ya usados.
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from PasswordResetToken t where t.expiresAt < :cutoff or t.used = true")
    int deleteExpired(@Param("cutoff") Instant cutoff);
}
