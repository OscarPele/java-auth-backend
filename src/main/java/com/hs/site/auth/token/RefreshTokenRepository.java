package com.hs.site.auth.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Query("select rt from RefreshToken rt join fetch rt.user where rt.tokenHash = :tokenHash")
    Optional<RefreshToken> findByTokenHashFetchUser(@Param("tokenHash") String tokenHash);

    @Query("select rt.id from RefreshToken rt where rt.user.id = :userId order by rt.createdAt asc")
    List<Long> findIdsByUserOldestFirst(@Param("userId") long userId);

    long countByUserId(long userId);

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from RefreshToken rt where rt.user.id = :userId")
    void deleteAllByUserId(@Param("userId") long userId);
}
