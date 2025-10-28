package com.hs.site.auth.token;

import jakarta.persistence.*;

import com.hs.site.auth.user.User;

import java.time.Instant;

@Entity
@Table(name = "refresh_tokens",
        indexes = {
                @Index(name = "idx_rt_token_hash", columnList = "token_hash", unique = true),
                @Index(name = "idx_rt_user", columnList = "user_id")
        })
public class RefreshToken {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, foreignKey = @ForeignKey(name = "fk_rt_user"))
    private User user;

    /** Hash base64url(SHA-256(token)) */
    @Column(name = "token_hash", unique = true, length = 64, nullable = false)
    private String tokenHash;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = Instant.now();
    }

    // getters / setters
    public Long getId() { return id; }
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    public String getTokenHash() { return tokenHash; }
    public void setTokenHash(String tokenHash) { this.tokenHash = tokenHash; }
    public Instant getCreatedAt() { return createdAt; }
}
