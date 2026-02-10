package com.example.secure_auth_system.models;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 500)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column
    private LocalDateTime revokedAt;

    @Column(nullable = false)
    private Boolean revoked;

    @Column(nullable = false)
    private Boolean used;

    // Token family for rotation tracking - all tokens in a refresh chain share the same family ID
    @Column(nullable = false, length = 100)
    private String tokenFamily;

    // IP address for security auditing
    @Column(length = 45)
    private String ipAddress;

    // User agent for device tracking
    @Column(length = 500)
    private String userAgent;

    // Replaced by token - tracks which new token replaced this one during rotation
    @Column(length = 500)
    private String replacedByToken;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        if (revoked == null) revoked = false;
        if (used == null) used = false;
    }

    public boolean isValid() {
        return !revoked && !used && LocalDateTime.now().isBefore(expiresAt);
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }
}
