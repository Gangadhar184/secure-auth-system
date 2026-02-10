package com.example.secure_auth_system.repositories;

import com.example.secure_auth_system.models.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    Optional<PasswordResetToken> findByUserEmailAndOtp(String userEmail, String otp);

    Optional<PasswordResetToken> findTopByUserEmailOrderByCreatedAtDesc(String userEmail);

    @Modifying
    @Query("DELETE FROM PasswordResetToken prt WHERE prt.expiresAt < :date")
    void deleteExpiredTokens(LocalDateTime date);

    @Modifying
    @Query("UPDATE PasswordResetToken prt SET prt.used = true WHERE prt.userEmail = :email")
    void markAllAsUsedByEmail(String email);
}

