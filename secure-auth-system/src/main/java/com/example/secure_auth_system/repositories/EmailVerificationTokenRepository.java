package com.example.secure_auth_system.repositories;




import com.example.secure_auth_system.models.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {

    Optional<EmailVerificationToken> findByUserEmailAndOtp(String userEmail, String otp);

    Optional<EmailVerificationToken> findTopByUserEmailOrderByCreatedAtDesc(String userEmail);

    @Modifying
    @Query("DELETE FROM EmailVerificationToken evt WHERE evt.expiresAt < :date")
    void deleteExpiredTokens(LocalDateTime date);

    @Modifying
    @Query("UPDATE EmailVerificationToken evt SET evt.used = true WHERE evt.userEmail = :email")
    void markAllAsUsedByEmail(String email);
}
