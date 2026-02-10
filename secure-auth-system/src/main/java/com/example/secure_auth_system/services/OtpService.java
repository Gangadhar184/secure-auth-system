package com.example.secure_auth_system.services;

import com.example.secure_auth_system.exceptions.InvalidOtpException;
import com.example.secure_auth_system.models.EmailVerificationToken;
import com.example.secure_auth_system.models.PasswordResetToken;
import com.example.secure_auth_system.repositories.EmailVerificationTokenRepository;
import com.example.secure_auth_system.repositories.PasswordResetTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class OtpService {
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${otp.expiration}")
    private long otpExpiration;

    @Value("${otp.length}")
    private int otpLength;

    @Transactional
    public String generateEmailVerificationOtp(String email) {
        String otp = generateOtp();

        // Invalidate any existing OTPs for this email
        emailVerificationTokenRepository.markAllAsUsedByEmail(email);

        EmailVerificationToken token = EmailVerificationToken.builder()
                .userEmail(email)
                .otp(otp)
                .expiresAt(LocalDateTime.now().plus(Duration.ofMillis(otpExpiration)))
                .build();

        emailVerificationTokenRepository.save(token);
        log.info("Generated email verification OTP for: {}", email);

        return otp;
    }
    @Transactional
    public void validateEmailVerificationOtp(String email, String otp) {
        EmailVerificationToken token = emailVerificationTokenRepository
                .findByUserEmailAndOtp(email, otp)
                .orElseThrow(() -> new InvalidOtpException("Invalid or expired OTP"));

        if (!token.isValid()) {
            throw new InvalidOtpException("Invalid or expired OTP");
        }

        token.setUsed(true);
        emailVerificationTokenRepository.save(token);

        // Mark all other OTPs for this email as used
        emailVerificationTokenRepository.markAllAsUsedByEmail(email);

        log.info("Email verification OTP validated for: {}", email);
    }
    @Transactional
    public String generatePasswordResetOtp(String email) {
        String otp = generateOtp();

        // Invalidate any existing OTPs for this email
        passwordResetTokenRepository.markAllAsUsedByEmail(email);

        PasswordResetToken token = PasswordResetToken.builder()
                .userEmail(email)
                .otp(otp)
                .expiresAt(LocalDateTime.now().plus(Duration.ofMillis(otpExpiration)))
                .build();

        passwordResetTokenRepository.save(token);
        log.info("Generated password reset OTP for: {}", email);

        return otp;
    }
    @Transactional
    public void validatePasswordResetOtp(String email, String otp) {
        PasswordResetToken token = passwordResetTokenRepository
                .findByUserEmailAndOtp(email, otp)
                .orElseThrow(() -> new InvalidOtpException("Invalid or expired OTP"));

        if (!token.isValid()) {
            throw new InvalidOtpException("Invalid or expired OTP");
        }

        token.setUsed(true);
        passwordResetTokenRepository.save(token);

        log.info("Password reset OTP validated for: {}", email);
    }

    private String generateOtp() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            otp.append(secureRandom.nextInt(10));
        }
        return otp.toString();
    }

    // Cleanup expired tokens daily
    @Scheduled(cron = "0 0 3 * * *") // Run at 3 AM daily
    @Transactional
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        emailVerificationTokenRepository.deleteExpiredTokens(now);
        passwordResetTokenRepository.deleteExpiredTokens(now);
        log.info("Cleaned up expired OTP tokens");
    }
}
