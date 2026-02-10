package com.example.secure_auth_system.services;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    @Async
    public void sendVerificationEmail(String to, String otp) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject("Email Verification - secure auth system ");
            message.setText(buildVerificationEmailBody(otp));
            mailSender.send(message);
            log.info("Verification email sent to : {}", to);
        }catch (Exception e) {
            log.error("Failed to send verification email to: {}", to, e);
            throw new RuntimeException("Failed to send verification email");
        }
    }
    @Async
    public void sendPasswordResetEmail(String to, String otp) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject("Password Reset Request - Secure Auth System");
            message.setText(buildPasswordResetEmailBody(otp));

            mailSender.send(message);
            log.info("Password reset email sent to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}", to, e);
            throw new RuntimeException("Failed to send password reset email");
        }
    }

    @Async
    public void sendPasswordChangedNotification(String to) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject("Password Changed - Secure Auth System");
            message.setText(buildPasswordChangedEmailBody());

            mailSender.send(message);
            log.info("Password changed notification sent to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send password changed notification to: {}", to, e);
        }
    }

    private String buildVerificationEmailBody(String otp) {
        return String.format("""
                Hello,
                
                Thank you for registering with Secure Auth System!
                
                Your email verification code is: %s
                
                This code will expire in 10 minutes.
                
                If you didn't request this verification, please ignore this email.
                
                Best regards,
                Secure Auth System Team
                """, otp);
    }

    private String buildPasswordResetEmailBody(String otp) {
        return String.format("""
                Hello,
                
                We received a request to reset your password.
                
                Your password reset code is: %s
                
                This code will expire in 10 minutes.
                
                If you didn't request a password reset, please ignore this email and ensure your account is secure.
                
                Best regards,
                Secure Auth System Team
                """, otp);
    }

    private String buildPasswordChangedEmailBody() {
        return """
                Hello,
                
                This is a confirmation that your password was successfully changed.
                
                If you did not make this change, please contact our support team immediately.
                
                Best regards,
                Secure Auth System Team
                """;
    }
}
