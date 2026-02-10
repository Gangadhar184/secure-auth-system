package com.example.secure_auth_system.services;

import com.example.secure_auth_system.dtos.*;
import com.example.secure_auth_system.exceptions.EmailAlreadyExistsException;
import com.example.secure_auth_system.exceptions.EmailNotVerifiedException;
import com.example.secure_auth_system.exceptions.InvalidCredentialsException;
import com.example.secure_auth_system.exceptions.UserNotFoundException;
import com.example.secure_auth_system.models.RefreshToken;
import com.example.secure_auth_system.models.Role;
import com.example.secure_auth_system.models.User;
import com.example.secure_auth_system.repositories.UserRepository;
import com.example.secure_auth_system.security.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Arrays;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final OtpService otpService;
    private final EmailService emailService;

    @Value("${cookie.secure}")
    private boolean cookieSecure;

    @Value("${cookie.same-site}")
    private String cookieSameSite;

    @Value("${cookie.domain}")
    private String cookieDomain;

    @Value("${app.require-email-verification}")
    private boolean requireEmailVerification;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email already registered");
        }
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .role(Role.USER)
                .emailVerified(false)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();

        userRepository.save(user);
        log.info("User registered: {}", user.getEmail());

        // Generate and send verification OTP
        String otp = otpService.generateEmailVerificationOtp(user.getEmail());
        emailService.sendVerificationEmail(user.getEmail(), otp);

        return AuthResponse.builder()
                .message("Registration successful. Please verify your email.")
                .emailVerified(false)
                .requiresVerification(true)
                .build();
    }

    @Transactional
    public AuthResponse login(LoginRequest request, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        // Authenticate user
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
        } catch (Exception e) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Check if email verification is required
        if (requireEmailVerification && !user.getEmailVerified()) {
            throw new EmailNotVerifiedException("Please verify your email before logging in");
        }

        // Generate tokens
        String accessToken = jwtUtil.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user, httpRequest);

        // Set tokens in cookies
        setAuthCookies(httpResponse, accessToken, refreshToken.getToken());

        log.info("User logged in: {}", user.getEmail());

        return AuthResponse.builder()
                .message("Login successful")
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .role(user.getRole().name())
                .emailVerified(user.getEmailVerified())
                .requiresVerification(false)
                .build();
    }

    @Transactional
    public void verifyEmail(VerifyEmailRequest request) {
        // Validate OTP
        otpService.validateEmailVerificationOtp(request.getEmail(), request.getOtp());

        // Update user email verification status
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        user.setEmailVerified(true);
        userRepository.save(user);

        log.info("Email verified for user: {}", user.getEmail());
    }

    @Transactional
    public void resendVerificationEmail(ResendVerificationRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (user.getEmailVerified()) {
            throw new IllegalStateException("Email already verified");
        }

        String otp = otpService.generateEmailVerificationOtp(user.getEmail());
        emailService.sendVerificationEmail(user.getEmail(), otp);

        log.info("Verification email resent to: {}", user.getEmail());
    }

    @Transactional
    public AuthResponse refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshTokenValue = extractRefreshTokenFromCookie(request);

        if (refreshTokenValue == null) {
            throw new InvalidCredentialsException("Refresh token not found");
        }

        // Rotate refresh token (includes reuse detection)
        RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(refreshTokenValue, request);

        // Generate new access token
        String accessToken = jwtUtil.generateAccessToken(newRefreshToken.getUser());

        // Set new tokens in cookies
        setAuthCookies(response, accessToken, newRefreshToken.getToken());

        log.info("Tokens refreshed for user: {}", newRefreshToken.getUser().getEmail());

        return AuthResponse.builder()
                .message("Tokens refreshed successfully")
                .email(newRefreshToken.getUser().getEmail())
                .build();
    }

    @Transactional
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String refreshTokenValue = extractRefreshTokenFromCookie(request);

        if (refreshTokenValue != null) {
            refreshTokenService.revokeToken(refreshTokenValue);
        }

        // Clear cookies
        clearAuthCookies(response);

        // Clear security context
        SecurityContextHolder.clearContext();

        log.info("User logged out");
    }

    @Transactional
    public void forgotPassword(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        String otp = otpService.generatePasswordResetOtp(user.getEmail());
        emailService.sendPasswordResetEmail(user.getEmail(), otp);

        log.info("Password reset OTP sent to: {}", user.getEmail());
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        // Validate OTP
        otpService.validatePasswordResetOtp(request.getEmail(), request.getOtp());

        // Update password
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setLastPasswordChange(LocalDateTime.now());
        userRepository.save(user);

        // Revoke all refresh tokens for security
        refreshTokenService.revokeAllUserTokens(user);

        // Send notification email
        emailService.sendPasswordChangedNotification(user.getEmail());

        log.info("Password reset successful for user: {}", user.getEmail());
    }

    @Transactional
    public void changePassword(ChangePasswordRequest request, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Verify current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new InvalidCredentialsException("Current password is incorrect");
        }

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setLastPasswordChange(LocalDateTime.now());
        userRepository.save(user);

        // Revoke all refresh tokens to force re-login on all devices
        refreshTokenService.revokeAllUserTokens(user);

        // Clear cookies from current session
        clearAuthCookies(httpResponse);

        // Clear security context
        SecurityContextHolder.clearContext();

        // Send notification email
        emailService.sendPasswordChangedNotification(user.getEmail());

        log.info("Password changed for user: {}", user.getEmail());
    }

    public UserProfileResponse getCurrentUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        return UserProfileResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .role(user.getRole().name())
                .emailVerified(user.getEmailVerified())
                .createdAt(user.getCreatedAt())
                .lastPasswordChange(user.getLastPasswordChange())
                .build();
    }

    private void setAuthCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        // Access token cookie
        Cookie accessTokenCookie = createCookie("accessToken", accessToken, 15 * 60); // 15 minutes
        response.addCookie(accessTokenCookie);

        // Refresh token cookie
        Cookie refreshTokenCookie = createCookie("refreshToken", refreshToken, 7 * 24 * 60 * 60); // 7 days
        response.addCookie(refreshTokenCookie);
    }

    private void clearAuthCookies(HttpServletResponse response) {
        Cookie accessTokenCookie = createCookie("accessToken", "", 0);
        Cookie refreshTokenCookie = createCookie("refreshToken", "", 0);

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }

    private Cookie createCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(cookieSecure);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);

        // SameSite attribute - requires servlet 6.0+ or manual header setting
        if (!"localhost".equals(cookieDomain)) {
            cookie.setDomain(cookieDomain);
        }

        return cookie;
    }

    private String extractRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            return Arrays.stream(request.getCookies())
                    .filter(cookie -> "refreshToken".equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElse(null);
        }
        return null;
    }
}
