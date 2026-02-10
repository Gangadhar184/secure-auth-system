package com.example.secure_auth_system.services;

import com.example.secure_auth_system.exceptions.InvalidTokenException;
import com.example.secure_auth_system.exceptions.TokenReusedException;
import com.example.secure_auth_system.models.RefreshToken;
import com.example.secure_auth_system.models.User;
import com.example.secure_auth_system.repositories.RefreshTokenRepository;
import com.example.secure_auth_system.security.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;

    @Value("${jwt.refresh-token.expiration}")
    private long refreshTokenExpiration;

    @Value("${app.max-refresh-tokens-per-user}")
    private int maxRefreshTokensPerUser;

    @Transactional
    public RefreshToken createRefreshToken(User user, HttpServletRequest request) {
        //check if user has too many active tokens and revoke the oldest one
        long activeTokenCount = refreshTokenRepository.countActiveTokensByUser(user, LocalDateTime.now());
        if(activeTokenCount >= maxRefreshTokensPerUser) {
            List<RefreshToken> userTokens = refreshTokenRepository.findByUser(user);
            userTokens.stream()
                    .filter(token -> !token.getRevoked() && !token.isExpired())
                    .sorted(Comparator.comparing(RefreshToken::getCreatedAt))
                    .limit(activeTokenCount - maxRefreshTokensPerUser + 1)
                    .forEach(token -> {
                        token.setRevoked(true);
                        token.setRevokedAt(LocalDateTime.now());
                        refreshTokenRepository.save(token);
                    });
        }

        String tokenValue = jwtUtil.generateRefreshToken(user);
        String tokenFamily = UUID.randomUUID().toString();

        RefreshToken refreshToken = RefreshToken.builder()
                .token(tokenValue)
                .user(user)
                .tokenFamily(tokenFamily)
                .expiresAt(LocalDateTime.now().plus(Duration.ofMillis(refreshTokenExpiration))  )
                .ipAddress(getClientIP(request))
                .userAgent(request.getHeader("user-Agent"))
                .build();
        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public RefreshToken rotateRefreshToken(String oldTokenValue, HttpServletRequest request) {
        RefreshToken oldToken = refreshTokenRepository.findByToken(oldTokenValue)
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        //reuse detection if token was already used, revoke entire token family
        if(oldToken.getUsed()) {
            log.warn("Token reuse detected! Revoking entire token family: {}", oldToken.getTokenFamily());
            revokeTokenFamily(oldToken.getTokenFamily());
            throw new TokenReusedException("Token reuse detected. All sessions have been terminated for security");

        }
        if(!oldToken.isValid()){
            throw new InvalidTokenException("Refresh token is invalid, expired or revoked");
        }

        //mark old token as used
        oldToken.setUsed(true);

        //create new token in same family
        String newTokenValue = jwtUtil.generateRefreshToken(oldToken.getUser());

        RefreshToken newToken = RefreshToken.builder()
                .token(newTokenValue)
                .user(oldToken.getUser())
                .tokenFamily(oldToken.getTokenFamily())
                .expiresAt(LocalDateTime.now().plus(Duration.ofMillis(refreshTokenExpiration)))
                .ipAddress(getClientIP(request))
                .userAgent(request.getHeader("User-Agent"))
                .build();

        //link old token to new token
        oldToken.setReplacedByToken(newTokenValue);
        refreshTokenRepository.save(oldToken);
        return refreshTokenRepository.save(newToken);
    }

    @Transactional
    public void revokeToken(String tokenValue) {
        refreshTokenRepository.findByToken(tokenValue).ifPresent(token -> {
            token.setRevoked(true);
            token.setRevokedAt(LocalDateTime.now());
            refreshTokenRepository.save(token);
        });
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllUserTokens(user, LocalDateTime.now());
    }

    @Transactional
    public void revokeTokenFamily(String tokenFamily) {
        refreshTokenRepository.revokeTokenFamily(tokenFamily, LocalDateTime.now());
    }

    public RefreshToken validateRefreshToken(String tokenValue) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        if (!refreshToken.isValid()) {
            throw new InvalidTokenException("Refresh token is invalid, expired, or revoked");
        }

        return refreshToken;
    }


    @Scheduled(cron = "0 0 2 * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(7);
        refreshTokenRepository.deleteExpiredTokens(cutoffDate);
        log.info("Cleaned up expired refresh tokens");
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
