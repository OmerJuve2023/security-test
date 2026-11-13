package omer.solutions.securitytest.dto;

public record AuthResponse(
        String accessToken,
        String refreshToken
) {
}
