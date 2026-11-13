package omer.solutions.securitytest.dto;

public record LoginRequest(
        String username,
        String password
) {
}
