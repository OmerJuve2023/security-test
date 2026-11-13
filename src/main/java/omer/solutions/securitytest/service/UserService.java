package omer.solutions.securitytest.service;

import omer.solutions.securitytest.dto.AuthResponse;
import omer.solutions.securitytest.dto.RegisterRequest;

public interface UserService {
    AuthResponse createUser(RegisterRequest request);
}
