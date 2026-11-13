package omer.solutions.securitytest.service.impl;

import lombok.RequiredArgsConstructor;
import omer.solutions.securitytest.domain.User;
import omer.solutions.securitytest.dto.AuthResponse;
import omer.solutions.securitytest.dto.RegisterRequest;
import omer.solutions.securitytest.repository.UserRepository;
import omer.solutions.securitytest.service.JwtService;
import omer.solutions.securitytest.service.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImp implements UserService {

    private final PasswordEncoder encoder;
    private final UserRepository repository;
    private final JwtService jwtService;

    @Override
    public AuthResponse createUser(RegisterRequest request) {
        if (repository.existsByUsername(request.username())) {
            throw new RuntimeException("Username already exists");
        }
        User user = new User();
        user.setUsername(request.username());
        user.setPassword(encoder.encode(request.password()));
        user.setRole("USER");

        User saveUser = repository.save(user);

        return new AuthResponse(
                jwtService.accessToken(saveUser),
                jwtService.refreshToken(saveUser)
        );
    }

}
