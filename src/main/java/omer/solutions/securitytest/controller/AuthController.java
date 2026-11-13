package omer.solutions.securitytest.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import omer.solutions.securitytest.dto.AuthResponse;
import omer.solutions.securitytest.dto.LoginRequest;
import omer.solutions.securitytest.dto.RegisterRequest;
import omer.solutions.securitytest.service.JwtService;
import omer.solutions.securitytest.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth/v1")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authManager;
    private final JwtService jwt;
    private final UserService userService;

    @PostMapping("/register")
    ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = userService.createUser(request);
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);

    }

    @PostMapping("/login")
    ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );
        UserDetails user = (UserDetails) authentication.getPrincipal();
        AuthResponse response = new AuthResponse(
                jwt.accessToken(user),
                jwt.refreshToken(user)
        );
        return ResponseEntity.ok(response);
    }
}

