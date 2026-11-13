package omer.solutions.securitytest;

import lombok.RequiredArgsConstructor;
import omer.solutions.securitytest.domain.User;
import omer.solutions.securitytest.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@RequiredArgsConstructor
public class SecurityTestApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityTestApplication.class, args);
    }

    @Bean
    CommandLineRunner createInitialUser(UserRepository userRepository, PasswordEncoder encoder) {
        return args -> {
            String username = "admin";
            if (userRepository.existsByUsername(username)) {
                return;
            }
            User user = new User();
            user.setUsername(username);
            user.setPassword(encoder.encode("admin"));
            user.setRole("ADMIN");
            userRepository.save(user);
            System.out.println("Initial user created: " + username + " with password: admin");
        };
    }

}
