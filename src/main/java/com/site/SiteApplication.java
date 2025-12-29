package com.site;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

import com.site.auth.user.UserRepository;
import com.site.auth.user.UserService;

import org.springframework.context.annotation.Bean;
import org.springframework.boot.CommandLineRunner;

@SpringBootApplication
@EnableScheduling
public class SiteApplication {

    public static void main(String[] args) {
        SpringApplication.run(SiteApplication.class, args);
    }

    @Bean
    CommandLineRunner seedDefaultUser(UserRepository userRepo, UserService userService) {
        return args -> {
            final String username = "oscar";
            final String email = "oscar@seed.local"; // correo fijo para la seed
            final String rawPassword = "oscar";

            userRepo.findByUsername(username)
                    .or(() -> userRepo.findByEmail(email))
                    .ifPresentOrElse(existing -> {
                        // Asegura que está verificado y con la contraseña de la seed
                        if (!existing.isEnabled()) {
                            existing.setEnabled(true);
                            userRepo.save(existing);
                        }
                        userService.forceChangePassword(existing.getId(), rawPassword);
                    }, () -> {
                        // Crea el usuario si no existe
                        var u = userService.register(username, email, rawPassword);
                        u.setEnabled(true); // marcado como verificado
                        userRepo.save(u);
                    });
        };
    }
}
