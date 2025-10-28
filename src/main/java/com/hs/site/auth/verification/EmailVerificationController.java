package com.hs.site.auth.verification;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.hs.site.auth.user.UserService;

@RestController
@RequestMapping("/auth")
public class EmailVerificationController {

    private final EmailVerificationService verification;
    private final UserService users;

    public EmailVerificationController(EmailVerificationService verification, UserService users) {
        this.verification = verification;
        this.users = users;
    }

    @Operation(summary = "Solicitar/reenviar verificación (si existe y no verificado). Responde 204 siempre.")
    @PostMapping("/verify-email/request")
    public ResponseEntity<Void> request(@RequestBody VerifyEmailRequest body) {
        users.findByEmailIgnoreCase(body.email()).ifPresent(u -> {
            if (!u.isEnabled()) verification.send(u);
        });
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/verify-email")
    public ResponseEntity<Void> verify(@RequestParam("token") String token) {
        String redirectTo = verification.confirmAndGetRedirectUrl(token);
        return ResponseEntity.status(302).header("Location", redirectTo).build();
    }

    public record VerifyEmailRequest(@NotBlank @Email String email) {}
}
