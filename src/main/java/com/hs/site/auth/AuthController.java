package com.hs.site.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import com.hs.site.auth.password.PasswordResetService;
import com.hs.site.auth.token.RefreshTokenService;
import com.hs.site.auth.user.UserService;
import com.hs.site.auth.verification.EmailVerificationService;
import com.hs.site.security.JWTService;

import java.util.Map;

import static com.hs.site.security.JwtUtils.getUid;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordResetService passwordResetService;
    private final EmailVerificationService emailVerificationService;
    private final JWTService jwtService;

    public AuthController(UserService userService,
                          RefreshTokenService refreshTokenService,
                          PasswordResetService passwordResetService,
                          EmailVerificationService emailVerificationService,
                          JWTService jwtService) {
        this.userService = userService;
        this.refreshTokenService = refreshTokenService;
        this.passwordResetService = passwordResetService;
        this.emailVerificationService = emailVerificationService;
        this.jwtService = jwtService;
    }

    @Operation(
            summary = "Registrar usuario",
            description = "Crea un usuario y envía email de verificación.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(example = """
                { "username":"johndoe", "email":"john@example.com", "password":"StrongPass123" }
                """))
            ),
            responses = {
                    @ApiResponse(responseCode = "200", description = "Registrado"),
                    @ApiResponse(responseCode = "400", description = "Datos inválidos")
            }
    )
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        var user = userService.register(body.get("username"), body.get("email"), body.get("password"));
        emailVerificationService.send(user);
        return ResponseEntity.ok(Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "email", user.getEmail(),
                "enabled", user.isEnabled(),
                "createdAt", user.getCreatedAt()
        ));
    }

    @Operation(
            summary = "Login",
            description = "Autentica por username o email y devuelve access + refresh fijo (sin rotación).",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(example = """
                { "usernameOrEmail":"johndoe", "password":"StrongPass123" }
                """))
            ),
            responses = {
                    @ApiResponse(responseCode = "200", description = "OK",
                            content = @Content(mediaType = "application/json",
                                    examples = @ExampleObject(value = """
                    {
                      "tokenType":"Bearer",
                      "accessToken":"<jwt>",
                      "expiresIn":3600,
                      "refreshToken":"<refresh>"
                    }
                    """))),
                    @ApiResponse(responseCode = "401", description = "Credenciales inválidas")
            }
    )
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        var user = userService.authenticate(body.get("usernameOrEmail"), body.get("password"));
        String access = jwtService.generate(user.getUsername(), Map.of("uid", user.getId()));
        String refresh = refreshTokenService.create(user);
        return ResponseEntity.ok(Map.of(
                "tokenType", "Bearer",
                "accessToken", access,
                "expiresIn", jwtService.getExpirationSeconds(),
                "refreshToken", refresh
        ));
    }

    @Operation(
            summary = "Refrescar access token",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(schema = @Schema(example = """
            { "refreshToken":"<refresh>" }
            """))
            ),
            responses = {
                    @ApiResponse(responseCode = "200", description = "OK"),
                    @ApiResponse(responseCode = "401", description = "Refresh inválido")
            }
    )
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> body) {
        var userRef = refreshTokenService.validateAndGetUserRef(body.get("refreshToken")); // NO rotación
        String newAccess = jwtService.generate(userRef.username(), Map.of("uid", userRef.id()));
        return ResponseEntity.ok(Map.of(
                "tokenType", "Bearer",
                "accessToken", newAccess,
                "expiresIn", jwtService.getExpirationSeconds(),
                "refreshToken", body.get("refreshToken")
        ));
    }

    @Operation(
            summary = "Cerrar sesión (un dispositivo)",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(schema = @Schema(example = """
            { "refreshToken":"<refresh>" }
            """))
            ),
            responses = @ApiResponse(responseCode = "204", description = "Eliminado")
    )
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody Map<String, String> body) {
        refreshTokenService.revoke(body.get("refreshToken"));
        return ResponseEntity.noContent().build();
    }

    @Operation(
            summary = "Cerrar sesión en todos los dispositivos",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(schema = @Schema(example = """
            { "refreshToken":"<refresh>" }
            """))
            ),
            responses = @ApiResponse(responseCode = "204", description = "Todas las sesiones eliminadas")
    )
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(@RequestBody Map<String, String> body) {
        var userRef = refreshTokenService.validateAndGetUserRef(body.get("refreshToken"));
        refreshTokenService.revokeAllByUserId(userRef.id());
        return ResponseEntity.noContent().build();
    }

    @Operation(
            summary = "Solicitar restablecimiento de contraseña",
            description = "Siempre responde 204 por privacidad.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(schema = @Schema(example = """
            { "email":"john@example.com" }
            """))
            ),
            responses = @ApiResponse(responseCode = "204", description = "Enviado si existe")
    )
    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(@RequestBody Map<String, String> body) {
        passwordResetService.requestReset(body.getOrDefault("email", ""));
        return ResponseEntity.noContent().build();
    }

    @Operation(
            summary = "Restablecer contraseña",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(schema = @Schema(example = """
            { "token":"<token>", "newPassword":"NewStrongPass456" }
            """))
            ),
            responses = {
                    @ApiResponse(responseCode = "204", description = "Cambiada"),
                    @ApiResponse(responseCode = "400", description = "Token inválido/expirado")
            }
    )
    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(@RequestBody Map<String, String> body) {
        passwordResetService.reset(body.get("token"), body.get("newPassword"));
        return ResponseEntity.noContent().build();
    }

    @Operation(
            summary = "Cambiar contraseña (usuario autenticado)",
            description = "Verifica la contraseña actual y establece la nueva. No cierra sesiones.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(example = """
                { "currentPassword":"OldPass123", "newPassword":"NewStrongPass456" }
                """))
            ),
            responses = {
                    @ApiResponse(responseCode = "204", description = "Cambiada"),
                    @ApiResponse(responseCode = "400", description = "Datos inválidos / contraseña actual incorrecta"),
                    @ApiResponse(responseCode = "401", description = "No autenticado")
            }
    )
    @PutMapping("/users/me/password")
    public ResponseEntity<Void> changeOwnPassword(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody Map<String, String> body
    ) {
        Long uid = getUid(jwt);
        if (uid == null) throw new org.springframework.security.access.AccessDeniedException("JWT sin uid");

        String current = body.getOrDefault("currentPassword", "");
        String next = body.getOrDefault("newPassword", "");

        userService.changePassword(uid, current, next);
        refreshTokenService.revokeAllByUserId(uid);

        return ResponseEntity.noContent().build();
    }
}
