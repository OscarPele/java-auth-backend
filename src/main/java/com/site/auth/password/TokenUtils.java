package com.site.auth.password;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

final class TokenUtils {
    private static final SecureRandom RNG = new SecureRandom();

    static String newBase64UrlToken() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    static String sha256Base64Url(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(dig);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private TokenUtils() {}
}
