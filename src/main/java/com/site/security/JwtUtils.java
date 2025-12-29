package com.site.security;

import org.springframework.security.oauth2.jwt.Jwt;

public final class JwtUtils {
    private JwtUtils() {}

    /** Devuelve el uid del JWT o null si no está/vale. */
    public static Long getUid(Jwt jwt) {
        if (jwt == null) return null;
        Object claim = jwt.getClaim("uid");
        if (claim == null) return null;
        if (claim instanceof Number n) return n.longValue();
        try { return Long.valueOf(String.valueOf(claim)); } catch (Exception e) { return null; }
    }
}
