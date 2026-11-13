package omer.solutions.securitytest.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtService {
    private final SecretKey secretKey;
    private final long accessMs, refreshMs;

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-ms}") long accessMs,
            @Value("${jwt.refresh-ms}") long refreshMs) {
        this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.accessMs = accessMs;
        this.refreshMs = refreshMs;
    }

    private String build(UserDetails u, long ttl, String type) {
        return Jwts.builder()
                .setSubject(u.getUsername()).claim("type", type)
                .claim("roles", u.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + ttl))
                .signWith(secretKey).compact();
    }

    public Claims claims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    public String accessToken(UserDetails u) {
        return build(u, accessMs, "access");
    }

    public String refreshToken(UserDetails u) {
        return build(u, refreshMs, "refresh");
    }


}
