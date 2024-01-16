package com.example.SpringJWT.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

// 4. 토큰을 생성하는 클래스
@Component
public class JWTUtil {

    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}")String secret){
        // 설정 파일에 있는 키값을 암호화 하고 객체화 함
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    //토큰에서 username을 뽑아내는 메서드
    public String getUsername(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username",String.class);
    }

    //토큰에서 role을 뽑아내는 메서드
    public String getRole(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role",String.class);
    }

    //토큰에서 만료시간을 뽑아내는 메서드
    public Boolean isExpired(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    //로그인을 성공했을 때 successfulHandler를 통해 username, role, expireMs를 받고 토큰을 생성
    public String createJwt(String username,String role, Long expireMs){
        return Jwts.builder()
                .claim("username",username)
                .claim("role",role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expireMs))
                .signWith(secretKey)
                .compact();
    }

    public Map<String,String> createJwtTokenAndRefreshToken(String username, String role, Long expireMs, Long refreshExpireMs){
        String accessToken = Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expireMs))
                .signWith(secretKey)
                .compact();

        String refreshToken = Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + refreshExpireMs))
                .signWith(secretKey)
                .compact();

        Map<String,String> tokens = new HashMap<>();
        tokens.put("accessToken",accessToken);
        tokens.put("refreshToken",refreshToken);

        return tokens;
    }
}
