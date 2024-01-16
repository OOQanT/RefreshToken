package com.example.SpringJWT.jwt;

import com.example.SpringJWT.service.LogoutService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtLogoutFilter implements LogoutHandler {

    private final LogoutService logoutService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = extractToken(request);
        String refreshToken = extractRefreshToken(request);
        if(token != null){
            logoutService.addToBlacklist(token,refreshToken);
            log.info("accessTokenIsBlocked={}",token);
            log.info("refreshTokenIsBlocked={}",refreshToken);
        }
        response.setStatus(HttpServletResponse.SC_OK);
    }

    private String extractToken(HttpServletRequest request){
        String authorizationHeader = request.getHeader("Authorization");
        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            return authorizationHeader.substring(7);
        }
        return null;
    }

    private String extractRefreshToken(HttpServletRequest request){
        String refreshTokenHeader = request.getHeader("Refresh-Token");
        if(refreshTokenHeader != null){
            return refreshTokenHeader;
        }
        return null;
    }
}
