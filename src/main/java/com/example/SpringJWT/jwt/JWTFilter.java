package com.example.SpringJWT.jwt;

import com.example.SpringJWT.dto.CustomUserDetails;
import com.example.SpringJWT.entity.UserEntity;
import com.example.SpringJWT.service.LogoutService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// 7. 요청으로 오는 토큰을 검증 해야 함
@Slf4j
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter{ // 요청에 대해 한 번만 작동하는 OncePerRequestFilter을 상속 받음

    private final JWTUtil jwtUtil;
    private final LogoutService logoutService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //request에서 Authorization 헤더를 찾음
        String authorization = request.getHeader("Authorization");

        //request에서 Refresh-Token  찾음
        String refreshToken = request.getHeader("Refresh-Token");

        //Authorization 헤더 검증
        if(authorization == null || !authorization.startsWith("Bearer ")){
            log.info("token null");
            filterChain.doFilter(request,response);

            return;
        }

        String token = authorization.split(" ")[1];

        //accessToken과 refreshToken이 블랙리스트에 있으면 인증 실패
        if(logoutService.isBlacklisted(token) && logoutService.isBlackListedRefresh(refreshToken)){
            log.info("Blacklisted token detected: {}",token);

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        log.info("authorization now");

        //토큰 소멸시간 검증
        if(jwtUtil.isExpired(token)){ // 토큰이 만료인 경우 인증 실패
            log.info("token expired");
            filterChain.doFilter(request,response);
            return;
        }

        //토큰에서 username 과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        //UserEntity를 생성하여 값 set
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword"); // 임시 비밀번호를 넣음 정확한 비밀번호를 넣을 필요가 없음
        userEntity.setRole(role);

        //UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails,null,customUserDetails.getAuthorities());

        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request,response);

    }
}
