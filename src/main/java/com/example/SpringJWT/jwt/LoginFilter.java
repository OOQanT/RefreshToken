package com.example.SpringJWT.jwt;

import com.example.SpringJWT.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

// 1. 로그인 필터 만들기, 만들고 SecurityConfig에 등록
//securityFilterChain에서 formLogin을 disable했기 때문에 이를 대체하는 UsernamePasswordAuthenticationFilter를 만들어 주어야 함
@Slf4j
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // 5. 만든 토큰생성기를 주입 받고 로그인을 성공했을 때 사용
    private final JWTUtil jwtUtil;

    /*필수로 구현 해야 하는 메서드이다. 여기서 인증을 시도하는 사용자의 정보를 UsernamePasswordAuthenticationToken이라는 박스에 담아서
    AuthenticationManager에 전달 해야 한다.*/
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String username = obtainUsername(request); //obtainUsername()으로 username을 얻어올 수 있음
        String password = obtainPassword(request); //obtainPassword()으로 password를 얻어올 수 있음

        //얻어온 유저 정보를 UsernamePasswordAuthenticationToken에 담는다
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username,password,null);

        // 유저 정보를 담은 토큰을 AuthenticationManager에 보낸다.
        return authenticationManager.authenticate(authToken);

        //이 후 인증에 성공할 경우 successfulAuthentication()메서드가 자동으로 실행되고
        //실패 하면 unsuccessfulAuthentication메서드가 실행된다.
    }

    // 6. 토큰을 생성하고 response에 보냄
    // 메서드의 Authentication authResult 가 위에서 attemptAuthentication()이 성공했을 때의 유저정보를 담고 있음
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        //username을 뽑아냄
        CustomUserDetails customUserDetails = (CustomUserDetails)authResult.getPrincipal();
        String username = customUserDetails.getUsername();

        //role값을 뽑아냄
        Collection<? extends GrantedAuthority> authorities = customUserDetails.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

       /* //토큰 생성
        String token = jwtUtil.createJwt(username,role, 600*600*10L);
        //Authorization라는 헤더에 토큰을 넣음
        response.addHeader("Authorization","Bearer " + token);*/

        //토큰 생성 accessToken + refreshToken
        Map<String,String> tokens = jwtUtil.createJwtTokenAndRefreshToken(username,role,60000L,86400000L);

        // Authorization 헤더에 AccessToken 추가
        response.addHeader("Authorization","Bearer " + tokens.get("accessToken"));

        // Response 헤더에 ResponseToken 추가
        response.addHeader("Refresh-Token", tokens.get("refreshToken"));

        log.info("success");
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(401);
        log.info("fail");
    }
}
