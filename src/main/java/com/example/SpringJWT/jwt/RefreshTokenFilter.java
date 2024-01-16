package com.example.SpringJWT.jwt;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class RefreshTokenFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

   /* @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse) response;

        String refreshToken = req.getHeader("Refresh_Token");

        if(refreshToken != null){
            // Refresh Token이 유효한 경우
            if(!jwtUtil.isExpired(refreshToken)){
                //새로운 accessToken 생성
                String newAccessToken = jwtUtil.createJwt(jwtUtil.getUsername(refreshToken), jwtUtil.getRole(refreshToken),600 * 600 * 10L );

                res.addHeader("Authorization", "Bearer " + newAccessToken);
            }
        }

        chain.doFilter(req,res);
    }*/

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String refreshToken = request.getHeader("Refresh_Token");

        if(refreshToken != null){
            // Refresh Token이 유효한 경우
            if(!jwtUtil.isExpired(refreshToken)){
                //새로운 accessToken 생성
                String newAccessToken = jwtUtil.createJwt(jwtUtil.getUsername(refreshToken), jwtUtil.getRole(refreshToken),600 * 600 * 10L );

                response.addHeader("Authorization", "Bearer " + newAccessToken);
            }
        }

        filterChain.doFilter(request,response);
    }
}
