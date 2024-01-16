package com.example.SpringJWT.service;

import com.example.SpringJWT.dto.CustomUserDetails;
import com.example.SpringJWT.entity.UserEntity;
import com.example.SpringJWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 2. UserDetailsService를 구현하여 요청으로 받아온 유저정보 토대로 인증을 구현 해야 한다.
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    //loadUserByUsername() 는 UserDetailsService을 상속 받았을 때 구현 해야 하는 메서드이다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //db에서 유저가 존재 하는지 판별
        UserEntity userData = userRepository.findByUsername(username);

        //존재 하는 유저인 경우 유저의 정보를 담은 dto를 반환
        if(userData != null){
            return new CustomUserDetails(userData);
        }
        return null;
    }
}
