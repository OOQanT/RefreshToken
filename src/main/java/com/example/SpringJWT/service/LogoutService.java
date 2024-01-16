package com.example.SpringJWT.service;


import lombok.Getter;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@Getter
public class LogoutService {
    private Set<String> blacklist = new HashSet<>();
    private Set<String> blacklistRefresh = new HashSet<>();

    public void addToBlacklist(String token,String refreshToken){
        blacklist.add(token);
        blacklistRefresh.add(refreshToken);
    }

    public boolean isBlacklisted(String token){
        return blacklist.contains(token);
    }

    public boolean isBlackListedRefresh(String refreshToken){
        return blacklistRefresh.contains(refreshToken);
    }

}
