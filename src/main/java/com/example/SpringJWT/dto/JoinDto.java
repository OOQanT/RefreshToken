package com.example.SpringJWT.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JoinDto {

    private String username;
    private String password;

    public JoinDto(String username, String password) {
        this.username = username;
        this.password = password;
    }
}
