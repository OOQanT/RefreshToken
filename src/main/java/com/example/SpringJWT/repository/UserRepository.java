package com.example.SpringJWT.repository;

import com.example.SpringJWT.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity,Long> {

    Boolean existsByUsername(String username);

    // username을 받아 db 테이블에서 회원을 조회
    UserEntity findByUsername(String username);
}
