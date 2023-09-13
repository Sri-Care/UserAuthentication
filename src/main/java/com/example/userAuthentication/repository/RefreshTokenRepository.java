package com.example.userAuthentication.repository;

import com.example.userAuthentication.entity.RefreshToken;
import com.example.userAuthentication.entity.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Integer> {
    Optional<RefreshToken> findByToken(String token);

    void deleteByUserInfo(UserInfo userInfo);

    Optional<RefreshToken> findByUserInfo(UserInfo userInfo);
}
