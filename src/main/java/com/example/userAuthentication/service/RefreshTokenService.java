package com.example.userAuthentication.service;

import com.example.userAuthentication.entity.RefreshToken;
import com.example.userAuthentication.entity.UserInfo;
import com.example.userAuthentication.repository.RefreshTokenRepository;
import com.example.userAuthentication.repository.UserInfoRepository;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private UserInfoRepository userInfoRepository;

    public RefreshToken createRefreshToken(String username) {
        // check if user already has a refresh token
        Optional<RefreshToken> refreshTokenOptional = refreshTokenRepository.findByUserInfo(userInfoRepository.findByName(username).get());
        // delete the old refresh token
        refreshTokenOptional.ifPresent(refreshToken -> refreshTokenRepository.delete(refreshToken));

        RefreshToken refreshToken = RefreshToken.builder()
                .userInfo(userInfoRepository.findByName(username).get())
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(600000))//10
                .build();
        return refreshTokenRepository.save(refreshToken);
    }


    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }


    public RefreshToken verifyExpiration(RefreshToken token) throws AuthenticationException {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
//            throw new RuntimeException(token.getToken() + " Refresh token was expired. Please make a new signin request");
            //throw status code 401 and message
            throw new AuthenticationException("Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

}
