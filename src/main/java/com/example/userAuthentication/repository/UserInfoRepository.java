package com.example.userAuthentication.repository;

import com.example.userAuthentication.entity.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserInfoRepository extends JpaRepository<UserInfo, Integer> {
    Optional<UserInfo> findByName(String username);

    // Find user by email
    Optional<UserInfo> findByEmail(String email);

    // Find user by email and password
    Optional<UserInfo> findByEmailAndPassword(String email, String password);



}
