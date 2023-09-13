package com.example.userAuthentication.controller;

import com.example.userAuthentication.dto.AuthRequest;
import com.example.userAuthentication.dto.JwtResponse;
import com.example.userAuthentication.dto.Product;
import com.example.userAuthentication.dto.RefreshTokenRequest;
import com.example.userAuthentication.entity.RefreshToken;
import com.example.userAuthentication.entity.UserInfo;
import com.example.userAuthentication.service.JwtService;
import com.example.userAuthentication.service.ProductService;
import com.example.userAuthentication.service.RefreshTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import javax.naming.AuthenticationException;
import java.util.List;

@RestController
@RequestMapping("/products")
public class ProductController {

    @Autowired
    private ProductService service;
    @Autowired
    private JwtService jwtService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private AuthenticationManager authenticationManager;


    @PostMapping("/signUp")
    public String addNewUser(@RequestBody UserInfo userInfo) {
        // check if user already exists
        String email = userInfo.getEmail();
        UserInfo user = service.isEmailExists(email);
        if (user != null) {
            return "user already exists";
        }
//        UserInfo user = service.getUser();
        return service.addUser(userInfo);
    }

    @GetMapping("/all")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public List<Product> getAllTheProducts() {
        return service.getProducts();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public Product getProductById(@PathVariable int id) {
        return service.getProduct(id);
    }


    @PostMapping("/login")
    public JwtResponse authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if (authentication.isAuthenticated()) {
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(authRequest.getUsername());
            return JwtResponse.builder()
                    .accessToken(jwtService.generateToken(authRequest.getUsername()))
                    .token(refreshToken.getToken()).build();
        } else {
            throw new UsernameNotFoundException("invalid user request !");
        }
    }

    @PostMapping("/refreshToken")
    public JwtResponse refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        return refreshTokenService.findByToken(refreshTokenRequest.getToken())
                .map(refreshToken -> {
                    // Step 1: Verify if the refresh token exists in the database
                    try {
                        refreshTokenService.verifyExpiration(refreshToken);
                    } catch (AuthenticationException e) {
                        //throw status code 401 and message
                        try {
                            throw new AuthenticationException("Refresh token was expired. Please make a new signin request");
                        } catch (AuthenticationException ex) {
                            throw new RuntimeException(ex);
                        }
                    }
                    // Step 2: Retrieve user information from the refresh token
                    UserInfo userInfo = refreshToken.getUserInfo();
                    // Step 3: Generate a new access token based on user information
                    String accessToken = jwtService.generateToken(userInfo.getName());
                    // Step 4: Build and return the JWT response
                    JwtResponse jwtResponse = JwtResponse.builder()
                            .accessToken(accessToken)
                            .token(refreshTokenRequest.getToken())
                            .build();
                    return jwtResponse;
                })
                .orElseThrow(() -> new RuntimeException("Refresh token is not in the database!"));

    }


}
