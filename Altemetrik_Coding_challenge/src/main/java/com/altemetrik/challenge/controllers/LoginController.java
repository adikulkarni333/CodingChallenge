package com.altemetrik.challenge.controllers;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.altemetrik.challenge.model.User;
import com.altemetrik.challenge.services.CustomUserDetailsService;
import com.altemetrik.challenge.utils.JwtUtils;

@RestController
public class LoginController {

    private static final String JWT_KEY = "jwt-token";

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService userDetailsSvc;

    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping("/authenticate")
    public String authenticate(@RequestBody User user, HttpServletResponse response) throws Exception {
        try {
            authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        } catch (BadCredentialsException ex) {
            throw new Exception("Incorrect username or password");
        }
        final UserDetails userDetails = userDetailsSvc.loadUserByUsername(user.getUsername());
        response.setHeader(JWT_KEY, jwtUtils.generateToken(userDetails));
        return "Authenticated successfully. Now you can call any REST api with valid JWT token which is set as 'jwt-token' header";
    }

    @GetMapping("/hello")
    public ResponseEntity<String> sayHello() {
        return new ResponseEntity<String>("Hello..!!", HttpStatus.OK);
    }

}
