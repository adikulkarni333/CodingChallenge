package com.altemetrik.challenge.services;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Value("${user}")
    private String userName;

    @Value("${password}")
    private String password;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        if (userName.equals(username)) {
            return new User(userName, password, new ArrayList<>());
        }

        throw new UsernameNotFoundException("Invalid user with name: " + username);
    }

}
