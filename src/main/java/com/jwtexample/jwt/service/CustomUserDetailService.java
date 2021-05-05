package com.jwtexample.jwt.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class CustomUserDetailService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(username.equals("test1")){
            return  new User("test1","password",new ArrayList<>()); // this arrayList basically contains list of permission/Authorities That user has.
        }else {
            throw new UsernameNotFoundException("user not found!!!");
        }
    }
}
