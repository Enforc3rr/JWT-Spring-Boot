package com.jwtexample.jwt.controller;

import com.jwtexample.jwt.model.JwtRequest;
import com.jwtexample.jwt.model.JwtResponse;
import com.jwtexample.jwt.service.CustomUserDetailService;
import com.jwtexample.jwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class JwtController {
    /*
    AuthenticationManager is interface that has authenticate function associated with it , which takes in
    object of UsernamePasswordAuthenticationToken that takes in two args username and password.
    UsernamePasswordAuthenticationToken is the standard token that spring MVC uses for username and password.
    Basically it means that when we use normal form based login then internally this UsernamePasswordAuthenticationToken is
    called for authentication.
     */
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private CustomUserDetailService customUserDetailService;
    @Autowired
    private JwtUtil jwtUtil;
    /*
    ResponseEntity represents the whole HTTP response: status code, headers, and body. As a result, we can use it to fully configure the HTTP response.
    ResponseEntity.ok()
        .header("Custom-Header", "foo")
        .body("Custom header set");
     */
    /*
    JwtRequest class contains the format in which our incoming request is going to be in.
    JwtResponse class contains the format our response is going to be in.
    */
    @PostMapping("/token")
    public ResponseEntity<?> generateToken(@RequestBody JwtRequest jwtRequest) throws Exception {
        try {
            this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(jwtRequest.getUsername(),jwtRequest.getPassword()));
        }catch (UsernameNotFoundException e){
            e.printStackTrace();
            throw new Exception("Bad Cred");
        }
        //Once we have reached here , that means we didn't find any error while authentication and we are safe to proceed forward.
        /*
        Since , generateToken method in jwtUtil takes in instance of UserDetailsService . And we are using loadUserByUsername Method
        of our customUserDetailService to find and search for the user from the database and it returns the a obj of User class
        (which is inbuilt class of spring security but we can take make in our custom User Class).
         */
        final UserDetails userDetails = this.customUserDetailService.loadUserByUsername(jwtRequest.getUsername());
        //signs in the username into the token's header.
        final String token = this.jwtUtil.generateToken(userDetails);
        return  new ResponseEntity<>(new JwtResponse(token), HttpStatus.OK);
    }

}
