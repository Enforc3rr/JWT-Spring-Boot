package com.jwtexample.jwt.security;

import com.jwtexample.jwt.service.CustomUserDetailService;
import com.jwtexample.jwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//This class is basically used as a filter i.e. verify-token middleware in case of node , it basically intercepts the requests coming in with token check if it's valid.
@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private CustomUserDetailService customUserDetailService;
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        /*
        Get Header
        Starts with Bearer or not
        validate
         */
        //It checks for Authorization Param in Header.
        String rqstTokenHeader = httpServletRequest.getHeader("Authorization");
        String username = null;
        String jwtToken = null;
        //Current format of sending token is that it should start with Bearer .
        if(rqstTokenHeader!=null && rqstTokenHeader.startsWith("Bearer ")){
            //we extract token part of from sent in data.
            jwtToken = rqstTokenHeader.substring(7);
            try {
              //fetching username/sub from the received token
              username = this.jwtUtil.extractUsername(jwtToken);
            }catch (Exception e){
                e.printStackTrace();
            }
            //checking if that user exists or  not.
            UserDetails userDetails = this.customUserDetailService.loadUserByUsername(username);

             /*
                The SecurityContext and SecurityContextHolder are two fundamental classes of Spring Security.
                The SecurityContext is used to store the details of the currently authenticated user, also known as a principle.
                The SecurityContextHolder is just a helper class to work with SecurityContext.
                That's why we need to make sure it's authentication part is null as it tells us that no user has been authenticated yet.
             */
            if(username !=null && SecurityContextHolder.getContext().getAuthentication()==null){
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                //WebAuthenticationDetailsSource is used to create object which contains details about the rqst , these things would've happened automatically.
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                //Setting it into the context.
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }else{
                System.out.println("token not valid");
            }
        }
        //it basically channels our request and response  fwd , as everything which  is above is correct...!!
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }
}
