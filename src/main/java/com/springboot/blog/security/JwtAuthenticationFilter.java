package com.springboot.blog.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //get jwt token from http request
       String token = getJwtFromRequest(request);


      //validate token
       if(StringUtils.hasText(token) && jwtTokenProvider.validateToken(token))
       {
           // load username associated with the token
           String username = jwtTokenProvider.getUsernameFromJWT(token);

           UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

           UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
             userDetails, null, userDetails.getAuthorities()
           );
           authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

           //set spring security
           SecurityContextHolder.getContext().setAuthentication(authenticationToken);

       }
       filterChain.doFilter(request,response);

    }

    private String getJwtFromRequest (HttpServletRequest request)
    {
      String bearerToken =  request.getHeader("Authorization");
      if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")){
          return bearerToken.substring(7, bearerToken.length());

      }
      return null;

    }
}
