package com.springboot.blog.controller;

import com.springboot.blog.entity.Role;
import com.springboot.blog.entity.User;
import com.springboot.blog.payload.JwtAuthResponse;
import com.springboot.blog.payload.LoginDto;
import com.springboot.blog.payload.SignUpDto;
import com.springboot.blog.repository.RoleRepository;
import com.springboot.blog.repository.UserRepository;
import com.springboot.blog.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
public class AuthController  {
   @Autowired
    private AuthenticationManager authenticationManager;

   @Autowired
   private UserRepository userRepository;

   @Autowired
   private RoleRepository roleRepository;

   @Autowired
   private PasswordEncoder passwordEncoder;

   @Autowired
   private JwtTokenProvider tokenProvider;

   @PostMapping("/signin")
   public ResponseEntity<JwtAuthResponse> authenticateUser(@RequestBody LoginDto loginDto)
   {
     Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
             loginDto.getUsernameOrEmail(), loginDto.getPassword()));
       SecurityContextHolder.getContext().setAuthentication(authentication);

       String token = tokenProvider.generateToken(authentication);

       return  ResponseEntity.ok(new JwtAuthResponse(token));
   }

   @PostMapping("/signup")
   public ResponseEntity<?> registerUser(@RequestBody SignUpDto signUpDto) {
       if (userRepository.existsByUsername(signUpDto.getUsername())) {
           return new ResponseEntity<>("username is already taken", HttpStatus.BAD_REQUEST);

       }
       if (userRepository.existsByEmail(signUpDto.getEmail())) {
           return new ResponseEntity<>("Email is already taken", HttpStatus.BAD_REQUEST);
       }

       User user = new User();
       user.setName(signUpDto.getName());
       user.setUsername(signUpDto.getUsername());
       user.setEmail(signUpDto.getEmail());
       user.setPassword(passwordEncoder.encode(signUpDto.getPassword()));

       Role roles = roleRepository.findByName("ROLE_ADMIN").get();
       user.setRoles(Collections.singleton(roles));

       userRepository.save(user);


       return new ResponseEntity<>("user registered Sucessfully", HttpStatus.OK  );
   }

}
