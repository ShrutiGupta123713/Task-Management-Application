package com.taskmanager.smartnotes.user_service.controller;

import com.taskmanager.smartnotes.user_service.model.User;
import com.taskmanager.smartnotes.user_service.repository.UserRepository;
import com.taskmanager.smartnotes.user_service.security.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService; // Inject UserDetailsService

    @PostMapping("/register")
    public String register(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword())); // Encode password
        userRepository.save(user);
        return "User registered successfully!";
    }

    @PostMapping("/login")
    public String login(@RequestBody User user) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
            );

            // Load user details after successful authentication
            UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
            System.out.println("Loaded User: " + userDetails.getUsername());
            // Generate JWT token
            return jwtUtils.generateToken(userDetails);
        } catch (BadCredentialsException e) {
            return "Invalid username or password!";
        }
    }
}
