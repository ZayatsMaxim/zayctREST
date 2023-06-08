package com.example.zayctrest.controllers;

import com.example.zayctrest.requests.AuthenticationRequest;
import com.example.zayctrest.requests.RegisterRequest;
import com.example.zayctrest.responses.AuthenticationResponse;
import com.example.zayctrest.services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/")
@RequiredArgsConstructor
public class AuthorizationController {

    private final AuthenticationService authenticationService;

    @PostMapping("register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) {
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @GetMapping("")
    public ResponseEntity<AuthenticationResponse> authenticateRequest(
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

}