package com.skillstorm.taxprep.auth;
import org.apache.catalina.connector.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;


@RestController
@RequestMapping("/api/v1/auth/demo-controller")
@RequiredArgsConstructor
public class AuthController {
    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("hello from secured endpoint");
    }
    

}
