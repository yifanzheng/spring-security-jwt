package com.example.security.controller;

import com.example.security.entity.User;
import com.example.security.util.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

/**
 * @author kevin
 * @date 2018-10-04 9:52
 **/
@RestController
public class DemoController {

    @GetMapping("/api/admin")
    @PreAuthorize(value = "hasRole('ROLE_ADMIN')")
    public Object helloAdmin(){
        return "Hello admin";
    }

    @GetMapping("/api/hello")
    public Object hello(){
        return "Hello,you have a valid token";
    }

    @PostMapping("/login")
    public Object login(@RequestBody User user){
        if(isValidPassword(user)){
            String jwt = JwtUtil.generateToken(user.getUsername());
            return new HashMap<String,String>(){
                {
                    put("token",jwt);
                }
            };
        }else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * 验证用户信息是否正确
     * @param user
     * @return
     */
    private boolean isValidPassword(User user) {
        return "admin".equals(user.getUsername())
                &&"admin".equals(user.getPassword())
                || "user".equals(user.getUsername()) && "user".equals(user.getPassword());
    }

}
