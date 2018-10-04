package com.example.jwtverify.controller;

import com.example.jwtverify.entity.User;
import com.example.jwtverify.util.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

/**
 * 控制器
 *
 * @author kevin
 * @date 2018-10-03 9:57
 **/
@RestController
public class DemoController {

    @GetMapping("/api/success")
    public Object success(@RequestHeader(value ="ROLE") String role){
        return "Login success! Wellcome "+role;
    }


    @PostMapping("/login")
    public Object login(@RequestBody User user){
        if (isValidPassword(user)){
            String token = JwtUtil.generateToken(user.getUsername());
            return new HashMap<String,String>(){{
                put("token",token);
            }};
        }else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * 验证登录信息
     * @param user 用户信息
     * @return
     */
    private boolean isValidPassword(User user) {
        //验证登录信息，实际是query数据库数据
        return "admin".equals(user.getUsername())
                && "admin".equals(user.getPassword());
    }



}
