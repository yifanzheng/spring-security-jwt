package com.example.security.controller;

import com.example.security.entity.UserDto;
import com.example.security.util.JwtUtils;
import com.example.security.util.SecurityUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

/**
 * @author kevin
 * @date 2018-10-04 9:52
 **/
@RestController
public class DemoController {

    @GetMapping("/api/admin")
    @PreAuthorize(value = "hasRole('ROLE_USER')")
    public ResponseEntity<UserDto> helloAdmin() {
        UserDto user = new UserDto();
        //从上下文中获取用户信息
        user.setUsername(SecurityUtils.getCurrentUserLogin().orElse(null));

        return ResponseEntity.ok(user);
    }

    @PostMapping("/checklogin")
    public Object checkLogin(@RequestBody UserDto user) {
        if (isValidPassword(user)) {
            String jwt = JwtUtils.generateToken(user);
            return new HashMap<String, String>() {
                {
                    put("token", jwt);
                }
            };
        } else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * 验证用户信息是否正确
     *
     * @param user
     * @return
     */
    private boolean isValidPassword(UserDto user) {
        return "admin".equals(user.getUsername())
                && "admin".equals(user.getPassword())
                || "user".equals(user.getUsername()) && "user".equals(user.getPassword());
    }

}
