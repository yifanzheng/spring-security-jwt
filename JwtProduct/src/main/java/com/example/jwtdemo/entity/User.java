package com.example.jwtdemo.entity;

import org.springframework.stereotype.Component;

/**
 * 实体类
 *
 * @author kevin
 * @date 2018-10-02 17:02
 **/
public class User {

    private String username;

    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
