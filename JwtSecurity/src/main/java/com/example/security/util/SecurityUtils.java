package com.example.security.util;

import com.example.security.entity.UserDto;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

/**
 * @author kevin
 * @date 2018-10-12 21:28
 **/
public final class SecurityUtils {

    private SecurityUtils() {
    }

    /**
     * 从上下文中获取用户信息
     *
     * @return
     */
    public static Optional<String> getCurrentUserLogin() {
        // 获取上下文对象
        SecurityContext context = SecurityContextHolder.getContext();

        // 获取验证信息
        Authentication authentication = context.getAuthentication();

        //返回上下文中的用户信息
        return Optional.ofNullable(authentication)
                .map(auth -> {
                    if (auth.getPrincipal() instanceof UserDetails) {
                        UserDetails userDetails = (UserDetails) auth.getPrincipal();
                        return userDetails.getUsername();
                    } else if (auth.getPrincipal() instanceof String) {
                        return (String) auth.getPrincipal();
                    }
                    return null;
                });

    }

    /**
     * 获取用户验证信息
     *
     * @return
     */
    public static Authentication getAuthentication(UserDto user) {
        // 添加授权信息
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        // 缓存用户的信息
        UserDetails userDetails = new User(user.getUsername(), "", authorities);
        // 用户验证，使用密码验证用户信息的正确性
        return new UsernamePasswordAuthenticationToken(userDetails, user.getPassword(), authorities);
    }


}
