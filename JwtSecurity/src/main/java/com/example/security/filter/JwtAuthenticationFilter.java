package com.example.security.filter;

import com.example.security.entity.UserDto;
import com.example.security.util.Constants;
import com.example.security.util.JwtUtils;
import com.example.security.util.SecurityUtils;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;


import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * jwt验证过滤器
 *
 * @author kevin
 * @date 2018-10-02 17:50
 **/
@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    /**
     * 路径匹配器
     */
    private static final PathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            if (isProtectedUrl("/api/**", request)) {
                String token = request.getHeader(Constants.AUTO_HEADER);
                Map<String, Object> body = JwtUtils.validateTokenAndAddRoleToHeader(token);
                // 获取role信息
                UserDto user = new UserDto();
                user.setUsername(String.valueOf(body.get("username")));
                user.setPassword(String.valueOf(body.get("password")));
                // 获取验证对象
                Authentication authentication = SecurityUtils.getAuthentication(user);
                // 将验证信息放入上下文
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
            e.printStackTrace();
            return;
        }
        //如果jwt检查通过就放行
        filterChain.doFilter(request, response);
    }

    //只对地址 /api 开头的api检查jwt. 不然的话登录/login也需要jwt
    private boolean isProtectedUrl(String path, HttpServletRequest request) {
        return pathMatcher.match(path, request.getServletPath());
    }

    @Bean
    public FilterRegistrationBean jwtFilter() {
        final FilterRegistrationBean<JwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter();
        registrationBean.setFilter(filter);
        return registrationBean;
    }
}
