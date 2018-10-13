# Spring实现jwt并集成Spring security
和Spring Security集成在一起, 首先要配置，我们要允许所有/login的请求, 只对其他请求验证权限。
```java
protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/").permitAll()
            .antMatchers(HttpMethod.POST,"/login").permitAll()
            .anyRequest().authenticated().and()
             // 过滤 /api/** 请求
            .addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
}
```
在JwtAuthenticationFilter过滤器中，设置身份信息认证，并存入上下文。
```java
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
}
```
根据实际需要，可以在spring security提供的SecurityContextHolder上下文控制器中获取存入上下文的信息
```java
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
```