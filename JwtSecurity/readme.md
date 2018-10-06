# Spring实现jwt并集成Spring security
和Spring Security集成在一起, 首先要配置，我们要允许所有/login的请求, 只对其他请求验证权限。
```java
protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/").permitAll()
            .antMatchers(HttpMethod.POST,"/login").permitAll()
            .anyRequest().authenticated().and()
            //filter /api/** request
            .addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
}
```
在Filter过滤器中，设置身份信息认证。
```java
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    try {
        if(isProtectedUrl(request)){
            Map<String, Object> body = JwtUtil.validateTokenAndAddRoleToHeader(request);
            //获取role信息
            String role = String.valueOf(body.get("ROLE"));
            SecurityContextHolder.getContext()
                    .setAuthentication(new UsernamePasswordAuthenticationToken(null,null,
                            Arrays.asList(new GrantedAuthority() {
                                @Override
                                public String getAuthority() {
                                    return role;
                                }
                            })));
        }
    } catch (Exception e) {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,e.getMessage());
        return;
    }
    //如果jwt检查通过就放行
    filterChain.doFilter(request,response);
}
```