# springboot使用jwt实现Authentication认证
通常情况下，将api直接暴露出来是非常危险的。每一个api请求，用户都应该附上额外的信息，以供我们认证和授权。JWT是一种既能满足这样需求，而又简单安全便捷的方法。前端login获取JWT之后，只需在每一次HTTP呼叫的时候添加上JWT作为HTTP Header即可。

### 创建login的API
验证用户的登录信息，如果匹配，那么会返回生成的jwt。这时前端拿到的这个jwt就类似于拿到了一个临时的密码，之后所有的HTTP请求都附上这个"临时密码"即可(专业术语叫令牌/token)。
```java
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
```
##### 登录的效果图
![login](/images/1.png)

### 注册过滤器Filter
注册一个检验jwt的过滤器，通过过滤器实现对指定api请求的jwt验证。任何请求都会先经过Filter，Filter会检验指定的api请求是否合法，并让合法的请求通过。
```java
@Configuration
public class JwtAuthenticationFilter extends OncePerRequestFilter{
    /**
     * 路径匹配器
     */
    private static final PathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            if(isProtectedUrl(request)){
                String token = request.getHeader("Authorization");
                //检查jwt令牌, 如果令牌不合法或者过期, 里面会直接抛出异常, 下面的catch部分会直接返回
                JwtUtil.validateToken(token);
            }
        } catch (IllegalStateException e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,e.getMessage());
            return;
        }
        //如果jwt检查通过就放行
        filterChain.doFilter(request,response);
    }

    //只对地址 /api 开头的api检查jwt. 不然的话登录/login也需要jwt
    private boolean isProtectedUrl(HttpServletRequest request) {
        return pathMatcher.match("/api/**", request.getServletPath());
    }

    @Bean
    public FilterRegistrationBean jwtFilter(){
        final FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter();
        registrationBean.setFilter(filter);
        return registrationBean;
    }
}
```
### 验证/api/**的请求
![api](/images/2.png)