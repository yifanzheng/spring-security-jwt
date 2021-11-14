# Spring Security With JWT

### 概述

Spring Security 是 Spring 全家桶中一个功能强大且高度可定制的身份验证和访问控制框架。与所有 Spring 项目一样，我们可以轻松扩展 Spring Security 以满足自定义要求。 

由于 Spring Security 功能十分强大，相比于其他技术来说很难上手，很多刚接触 Spring Security 的开发者很难通过文档或者视频就能将其进行运用到实际开发中。

在公司实习的时候接触到的一个项目就使用了 Spring Security 这个强大的安全验证框架来完成用户的登录模块，并且也是自己负责的一个模块。当时自己对 Spring Security 基本不熟悉，可以说是第一次接触，查阅了很多关于这方面的资料，看得似懂非懂的，并且还在导师的指导下都花了将近一周的时间才勉强完成。

Spring Security 对于初学者来说，的确很难上手。于是自己在工作之余对这部分知识进行了学习，并实现了一个简单的项目，主要使用了 Spring Boot 技术集成 Spring Security 和 Spring Data Jpa 技术。这个项目实现的比较简单，还有很多地方需要优化，希望有兴趣的朋友可以一起完善，期待你的 PR。

### 项目调整记录

- 增加 Swagger UI，方便查看项目接口。
- 增加全局异常捕获功能。
- 增加 JPA 审计功能，完善数据表审计信息。
- 在 Controller 层中暴露用户登录接口(`/api/auth/login`)。
- 增加 Token 刷新功能，提供前端和后端各自的方案。

### Token 刷新并发处理方案

- 后端利用 Redis 缓存：https://github.com/yifanzheng/spring-security-jwt/tree/refresh-token-redis

- 前端利用请求拦截器：https://github.com/yifanzheng/spring-security-jwt/tree/refresh-token-frontend


### 项目下载

- git clone https://github.com/yifanzheng/spring-security-jwt.git 。

- 配置好 Maven 仓库，使用 IntelliJ IDEA 工具打开项目。

- 在 application.properties 配置文件中将数据库信息改成你自己的。

### 权限控制

本 Demo 权限控制采用 RBAC 思想。简单地说，一个用户拥有若干角色，用户与角色形成多对多关系。

**模型**
![权限模型](https://img-blog.csdnimg.cn/20200628230812139.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L29zY2hpbmFfNDE3OTA5MDU=,size_16,color_FFFFFF,t_70)

**数据表设计**

用户表与用户角色表是多对多的关系。因为这里比较简单，所以表设计上有点冗余。小伙伴们可以根据实际情况重新设计。
![表设计](https://img-blog.csdnimg.cn/2020062823082793.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L29zY2hpbmFfNDE3OTA5MDU=,size_16,color_FFFFFF,t_70)

**数据交互**

用户登录 -> 后端验证登录并返回 token -> 前端携带 token 请求后端数据 -> 后端返回数据。

![token流程](https://user-images.githubusercontent.com/22571230/138224284-770c1891-1be4-4c7d-9b76-c6b821f4e0b2.png)


### 项目核心类说明

**WebCorsConfiguration**  

WebCorsConfiguration 配置类，主要解决 HTTP 请求跨域问题。这里需要注意的是，如果没有将 `Authorization` 头字段暴露给客户端的话，客户端是无法获取到 Token 信息的。

```java
/**
 * WebCorsConfiguration 跨域配置
 *
 * @author star
 */
@Configuration
public class WebCorsConfiguration implements WebMvcConfigurer {

    /**
     * 设置swagger为默认主页
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("redirect:/swagger-ui.html");
        registry.setOrder(Ordered.HIGHEST_PRECEDENCE);
        WebMvcConfigurer.super.addViewControllers(registry);
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(Collections.singletonList("*"));
        config.setAllowedMethods(Collections.singletonList("*"));
        config.setAllowedHeaders(Collections.singletonList("*"));
        // 暴露 header 中的其他属性给客户端应用程序
        config.setExposedHeaders(Arrays.asList(
                "Authorization", "X-Total-Count", "Link",
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials"
        ));
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

}
```

**SecurityConfiguration**  

SecurityConfiguration 配置类继承了 Spring Security 的 WebSecurityConfigurerAdapter 类。WebSecurityConfigurerAdapter 类提供了默认的安全配置，并允许其他类通过覆盖其方法来扩展它并自定义安全配置。

这里配置了如下内容：

- 忽略某些不需要验证的就能访问的资源路径；

- 在 Spring Security 机制中配置需要验证后才能访问的资源路径、不需要验证就可以访问的资源路径以及指定某些资源只能被特定角色访问。

- 配置请求权限认证异常时的处理类；

- 将自定义的 `JwtAuthorizationFilter` 过滤器添加到 Spring Security 机制中。

```java

/**
 * Web 安全配置
 *
 * @author star
 **/
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Import(SecurityProblemSupport.class)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private CorsFilter corsFilter;

    @Autowired
    private SecurityProblemSupport securityProblemSupport;

    /**
     * 使用 Spring Security 推荐的加密方式进行登录密码的加密
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 此方法配置的资源路径不会进入 Spring Security 机制进行验证
     */
    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .antMatchers(HttpMethod.OPTIONS, "/**")
                .antMatchers("/app/**/*.{js,html}")
                .antMatchers("/v2/api-docs/**")
                .antMatchers("/i18n/**")
                .antMatchers("/test/**")
                .antMatchers("/content/**")
                .antMatchers("/webjars/springfox-swagger-ui/**")
                .antMatchers("/swagger-resources/**")
                .antMatchers("/swagger-ui.html");
    }

    /**
     * 定义安全策略，设置 HTTP 访问规则
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()
                // 当用户无权访问资源时发送 401 响应
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                // 当用户访问资源因权限不足时发送 403 响应
                .accessDeniedHandler(securityProblemSupport)
             .and()
                // 禁用 CSRF
                .csrf().disable()
                .headers().frameOptions().disable()
             .and()
                .logout().logoutUrl("/auth/logout").and()
                .authorizeRequests()
                 // 指定路径下的资源需要进行验证后才能访问
                .antMatchers("/").permitAll()
                // 配置登录地址
                .antMatchers(HttpMethod.POST, SecurityConstants.AUTH_LOGIN_URL).permitAll()
                .antMatchers(HttpMethod.POST,"/api/users/register").permitAll()
                // 其他请求需验证
                .anyRequest().authenticated()
             .and()
                // 不需要 session（不创建会话）
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
             .and()
               .apply(securityConfigurationAdapter());
        super.configure(http);
    }

    private JwtConfigurer securityConfigurationAdapter() throws Exception{
        return new JwtConfigurer(new JwtAuthorizationFilter(authenticationManager()));
    }
}
```

**JwtAuthorizationFilter**

JwtAuthorizationFilter 用户请求授权过滤器，用于从用户请求中获取 token 信息，并对其进行验证，同时加载与 token 相关联的用户身份认证信息，并添加到 Spring Security 上下文中。

```java
/**
 * JwtAuthorizationFilter 用户请求授权过滤器
 *
 * <p>
 * 提供请求授权功能。用于处理所有 HTTP 请求，并检查是否存在带有正确 token 的 Authorization 标头。
 * 如果 token 有效，则过滤器会将身份验证数据添加到 Spring 的安全上下文中，并授权此次请求访问资源。</p>
 *
 * @author star
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {
        // 从 HTTP 请求中获取 token
        String token = this.getTokenFromHttpRequest(request);
        // 验证 token 是否有效
        if (StringUtils.hasText(token) && JwtUtils.validateToken(token)) {
            // 获取认证信息
            Authentication authentication = JwtUtils.getAuthentication(token);
            // 将认证信息存入 Spring 安全上下文中
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        // 放行请求
        filterChain.doFilter(request, response);

    }

    /**
     * 从 HTTP 请求中获取 token
     *
     * @param request HTTP 请求
     * @return 返回 token
     */
    private String getTokenFromHttpRequest(HttpServletRequest request) {
        String authorization = request.getHeader(SecurityConstants.TOKEN_HEADER);
        if (authorization == null || !authorization.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            return null;
        }
        // 去掉 token 前缀
        return authorization.replace(SecurityConstants.TOKEN_PREFIX, "");
    }

}
```

**所有的用户请求**都会经过此过滤器，当请求进入过滤器后会经历如下步骤：

- 首先，从请求中获取 token 信息，并检查 token 的有效性。

- 如果 token 有效，则解析 token 获取用户名，然后使用用户名从数据库中获取用户角色信息，并在 Spring Security 的上下文中设置身份验证。

- 如果 token 无效或请求不带 token 信息，则直接放行。

特别说明，这里用户的角色信息，是从数据库中重新获取的。其实，这里也可以换成从 token 信息中解析出用户角色，这样可以避免直接访问数据库。

但是，直接从数据库获取用户信息也是很有帮助的。例如，如果用户角色已更改，则可能要禁止使用此 token 进行访问。

**JwtUtils**

JwtUtils 工具类，在用户登录成功后，主要用于生成 token，并验证用户请求中发送的 token。

```java
/**
 * Jwt 工具类，用于生成、解析与验证 token
 *
 * @author star
 **/
public final class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private static final byte[] secretKey = DatatypeConverter.parseBase64Binary(SecurityConstants.JWT_SECRET_KEY);

    private JwtUtils() {
        throw new IllegalStateException("Cannot create instance of static util class");
    }

    /**
     * 根据用户名和用户角色生成 token
     *
     * @param userName   用户名
     * @param roles      用户角色
     * @param isRemember 是否记住我
     * @return 返回生成的 token
     */
    public static String generateToken(String userName, List<String> roles, boolean isRemember) {
        byte[] jwtSecretKey = DatatypeConverter.parseBase64Binary(SecurityConstants.JWT_SECRET_KEY);
        // 过期时间
        long expiration = isRemember ? SecurityConstants.EXPIRATION_REMEMBER_TIME : SecurityConstants.EXPIRATION_TIME;
        // 生成 token
        String token = Jwts.builder()
                // 生成签证信息
                .setHeaderParam("typ", SecurityConstants.TOKEN_TYPE)
                .signWith(Keys.hmacShaKeyFor(jwtSecretKey), SignatureAlgorithm.HS256)
                .setSubject(userName)
                .claim(SecurityConstants.TOKEN_ROLE_CLAIM, roles)
                .setIssuer(SecurityConstants.TOKEN_ISSUER)
                .setIssuedAt(new Date())
                .setAudience(SecurityConstants.TOKEN_AUDIENCE)
                // 设置有效时间
                .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
                .compact();
        return token;
    }

    /**
     * 验证 token 是否有效
     *
     * <p>
     * 如果解析失败，说明 token 是无效的
     *
     * @param token token 信息
     * @return 如果返回 true，说明 token 有效
     */
    public static boolean validateToken(String token) {
        try {
            getTokenBody(token);
            return true;
        } catch (ExpiredJwtException e) {
            logger.warn("Request to parse expired JWT : {} failed : {}", token, e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.warn("Request to parse unsupported JWT : {} failed : {}", token, e.getMessage());
        } catch (MalformedJwtException e) {
            logger.warn("Request to parse invalid JWT : {} failed : {}", token, e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.warn("Request to parse empty or null JWT : {} failed : {}", token, e.getMessage());
        }
        return false;
    }

    /**
     * 根据 token 获取用户认证信息
     *
     * @param token token 信息
     * @return 返回用户认证信息
     */
    public static Authentication getAuthentication(String token) {
        Claims claims = getTokenBody(token);
        // 获取用户角色字符串
        List<String> roles = (List<String>)claims.get(SecurityConstants.TOKEN_ROLE_CLAIM);
        List<SimpleGrantedAuthority> authorities =
                Objects.isNull(roles) ? Collections.singletonList(new SimpleGrantedAuthority(UserRoleConstants.ROLE_USER)) :
                        roles.stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList());
        // 获取用户名
        String userName = claims.getSubject();

        return new UsernamePasswordAuthenticationToken(userName, token, authorities);

    }

    private static Claims getTokenBody(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();
    }
}
```

### 请求认证流程说明

由于已将登录接口暴露在了 Controller 层，请求认证过程将变成，所有的请求会先经过 `JwtAuthorizationFilter` 过滤器，然后进入 Spring Security 机制中。

### 测试 API

**注册账号**
![register](https://img-blog.csdnimg.cn/20200524195659308.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L29zY2hpbmFfNDE3OTA5MDU=,size_16,color_FFFFFF,t_70)
**登录**
![login](https://img-blog.csdnimg.cn/20200524195721904.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L29zY2hpbmFfNDE3OTA5MDU=,size_16,color_FFFFFF,t_70)
**带上正确的 token 访问需要身份验证的资源**  
![correctToken](https://img-blog.csdnimg.cn/20200524200233825.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L29zY2hpbmFfNDE3OTA5MDU=,size_16,color_FFFFFF,t_70)
**带上不正确的 token 访问需要身份验证的资源**
![incorrectToken](https://img-blog.csdnimg.cn/20200524200307326.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L29zY2hpbmFfNDE3OTA5MDU=,size_16,color_FFFFFF,t_70)

**不带 token 访问需要身份验证的资源** 
![noToken](https://img-blog.csdnimg.cn/20200524200408739.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L29zY2hpbmFfNDE3OTA5MDU=,size_16,color_FFFFFF,t_70)


### 参考文档

- [https://www.callicoder.com/spring-boot-spring-security-jwt-mysql-react-app-part-2/
](https://www.callicoder.com/spring-boot-spring-security-jwt-mysql-react-app-part-2/
)
- [https://segmentfault.com/a/1190000009231329](https://segmentfault.com/a/1190000009231329)

- [https://www.springcloud.cc/spring-security.html](https://www.springcloud.cc/spring-security.html)
