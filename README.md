## Spring Security JWT 

### 概述

Spring Security 是 Spring 全家桶中一个功能强大且高度可定制的身份验证和访问控制框架。与所有 Spring 项目一样，我们可以轻松扩展 Spring Security 以满足自定义要求。 

由于 Spring Security 功能十分强大，相比于其他技术来说很难上手，很多刚接触 Spring Security 的开发者很难通过文档或者视频就能将其进行运用到实际开发中。

在公司实习的时候接触到的一个项目就使用了 Spring Security 这个强大的安全验证框架来完成用户的登录模块，并且也是自己负责的一个模块。当时自己对 Spring Security 基本不熟悉，可以说是第一次接触，查阅了很多关于这方面的资料，看得似懂非懂的，并且还在导师的指导下都花了将近一周的时间才勉强完成。

Spring Security 对于初学者来说，的确很难上手。于是自己在工作之余对这部分知识进行了学习，并实现了一个简单的项目，主要使用了 Spring Boot 技术集成 Spring Security 和 Spring Data Jpa 技术。这个项目实现的比较简单，还有很多地方需要优化，希望有兴趣的朋友可以一起完善，期待你的 PR。

### 项目下载

- git clone https://github.com/yifanzheng/spring-security-jwt.git 。

- 配置好 Maven 仓库，使用 IntelliJ IDEA 工具打开项目。

- 在 application.properties 配置文件中将数据库信息改成你自己的。

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

**WebSecurityConfig**  

WebSecurityConfig 配置类继承了 Spring Security 的 WebSecurityConfigurerAdapter 类。WebSecurityConfigurerAdapter 类提供了默认的安全配置，并允许其他类通过覆盖其方法来扩展它并自定义安全配置。

这里配置了如下内容：

- 忽略某些不需要验证的就能访问的资源路径；

- 设置自定义身份验证组件，用于验证用户的登录信息（用户名和密码）；

- 在 Spring Security 机制中配置需要验证后才能访问的资源路径、不需要验证就可以访问的资源路径以及指定某些资源只能被特定角色访问。

- 配置请求权限认证异常时的处理类；

- 将自定义的 `JwtAuthenticationFilter` 和 `JwtAuthorizationFilter` 两个过滤器添加到 Spring Security 机制中。



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
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CorsFilter corsFilter;

    @Autowired
    private UserService userService;

    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .antMatchers(HttpMethod.OPTIONS, "/**")
                .antMatchers("/app/**/*.{js,html}")
                .antMatchers("/v2/api-docs/**")
                .antMatchers("/webjars/springfox-swagger-ui/**")
                .antMatchers("/swagger-resources/**")
                .antMatchers("/i18n/**")
                .antMatchers("/content/**")
                .antMatchers("/swagger-ui.html")
                .antMatchers("/test/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) {
        // 设置自定义身份验证组件，用于从数据库中验证用户登录信息（用户名和密码）
        authenticationManagerBuilder.authenticationProvider(new CustomAuthenticationProvider());
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
                .accessDeniedHandler(new AccessDeniedHandlerImpl())
             .and()
                // 禁用 CSRF
                .csrf().disable()
                .headers().frameOptions().disable()
             .and()
                .authorizeRequests()
                 // 指定路径下的资源需要进行验证后才能访问
                .antMatchers("/").permitAll()
                .antMatchers(HttpMethod.POST, SecurityConstants.AUTH_LOGIN_URL).permitAll()
                .antMatchers("/api/users/register").permitAll()
                // 只允许管理员访问
                .antMatchers("/api/users/detail").hasRole("ADMIN")
                // 其他请求需验证
                .anyRequest().authenticated()
             .and()
                // 添加用户登录验证过滤器，将登录请求交给此过滤器处理
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                // 不需要 session（不创建会话）
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
             .and()
               .apply(securityConfigurationAdapter());
        super.configure(http);
    }

    private JwtConfigurer securityConfigurationAdapter() throws Exception{
        return new JwtConfigurer(new JwtAuthorizationFilter(authenticationManager()));
    }
}
```


****




### 测试 API

**注册账号**

![注册账号](./asset/imgs/register.png)

**登录**

![登录](./asset/imgs/login.png)

**带上正确的 token 访问需要身份验证的资源**  

![correctToken](./asset/imgs/correctToken.png)  

**带上不正确的 token 访问需要身份验证的资源**

![incorrectToken](./asset/imgs/incorrectToken.png)


**不带 token 访问需要身份验证的资源** 
![noToken](./asset/imgs/noToken.png)


### 参考文档
- [https://www.callicoder.com/spring-boot-spring-security-jwt-mysql-react-app-part-2/
](https://www.callicoder.com/spring-boot-spring-security-jwt-mysql-react-app-part-2/
)
- [https://segmentfault.com/a/1190000009231329](https://segmentfault.com/a/1190000009231329)

- [https://www.springcloud.cc/spring-security.html](https://www.springcloud.cc/spring-security.html)
