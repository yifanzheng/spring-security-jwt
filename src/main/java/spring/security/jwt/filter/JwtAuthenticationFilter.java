package spring.security.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import spring.security.jwt.constant.SecurityConstants;
import spring.security.jwt.dto.UserLoginDTO;
import spring.security.jwt.dto.UserRegisterDTO;
import spring.security.jwt.util.JwtUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sound.midi.SoundbankResource;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JwtAuthenticationFilter 用户登录验证过滤器
 *
 * <p>
 * 用于验证使用 URL 地址是 {@link SecurityConstants#AUTH_LOGIN_URL} 进行登录的用户请求。
 * 通过检查请求中的用户名和密码参数，并调用 Spring 的身份验证管理器进行验证。
 * 如果用户名和密码正确，那么过滤器将创建一个 token，并在 Authorization 标头中将其返回。
 * 格式：Authorization: "Bearer + 具体 token 值"</p>
 *
 * @author star
 **/
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final AuthenticationManager authenticationManager;

    private final ThreadLocal<Boolean> rememberMeLocal = new ThreadLocal<>();

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        // 指定需要验证的登录 URL
        super.setFilterProcessesUrl(SecurityConstants.AUTH_LOGIN_URL);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        try {
            // 获取用户登录信息，JSON 反序列化成 UserDTO 对象
            UserLoginDTO loginUser = new ObjectMapper().readValue(request.getInputStream(), UserLoginDTO.class);
            rememberMeLocal.set(loginUser.getRememberMe());
            // 根据用户名和密码生成身份验证信息
            Authentication authentication = new UsernamePasswordAuthenticationToken(loginUser.getUserName(), loginUser.getPassword(), new ArrayList<>());
            // 这里返回 Authentication 后会通过我们自定义的 {@see CustomAuthenticationProvider} 进行验证
            return this.authenticationManager.authenticate(authentication);
        } catch (IOException e) {
            return null;
        }

    }

    /**
     * 如果验证通过，就生成 token 并返回
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authentication) {
        try {
            // 获取用户信息
            String username = null;
            // 获取身份信息
            Object principal = authentication.getPrincipal();
            if (principal instanceof UserDetails) {
                UserDetails user = (UserDetails) principal;
                username = user.getUsername();
            } else if (principal instanceof String) {
                username = (String) principal;
            }
            // 获取用户认证权限
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            // 获取用户角色权限
            List<String> roles = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            boolean isRemember = this.rememberMeLocal.get();
            // 生成 token
            String token = JwtUtils.generateToken(username, roles, isRemember);
            // 将 token 添加到 Response Header 中返回
            response.addHeader(SecurityConstants.TOKEN_HEADER, token);
        } finally {
            // 清除变量
            this.rememberMeLocal.remove();
        }
    }

    /**
     * 如果验证证不成功，返回错误信息提示
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException {
        logger.warn(authenticationException.getMessage());

        if (authenticationException instanceof UsernameNotFoundException) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, authenticationException.getMessage());
            return;
        }
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authenticationException.getMessage());
    }
}
