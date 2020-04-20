package spring.security.jwt.filter;

import spring.security.jwt.constants.SecurityConstants;
import spring.security.jwt.utils.JwtUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JwtAuthenticationFilter 用户身份验证过滤器
 *
 * <p>
 * 检查请求中的用户名和密码参数，并调用 Spring 的身份验证管理器进行验证。
 * 如果用户名和密码正确，那么过滤器将创建一个 token，并在 Authorization 标头中将其返回。
 * 格式：Authorization: "Bearer + 具体 token 值"</p>
 *
 * @author star
 **/
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    private ThreadLocal<Boolean> rememberMeLocal = new ThreadLocal<>();

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;

        super.setFilterProcessesUrl(SecurityConstants.AUTH_LOGIN_URL);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        // 获取到登录的信息
        try {
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            boolean rememberMe = Boolean.parseBoolean(request.getParameter("rememberMe"));
            rememberMeLocal.set(rememberMe);
            if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
                return null;
            }
            Authentication authentication = new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>());

            return this.authenticationManager.authenticate(authentication);
        } catch (AuthenticationException e) {
            // e.printStackTrace();
            return null;
        }

    }

    /**
     * 如果认证成功，就生成 token 并返回
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authentication) {
        // 获取用户信息
        String username = null;

        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails) {
            UserDetails user = (UserDetails) principal;
            username = user.getUsername();
        } else if (principal instanceof String) {
            username = (String) principal;
        }
        // 获取用户认证权限
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        // 获取用户角色
        List<String> roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        // 生成 token
        Boolean isRemember = rememberMeLocal.get();
        String token = JwtUtils.generateToken(username, roles, isRemember);
        // 将 token 添加到 Response Header 中返回
        response.addHeader(SecurityConstants.TOKEN_HEADER, token);
    }

    /**
     * 如果认证不成功，返回状态码 401 提示
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authenticationException.getMessage());
    }
}
