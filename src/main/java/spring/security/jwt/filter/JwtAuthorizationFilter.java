package spring.security.jwt.filter;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.CollectionUtils;
import spring.security.jwt.SpringSecurityContextHelper;
import spring.security.jwt.constant.SecurityConstants;
import spring.security.jwt.constant.UserRoleConstants;
import spring.security.jwt.service.UserService;
import spring.security.jwt.util.JwtUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

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

    private UserService userService;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.userService = SpringSecurityContextHelper.getBean(UserService.class);
    }

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {
        System.out.println("111");
        // 从 HTTP 请求中获取 token
        String token = this.getTokenFromHttpRequest(request);
        // 验证 token 是否有效
        if (StringUtils.isNotEmpty(token) && JwtUtils.validateToken(token)) {
            // 获取认证信息
            Authentication authentication = this.getAuthentication(token);
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
        // 从请求头中获取 token
        return authorization.replace(SecurityConstants.TOKEN_PREFIX, "");
    }

    private Authentication getAuthentication(String token) {
        // 从 token 信息中获取用户名
        String userName = JwtUtils.getUserName(token);
        if (StringUtils.isNotEmpty(userName)) {
            // 从数据库中获取用户权限，保证权限的及时性
            List<String> roles = userService.listUserRoles(userName);
            // 如果用户角色为空，则默认赋予 ROLE_USER 权限
            if (CollectionUtils.isEmpty(roles)) {
                roles = Collections.singletonList(UserRoleConstants.ROLE_USER);
            }
            // 设置权限
            List<GrantedAuthority> authorities = roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            // 认证信息
            return new UsernamePasswordAuthenticationToken(userName, null, authorities);
        }
        return null;

    }

}
