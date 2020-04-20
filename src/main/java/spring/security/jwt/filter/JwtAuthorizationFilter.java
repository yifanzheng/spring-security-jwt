package spring.security.jwt.filter;

import spring.security.jwt.constants.SecurityConstants;
import spring.security.jwt.utils.JwtUtils;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.util.List;

/**
 * JwtAuthorizationFilter 用户请求授权过滤器
 *
 * <p>
 * 用于处理所有 HTTP 请求，并检查是否存在带有正确 token 的 Authorization 标头。
 * 如果 token 有效，则过滤器会将身份验证数据添加到 Spring 的安全上下文中，并授权此次请求访问资源。</p>
 *
 * @author star
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthorizationFilter.class);

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader(SecurityConstants.TOKEN_HEADER);
        // 如果请求头中没有 Authorization 的信息则直接放行
        if (authorization == null || !authorization.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }
        // 从请求头中获取 token
        String token = authorization.replace(SecurityConstants.TOKEN_PREFIX, "");
        // 获取认证信息
        Authentication authentication = this.getAuthentication(token);
        // 将认证信息存入 Spring 安全上下文中
        SecurityContextHolder.getContext().setAuthentication(authentication);
        super.doFilterInternal(request, response, filterChain);

    }

    private Authentication getAuthentication(String token) {
        // 从 token 信息中获取用户名
        String username = JwtUtils.getUsername(token);
        // 获取用户角色
        List<GrantedAuthority> authorities = JwtUtils.getRoles(token);
        try {
            if (StringUtils.isNotEmpty(username)) {
                return new UsernamePasswordAuthenticationToken(username, null, authorities);
            }
        } catch (ExpiredJwtException exception) {
            logger.warn("Request to parse expired JWT : {} failed : {}", token, exception.getMessage());
        } catch (UnsupportedJwtException exception) {
            logger.warn("Request to parse unsupported JWT : {} failed : {}", token, exception.getMessage());
        } catch (MalformedJwtException exception) {
            logger.warn("Request to parse invalid JWT : {} failed : {}", token, exception.getMessage());
        } catch (IllegalArgumentException exception) {
            logger.warn("Request to parse empty or null JWT : {} failed : {}", token, exception.getMessage());
        }
        return null;

    }

}
