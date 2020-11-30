package spring.security.jwt.security.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;
import spring.security.jwt.SpringSecurityContextHelper;
import spring.security.jwt.constant.JwtConstants;
import spring.security.jwt.constant.RedisKeyConstants;
import spring.security.jwt.constant.UserRoleConstants;
import spring.security.jwt.security.JwtInfo;
import spring.security.jwt.service.JwtRedisCacheService;
import spring.security.jwt.util.JwtUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
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

    private static final Logger log = LoggerFactory.getLogger(JwtAuthorizationFilter.class);

    private JwtRedisCacheService jwtRedisCacheService;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
        this.jwtRedisCacheService = SpringSecurityContextHelper.getBean(JwtRedisCacheService.class);
    }

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {
        // 从 HTTP 请求中获取 token
        String token = this.getTokenFromHttpRequest(request);
        try {
            // 验证 token 是否有效
            if (StringUtils.hasText(token) && JwtUtils.validateToken(token)) {
                // 获取认证信息
                Authentication authentication = JwtUtils.getAuthentication(token);
                // 将认证信息存入 Spring 安全上下文中
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (ExpiredJwtException e) {
            // 捕获 token 过期的异常，对 token 进行续期
            // 1. 获取过期的 token 中的信息
            Claims claims = e.getClaims();
            String userName = claims.getSubject();
            List<String> roles = claims.get(JwtConstants.ROLE_CLAIM, List.class);
            Long expiredTokenCreateTime = claims.get(JwtConstants.CREATE_TIME_CLAIM, Long.class);
            // 刷新 token 需要进行同步，防止并发请求重复刷新
            synchronized (this) {
                // 2. 获取 Redis 中缓存的 token 信息
                Optional<JwtInfo> refreshTokenInfoOptional =
                        jwtRedisCacheService.getValue(RedisKeyConstants.PREFIX_REFRESH_TOKEN + userName);
                if (refreshTokenInfoOptional.isPresent()) {
                    JwtInfo refreshJwtInfo = refreshTokenInfoOptional.get();
                    // 3. 检查过期的 token 与缓存 token 是否一致（token 字符串一致和创建时间一致）
                    if (Objects.equals(token, refreshJwtInfo.getToken())
                            && Objects.equals(expiredTokenCreateTime, refreshJwtInfo.getCreateTime())) {
                        // 刷新 token
                        JwtInfo newJwtInfo = this.refreshToken(userName, roles, refreshJwtInfo);
                        // 设置新的认证信息
                        Authentication authentication = JwtUtils.getAuthentication(newJwtInfo.getToken());
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        // 将新 token 存入响应头中返回
                        response.setHeader(JwtConstants.HEADER, JwtConstants.PREFIX + newJwtInfo.getToken());
                        // 放行请求
                        filterChain.doFilter(request, response);
                        log.info("Refresh token success");
                        return;
                    }
                    // 当 refresh token 信息不一致时，说明 token 已经被刷新了，
                    // 并发请求时，过期 token 可在过渡时间内重新通过认证
                    this.authExpiredTokenInTransitionTime(userName, roles, token, expiredTokenCreateTime);

                }
            }
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
        String authorization = request.getHeader(JwtConstants.HEADER);
        if (authorization == null || !authorization.startsWith(JwtConstants.PREFIX)) {
            return null;
        }
        // 去掉 token 前缀
        return authorization.replace(JwtConstants.PREFIX, "");
    }

    private JwtInfo refreshToken(String userName, List<String> roles, JwtInfo refreshJwtInfo) {
        // 4. 创建新的 token
        long newCreateTime = System.currentTimeMillis();
        String newToken = JwtUtils.createToken(userName, roles, newCreateTime, false);
        // 5. 更新 Redis 缓存中 token 信息
        String refreshTokenKey = RedisKeyConstants.PREFIX_REFRESH_TOKEN + userName;
        JwtInfo newJwtInfo = new JwtInfo(newToken, newCreateTime);
        jwtRedisCacheService.setValue(refreshTokenKey, newJwtInfo, JwtConstants.EXPIRE_REFRESH_TIME);
        // 6. 设置过期 token 的过渡时间，用于在并发请求时，放行后面的请求
        String transitionKey = RedisKeyConstants.PREFIX_REFRESH_TOKEN_TRANSITION + userName;
        jwtRedisCacheService.setValue(transitionKey, refreshJwtInfo, JwtConstants.TRANSITION_TIME);

        return newJwtInfo;
    }

    /**
     * 在过渡时间内，过期 token 可重新通过认证
     *
     * @param userName               用户名，用于生成认证信息
     * @param roles                  用户角色，用于生成认证信息
     * @param expiredToken           过期 token
     * @param expiredTokenCreateTime 过期 token 的创建时间
     */
    private void authExpiredTokenInTransitionTime(String userName, List<String> roles, String expiredToken, long expiredTokenCreateTime) {
        // 1. 判断是否在 token 过渡时间内
        String key = RedisKeyConstants.PREFIX_REFRESH_TOKEN_TRANSITION + userName;
        Optional<JwtInfo> jwtInfoOptional = jwtRedisCacheService.getValue(key);
        // 如果在过渡时间内，允许通过认证
        if (jwtInfoOptional.isPresent()) {
            JwtInfo jwtInfo = jwtInfoOptional.get();
            if (Objects.equals(expiredToken, jwtInfo.getToken())
                    && Objects.equals(expiredTokenCreateTime, jwtInfo.getCreateTime())) {
                // 2. 使用用户名和角色生成认证信息
                List<SimpleGrantedAuthority> authorities =
                        Objects.isNull(roles) ? Collections.singletonList(new SimpleGrantedAuthority(UserRoleConstants.ROLE_USER)) :
                                roles.stream()
                                        .map(SimpleGrantedAuthority::new)
                                        .collect(Collectors.toList());
                Authentication authentication = new UsernamePasswordAuthenticationToken(userName, expiredToken, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
    }


}
