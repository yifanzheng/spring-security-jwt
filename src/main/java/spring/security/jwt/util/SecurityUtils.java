package spring.security.jwt.util;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;
import spring.security.jwt.constant.UserRoleConstants;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * SecurityUtils
 *
 * <p>
 * 用于获取当前登录的用户名
 *
 * @author star
 **/
public final class SecurityUtils {

    private SecurityUtils() {
        throw new IllegalStateException("Cannot create instance of static util class");
    }

    /**
     * 从上下文中获取当前登录的用户信息
     */
    public static Optional<String> getCurrentUserLogin() {
        // 获取上下文对象
        SecurityContext context = SecurityContextHolder.getContext();
        // 获取验证信息
        Authentication authentication = context.getAuthentication();
        // 返回上下文中的用户信息
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

    public static Authentication generateAuthentication(String userName, List<String> roles) {
            if (StringUtils.isNotEmpty(userName)) {
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
