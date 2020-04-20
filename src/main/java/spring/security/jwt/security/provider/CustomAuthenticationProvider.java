package spring.security.jwt.security.provider;

import org.apache.commons.lang3.StringUtils;
import spring.security.jwt.SpringSecurityContextHelper;
import spring.security.jwt.entity.User;
import spring.security.jwt.service.UserService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * CustomAuthenticationProvider 自定义身份验证组件
 *
 * @author star
 */
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserService userService;

    public CustomAuthenticationProvider() {
        this.userService = SpringSecurityContextHelper.getBean(UserService.class);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 获取认证信息的用户名和密码 （即登录请求中的用户名和密码）
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        // 获取数据库中的用户名和密码
        User user = userService.getUserByName(username);

        // 判断用户名和密码是否正确
        if (Objects.equals(username, user.getUsername()) && Objects.equals(password, user.getPassword())) {
            String role = user.getRole();
            // 如果用户角色为空，则默认是 ROLE_USER
            if (StringUtils.isEmpty(role)) {
                role = "ROLE_USER";
            }
            // 设置权限和角色
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(role));

            // 生成认证信息
            return new UsernamePasswordAuthenticationToken(username, password, authorities);
        } else {
            throw new BadCredentialsException("The user name or password error.");
        }
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(UsernamePasswordAuthenticationToken.class);
    }
}
