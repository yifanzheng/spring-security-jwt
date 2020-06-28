package spring.security.jwt.security.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.CollectionUtils;
import spring.security.jwt.SpringSecurityContextHelper;
import spring.security.jwt.constant.UserRoleConstants;
import spring.security.jwt.entity.User;
import spring.security.jwt.service.UserService;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * CustomAuthenticationProvider 自定义用户身份验证组件
 *
 * TODO 本项目已将登录接口暴露在 Controller 层，此认证类过时。
 *
 * <p>
 * 提供用户登录密码验证功能。根据用户名从数据库中取出用户信息，进行密码验证，验证通过则赋予用户相应权限。
 *
 * @author star
 */
@Deprecated
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserService userService;

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public CustomAuthenticationProvider(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userService = SpringSecurityContextHelper.getBean(UserService.class);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws BadCredentialsException, UsernameNotFoundException {
        // 获取验证信息中的用户名和密码 （即登录请求中的用户名和密码）
        String userName = authentication.getName();
        String password = authentication.getCredentials().toString();
        // 根据登录名获取用户信息
        User user = userService.getUserByName(userName);
        // 验证登录密码是否正确。如果正确，则赋予用户相应权限并生成用户认证信息
        if (user != null && this.bCryptPasswordEncoder.matches(password, user.getPassword())) {
            List<String> roles = userService.listUserRoles(userName);
            // 如果用户角色为空，则默认赋予 ROLE_USER 权限
            if (CollectionUtils.isEmpty(roles)) {
                roles = Collections.singletonList(UserRoleConstants.ROLE_USER);
            }
            // 设置权限
            List<GrantedAuthority> authorities = roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            // 生成认证信息
            return new UsernamePasswordAuthenticationToken(userName, password, authorities);
        }
        // 验证不成功就抛出异常
        throw new BadCredentialsException("The userName or password error.");

    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(UsernamePasswordAuthenticationToken.class);
    }

}
