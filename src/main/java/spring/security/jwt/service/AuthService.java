package spring.security.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import spring.security.jwt.constant.UserRoleConstants;
import spring.security.jwt.dto.UserDTO;
import spring.security.jwt.dto.UserLoginDTO;
import spring.security.jwt.entity.User;
import spring.security.jwt.security.JwtUser;
import spring.security.jwt.util.JwtUtils;

import java.util.Collections;
import java.util.List;

/**
 * 用户认证服务
 *
 * @author star
 */
@Service
public class AuthService {

    @Autowired
    private UserService userService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * 用户登录认证
     *
     * @param userLogin 用户登录信息
     */
    public JwtUser authLogin(UserLoginDTO userLogin) {
        String userName = userLogin.getUserName();
        String password = userLogin.getPassword();

        // 根据登录名获取用户信息
        User user = userService.getUserByName(userName);
        // 验证登录密码是否正确。如果正确，则赋予用户相应权限并生成用户认证信息
        if (user != null && this.bCryptPasswordEncoder.matches(password, user.getPassword())) {
            List<String> roles = userService.listUserRoles(userName);
            // 如果用户角色为空，则默认赋予 ROLE_USER 角色
            if (CollectionUtils.isEmpty(roles)) {
                roles = Collections.singletonList(UserRoleConstants.ROLE_USER);
            }
            // 生成 token
            String token = JwtUtils.generateToken(userName, roles, userLogin.getRememberMe());

            // 认证成功后，设置认证信息到 Spring Security 上下文中
            Authentication authentication = JwtUtils.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 用户信息
            UserDTO userDTO = new UserDTO();
            userDTO.setUserName(userName);
            userDTO.setEmail(user.getEmail());
            userDTO.setRoles(roles);

            return new JwtUser(token, userDTO);

        }
        throw new BadCredentialsException("The userName or password error.");
    }

    /**
     * 用户退出登录
     *
     * <p>
     * 清除 Spring Security 上下文中的认证信息
     */
    public void logout() {
        SecurityContextHolder.clearContext();
    }
}
