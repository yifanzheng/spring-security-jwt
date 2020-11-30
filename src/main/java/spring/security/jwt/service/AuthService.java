package spring.security.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import spring.security.jwt.constant.JwtConstants;
import spring.security.jwt.constant.RedisKeyConstants;
import spring.security.jwt.constant.UserRoleConstants;
import spring.security.jwt.dto.UserDTO;
import spring.security.jwt.dto.UserLoginDTO;
import spring.security.jwt.entity.User;
import spring.security.jwt.security.JwtInfo;
import spring.security.jwt.security.JwtUser;
import spring.security.jwt.util.JwtUtils;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

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
    private JwtRedisCacheService jwtRedisCacheService;

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
        Optional<User> userOptional = userService.getUserByName(userName);
        if (!userOptional.isPresent()) {
            throw new UsernameNotFoundException("User not found with userName: " + userName);
        }
        User user = userOptional.get();
        // 1. 验证登录密码是否正确。如果正确，则赋予用户相应权限并生成用户认证信息
        if (this.bCryptPasswordEncoder.matches(password, user.getPassword())) {
            List<String> roles = userService.listUserRoles(userName);
            // 如果用户角色为空，则默认赋予 ROLE_USER 角色
            if (CollectionUtils.isEmpty(roles)) {
                roles = Collections.singletonList(UserRoleConstants.ROLE_USER);
            }
            // 2. 生成 jwt 信息
            JwtInfo jwtInfo = this.generateJwtInfo(userName, roles, userLogin.getRememberMe());
            // 3. 缓存 jwt
            String key = RedisKeyConstants.PREFIX_REFRESH_TOKEN + userName;
            jwtRedisCacheService.setValue(key, jwtInfo, JwtConstants.EXPIRE_REFRESH_TIME);

            // 4. 设置认证信息到 Spring Security 上下文中
            Authentication authentication = JwtUtils.getAuthentication(jwtInfo.getToken());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 用户信息
            UserDTO userDTO = new UserDTO();
            userDTO.setUserName(userName);
            userDTO.setEmail(user.getEmail());
            userDTO.setRoles(roles);

            return new JwtUser(jwtInfo.getToken(), userDTO);
        }
        throw new BadCredentialsException("The user name or password error.");
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

    private JwtInfo generateJwtInfo(String userName, List<String> roles, boolean rememberMe) {
        long createTime = System.currentTimeMillis();
        String accessToken = JwtUtils.createToken(userName, roles, createTime, rememberMe);

        return new JwtInfo(accessToken, createTime);
    }
}
