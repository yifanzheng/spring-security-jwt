package spring.security.jwt.web.rest;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.CollectionUtils;
import spring.security.jwt.constant.SecurityConstants;
import spring.security.jwt.constant.UserRoleConstants;
import spring.security.jwt.dto.UserDTO;
import spring.security.jwt.dto.UserLoginDTO;
import spring.security.jwt.entity.User;
import spring.security.jwt.service.UserService;
import spring.security.jwt.dto.UserRegisterDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import spring.security.jwt.util.JwtUtils;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * UserResource
 *
 * @author star
 */
@RestController
@RequestMapping("/api/users")
@Api(tags = {"用户资源"})
public class UserResource {

    @Autowired
    private UserService userService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/login")
    @ApiOperation(value = "用户登录")
    public ResponseEntity<UserDTO> login(@RequestBody UserLoginDTO userLogin) {
        String userName = userLogin.getUserName();
        String password = userLogin.getPassword();
        // 根据登录名获取用户信息
        User user = userService.getUserByName(userName);
        // 验证登录密码是否正确。如果正确，则赋予用户相应权限并生成用户认证信息
        if (user != null && this.bCryptPasswordEncoder.matches(password, user.getPassword())) {
            List<String> roles = userService.listUserRoles(userName);
            // 如果用户角色为空，则默认赋予 ROLE_USER 权限
            if (CollectionUtils.isEmpty(roles)) {
                roles = Collections.singletonList(UserRoleConstants.ROLE_USER);
            }
            // 生成 token
            String token = JwtUtils.generateToken(userName, roles, userLogin.getRememberMe());
            // 设置响应头
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.set(SecurityConstants.TOKEN_HEADER, token);
            // 用户信息
            UserDTO userDTO = new UserDTO();
            userDTO.setUserName(userName);
            userDTO.setEmail(user.getEmail());
            userDTO.setRoles(roles);

            return ResponseEntity.ok().headers(httpHeaders).body(userDTO);
        }
        throw new BadCredentialsException("The userName or password error.");

    }

    @PostMapping("/register")
    @ApiOperation(value = "用户注册")
    public ResponseEntity<Void> register(@RequestBody UserRegisterDTO userRegister) {
        userService.register(userRegister);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/detail")
    @ApiOperation(value = "获取用户详情")
    public ResponseEntity<Object> getUsersDetail() {
        return ResponseEntity.ok("Get users detail success.");
    }

}
