package spring.security.jwt.web.rest;

import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.security.jwt.constant.SecurityConstants;
import spring.security.jwt.dto.JwtUserDTO;
import spring.security.jwt.dto.UserDTO;
import spring.security.jwt.dto.UserLoginDTO;
import spring.security.jwt.service.AuthService;
import spring.security.jwt.util.JwtUtils;

/**
 * AuthResource
 *
 * @author star
 */
@RestController
@RequestMapping("/api/auth")
public class AuthResource {

    @Autowired
    private AuthService authService;


    @PostMapping("/login")
    @ApiOperation(value = "用户登录认证")
    public ResponseEntity<UserDTO> login(@RequestBody UserLoginDTO userLogin) {
        // 用户认证
        JwtUserDTO jwtUserDTO = authService.authLogin(userLogin);
        String token = jwtUserDTO.getToken();
        // 认证成功后，设置认证信息到 Spring Security 上下文中
        Authentication authentication = JwtUtils.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 将 token 存入响应头中返回
        HttpHeaders httpHeaders = new HttpHeaders();
        // 添加 token 前缀 "Bearer "
        httpHeaders.set(SecurityConstants.TOKEN_HEADER, SecurityConstants.TOKEN_PREFIX + token);

        return new ResponseEntity<>(jwtUserDTO.getUser(), httpHeaders, HttpStatus.OK);

    }

    @PostMapping("/logout")
    @ApiOperation(value = "用户登出")
    public ResponseEntity<Void> logout() {
        authService.logout();
        return ResponseEntity.ok().build();
    }
}
