package spring.security.jwt.web.rest;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import spring.security.jwt.dto.UserRegisterDTO;
import spring.security.jwt.service.UserService;

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
