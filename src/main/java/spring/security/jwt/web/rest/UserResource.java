package spring.security.jwt.web.rest;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import spring.security.jwt.dto.UserDTO;
import spring.security.jwt.dto.UserRegisterDTO;
import spring.security.jwt.service.UserService;

import javax.validation.Valid;

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

    @GetMapping("/{userName}")
    @ApiOperation(value = "根据用户名获取用户信息")
    public ResponseEntity<UserDTO> getUser(@PathVariable String userName) {
        UserDTO userDTO = userService.getUserInfoByName(userName);
        return ResponseEntity.ok(userDTO);
    }

    @PostMapping("/register")
    @ApiOperation(value = "用户注册")
    public ResponseEntity<Void> register(@RequestBody @Valid UserRegisterDTO userRegister) {
        userService.register(userRegister);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{userName}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @ApiOperation(value = "根据用户名删除用户信息")
    public ResponseEntity<Void> deleteByUserName(@PathVariable("userName") String userName) {
        userService.delete(userName);
        return ResponseEntity.ok().build();
    }

}
