package spring.security.jwt.web.rest;

import io.swagger.annotations.Api;
import spring.security.jwt.service.UserService;
import spring.security.jwt.service.dto.UserDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * UserResource
 *
 * @author star
 */
@RestController
@RequestMapping("/api/users")
@Api(tags = {"User Resource"})
public class UserResource {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody UserDTO dto) {
        userService.register(dto);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/detail")
    public ResponseEntity<Object> getUsersDetail() {
        return ResponseEntity.ok("Get users detail success.");
    }

}
