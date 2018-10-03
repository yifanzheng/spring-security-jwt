package com.example.jwtdemo.contoller;

import com.example.jwtdemo.entity.User;
import com.example.jwtdemo.util.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * 控制器
 *
 * @author kevin
 * @date 2018-10-02 16:25
 **/
@RestController
public class DemoController {

    @GetMapping("/api/protect")
    public Object helloWord(){
        return "Hello World! This is a protected api.";
    }

    @PostMapping("/login")
    public Object login(@RequestBody User user){
        if (isValidPassword(user)){
            String token = JwtUtil.generateToken(user.getUsername());
            return new HashMap<String,String>(){{
               put("token",token);
            }};
        }else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * 验证登录信息
     * @param user 用户信息
     * @return
     */
    private boolean isValidPassword(User user) {
        return "admin".equals(user.getUsername())
                && "admin".equals(user.getPassword());
    }


}
