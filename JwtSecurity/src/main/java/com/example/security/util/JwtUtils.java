package com.example.security.util;

import com.example.security.entity.UserDto;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Jwt工具类
 *
 * @author kevin
 * @date 2018-10-02 16:24
 **/
public final class JwtUtils {

    private JwtUtils() {
    }

    /**
     * 根据用户名生成token
     *
     * @return
     */
    public static String generateToken(UserDto user) {
        HashMap<String, Object> map = new HashMap<>();
        // 将用户名当作角色role信息，可以put任意的数据
        map.put("username", user.getUsername());
        map.put("password", user.getPassword());
        // 生成jwt字符串
        String jwt = Jwts.builder()
                .setClaims(map)
                .setExpiration(new Date(System.currentTimeMillis() + Constants.EXPIRATION_TIME))// 设置有效时间为100hours
                .signWith(SignatureAlgorithm.HS512, Constants.SECRET)// 生成签证信息
                .compact();
        return Constants.TOKEN_PREFIX + jwt;// jwt前面一般都会加Bearer;一般是在请求头里加入Authorization，并加上Bearer标注
    }

    /**
     * 验证token，解析token中的信息。
     * 如果解析失败，说明token是无效的
     *
     * @return
     */
    public static Map<String, Object> validateTokenAndAddRoleToHeader(String token) {
        if (token != null) {
            // 解析token
            try {
                Map<String, Object> body = Jwts.parser()
                        .setSigningKey(Constants.SECRET)
                        .parseClaimsJws(token.replace(Constants.TOKEN_PREFIX, ""))
                        .getBody();
                return body;
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        } else {
            throw new RuntimeException("Missing token");
        }
    }

}
