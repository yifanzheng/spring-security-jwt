package com.example.jwtdemo.util;

import io.jsonwebtoken.*;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Jwt工具类
 *
 * @author kevin
 * @date 2018-10-02 16:24
 **/
public class JwtUtil {
    private JwtUtil(){}

    /**
     * secret就是用来进行jwt的签发和jwt的验证,是服务端的私钥，可以任意指定
     */
    private static final String SECRET="secrect";

    /**
     * 有效时间100hours
     */
    private static final long EXPIRATION_TIME = 360000000L;

    /**
     * 一般是在请求头里加入Authorization，并加上Bearer标注
     */
    private static final String TOKEN_PREFIX="Bearer ";

    /**
     * 根据用户名生成token
     * @param username
     * @return
     */
    public static String generateToken(String username){
        HashMap<String, Object> map = new HashMap<>();
        // 可以put任意的数据
        map.put("username",username);
        //生成jwt字符串
        String jwt = Jwts.builder()
                .setClaims(map)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))//设置有效时间为100hours
                .signWith(SignatureAlgorithm.HS512, SECRET)//生成签证信息
                .compact();
        return TOKEN_PREFIX+jwt;//jwt前面一般都会加Bearer;一般是在请求头里加入Authorization，并加上Bearer标注
    }

    /**
     * 解析token，使它生效
     * @param token
     */
    public static void validateToken(String token){
        try {
            //解析token
            Map<String,Object> map= Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token.replace("Bearer ", ""))
                    .getBody();
        } catch (Exception e) {
            throw new IllegalStateException("Invalid Token. "+e.getMessage());
        }
    }

}
