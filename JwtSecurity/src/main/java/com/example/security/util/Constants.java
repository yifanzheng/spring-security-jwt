package com.example.security.util;

/**
 * 常量类
 *
 * @author kevin
 * @date 2018-10-12 22:38
 **/
public final class Constants {

    private Constants(){}

    /**
     * secret就是用来进行jwt的签发和jwt的验证,是服务端的私钥，可以任意指定
     */
    public static final String SECRET = "secrect";

    /**
     * 有效时间100hours
     */
    public static final long EXPIRATION_TIME = 360000000L;

    /**
     * 一般是在请求头里加入Authorization，并加上Bearer标注
     */
    public static final String TOKEN_PREFIX = "Bearer ";

    /**
     * Authorization请求头
     */
    public static final String AUTO_HEADER = "Authorization";

}
