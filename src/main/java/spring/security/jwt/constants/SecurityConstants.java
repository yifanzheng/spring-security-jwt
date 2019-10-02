package spring.security.jwt.constants;

/**
 * SecurityConstants
 *
 * @author star
 **/
public final class SecurityConstants {

    private SecurityConstants() {
        throw new IllegalStateException("Cannot create instance of static constant class");
    }

    /**
     * 用于登录的 url
     */
    public static final String AUTH_LOGIN_URL = "/auth/login";


    /**
     * JWT签名密钥，这里使用 HS512 算法的签名密钥
     * 注意：最好使用环境变量或 .properties 文件的方式将密钥传入程序
     * <p>
     * 密钥生成地址：http://www.allkeysgenerator.com/
     */
    public static final String JWT_SECRET_KEY = "p2s5v8y/B?E(H+MbQeThVmYq3t6w9z$C&F)J@NcRfUjXnZr4u7x!A%D*G-KaPdS";


    /**
     * 一般是在请求头里加入 Authorization，并加上 Bearer 标注
     */
    public static final String TOKEN_PREFIX = "Bearer ";

    /**
     * Authorization 请求头
     */
    public static final String TOKEN_HEADER = "Authorization";

    /**
     * token 类型
     */
    public static final String TOKEN_TYPE = "JWT";

    public static final String TOKEN_ROL_CLAIM = "rol";
    public static final String TOKEN_ISSUER = "security";
    public static final String TOKEN_AUDIENCE = "security-all";

    /**
     * 有效时间 2 hours
     */
    public static final Long EXPIRATION_TIME = 60 * 60 * 2L;


}
