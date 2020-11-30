package spring.security.jwt.constant;

/**
 * SecurityConstants
 *
 * @author star
 **/
public final class JwtConstants {

    private JwtConstants() {
        throw new IllegalStateException("Cannot create instance of static constant class");
    }

    /**
     * 用于登录的 url
     */
    public static final String AUTH_LOGIN_URL = "/api/auth/login";

    /**
     * JWT签名密钥，这里使用 HS512 算法的签名密钥
     * <p>
     * 注意：最好使用环境变量或 .properties 文件的方式将密钥传入程序
     * 密钥生成地址：http://www.allkeysgenerator.com/
     */
    public static final String SECRET_KEY = "p2s5v8y/B?E(H+MbQeThVmYq3t6w9z$C&F)J@NcRfUjXnZr4u7x!A%D*G-KaPdS";


    /**
     * 一般是在请求头里加入 Authorization，并加上 Bearer 标注
     */
    public static final String PREFIX = "Bearer ";

    /**
     * Authorization 请求头
     */
    public static final String HEADER = "Authorization";

    /**
     * 创建 token 的参数
     */
    public static final String TYPE = "JWT";
    public static final String ISSUER = "security";
    public static final String AUDIENCE = "security-all";

    public static final String ROLE_CLAIM = "role";
    public static final String CREATE_TIME_CLAIM = "create-time";

    /**
     * 当 Remember 是 false 时，token 有效时间 5 分钟
     *
     * <p>
     * 由于实现了 token 刷新，可以将 token 的有效时间设置短一点，这样可以提高安全性
     */
    public static final long EXPIRE_TIME = 1 * 60 * 1000;

    /**
     * refresh token 过期时间: 30 分钟
     */
    public static final long EXPIRE_REFRESH_TIME = 30 * 60 * 1000;

    /**
     * 过渡时间: 15 秒，（视具体情况设置）
     */
    public static final long TRANSITION_TIME = 15 * 1000;

    /**
     * 当 Remember 是 true 时，token 有效时间 7 天
     */
    public static final long EXPIRE_REMEMBER_TIME = 60 * 60 * 24 * 7 * 1000;


}
