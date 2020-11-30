package spring.security.jwt.constant;

/**
 * RedisKeyConstants
 *
 * @author star
 */
public final class RedisKeyConstants {

    private RedisKeyConstants() {
        throw new IllegalStateException("Cannot create instance of static constant class");
    }

    public static final String PREFIX_REFRESH_TOKEN = "jwt:refresh_token:";

    public static final String PREFIX_REFRESH_TOKEN_TRANSITION = "jwt:refresh_token_transition:";


}
