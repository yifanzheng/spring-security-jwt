package spring.security.jwt.security;

/**
 * TokenCacheDTO
 *
 * @author star
 */
public class JwtInfo {

    private String token;

    private Long createTime;

    public JwtInfo() {
    }

    public JwtInfo(String token, Long createTime) {
        this.token = token;
        this.createTime = createTime;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public long getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Long createTime) {
        this.createTime = createTime;
    }
}
