package spring.security.jwt.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * UserLoginDTO
 *
 * @author star
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserLoginDTO {

    private String userName;

    private String password;

    /**
     * 是否记住我，默认 false
     */
    private Boolean rememberMe = false;

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Boolean getRememberMe() {
        return rememberMe;
    }

    public void setRememberMe(Boolean rememberMe) {
        this.rememberMe = rememberMe;
    }
}
