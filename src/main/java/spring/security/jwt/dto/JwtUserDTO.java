package spring.security.jwt.dto;

/**
 *
 * JwtUserDTO
 *
 * @author star
 */
public class JwtUserDTO {

    private UserDTO user;

    private String token;

    public UserDTO getUser() {
        return user;
    }

    public void setUser(UserDTO user) {
        this.user = user;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
