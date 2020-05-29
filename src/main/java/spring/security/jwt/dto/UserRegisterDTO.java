package spring.security.jwt.dto;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

/**
 * UserDTO
 *
 * @author star
 **/
public class UserRegisterDTO {

    @NotBlank
    @Size(min = 4, max = 30)
    private String userName;

    @NotBlank
    @Size(min = 6, max = 15)
    private String password;

    @NotBlank
    @Email
    @Size(max = 40)
    private String email;

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

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}