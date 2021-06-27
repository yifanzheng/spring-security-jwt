package spring.security.jwt.entity;

import javax.persistence.*;

/**
 * User
 *
 * @author star
 */
@Entity
@Table(name = "user")
public class User extends AbstractAuditingEntity {

    private static final long serialVersionUID = 3340373364530753417L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_name", columnDefinition="varchar(30)", nullable = false, unique = true)
    private String userName;

    @Column(name = "nick_name", columnDefinition = "varchar(30)")
    private String nickName;

    @Column(name = "password", columnDefinition = "varchar(68)", nullable = false)
    private String password;

    @Column(name = "email", columnDefinition = "varchar(40)", nullable = false)
    private String email;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getNickName() {
        return nickName;
    }

    public void setNickName(String nickName) {
        this.nickName = nickName;
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
