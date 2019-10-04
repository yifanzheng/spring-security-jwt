package spring.security.jwt.entity;

import javax.persistence.*;

/**
 * User
 *
 * @author star
 */
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", columnDefinition="varchar(15)", nullable = false)
    private String username;

    @Column(name = "password", columnDefinition = "varchar(20)", nullable = false)
    private String password;

    @Column(name = "role", columnDefinition = "varchar(50)")
    private String role;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
