package spring.security.jwt.entity;

import javax.persistence.*;

/**
 * UserRole
 *
 * @author star
 */
@Entity
@Table(name = "user_role")
public class UserRole extends AbstractAuditingEntity{

    private static final long serialVersionUID = 1997955934111931587L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_name", nullable = false)
    private String userName;

    @Column(name = "role", length = 15, nullable = false)
    private String role;

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

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
