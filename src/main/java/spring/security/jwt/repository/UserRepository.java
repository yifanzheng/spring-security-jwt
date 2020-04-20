package spring.security.jwt.repository;

import spring.security.jwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * UserRepository
 *
 * @author star
 */
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsernameAndPasssword(String username, String password);
}
