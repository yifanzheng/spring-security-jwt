package spring.security.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import spring.security.jwt.entity.User;

import java.util.Optional;

/**
 * UserRepository
 *
 * @author star
 */
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUserName(String userName);

    @Modifying
    void deleteByUserName(String userName);
}
