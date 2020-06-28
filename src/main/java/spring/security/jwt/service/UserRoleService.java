package spring.security.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring.security.jwt.entity.UserRole;
import spring.security.jwt.repository.UserRoleRepository;

import java.util.List;

/**
 * UserRoleService
 *
 * @author star
 */
@Service
public class UserRoleService {

    @Autowired
    private UserRoleRepository userRoleRepository;

    public List<UserRole> listUserRoles(String userName) {
        return userRoleRepository.findByUserName(userName);
    }

    @Transactional(rollbackFor = Exception.class)
    public void deleteByUserName(String userName) {
        userRoleRepository.deleteByUserName(userName);
    }
}
