package spring.security.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring.security.jwt.dto.UserDTO;
import spring.security.jwt.dto.UserRegisterDTO;
import spring.security.jwt.entity.User;
import spring.security.jwt.entity.UserRole;
import spring.security.jwt.exception.AlreadyExistsException;
import spring.security.jwt.repository.UserRepository;
import spring.security.jwt.service.mapper.UserMapper;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * UserService
 *
 * @author star
 */
@Service
public class UserService {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRoleService userRoleService;

    @Transactional(rollbackFor = Exception.class)
    public void register(UserRegisterDTO dto) {
        // 预检查用户名是否存在
        Optional<User> userOptional = this.getUserByName(dto.getUserName());
        if (userOptional.isPresent()) {
            throw new AlreadyExistsException("Save failed, the user name already exist.");
        }
        User user = userMapper.convertOfUserRegisterDTO(dto);
        // 将登录密码进行加密
        String cryptPassword = bCryptPasswordEncoder.encode(dto.getPassword());
        user.setPassword(cryptPassword);
        try {
            userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            // 如果预检查没有检查到重复，就利用数据库的完整性检查
            throw new AlreadyExistsException("Save failed, the user name already exist.");

        }
    }

    public Optional<User> getUserByName(String userName) {
        return userRepository.findByUserName(userName);

    }

    public UserDTO getUserInfoByName(String userName) {
        Optional<User> userOptional = this.getUserByName(userName);
        if (!userOptional.isPresent()) {
            throw new UsernameNotFoundException("User not found with user name: " + userName);
        }
        // 获取用户角色
        List<String> roles = this.listUserRoles(userName);
        User user = userOptional.get();
        // 设置用户信息
        UserDTO userDTO = new UserDTO();
        userDTO.setUserName(user.getUserName());
        userDTO.setEmail(user.getEmail());
        userDTO.setRoles(roles);

        return userDTO;
    }

    public List<String> listUserRoles(String userName) {
        return userRoleService.listUserRoles(userName)
                .stream()
                .map(UserRole::getRole)
                .collect(Collectors.toList());
    }

    @Transactional(rollbackFor = Exception.class)
    public void delete(String userName) {
        // 删除用户角色信息
        userRoleService.deleteByUserName(userName);
        // 删除用户基本信息
        userRepository.deleteByUserName(userName);
    }
}
