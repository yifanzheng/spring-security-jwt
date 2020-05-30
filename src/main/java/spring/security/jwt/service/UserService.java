package spring.security.jwt.service;

import io.swagger.annotations.ApiImplicitParam;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import spring.security.jwt.entity.User;
import spring.security.jwt.entity.UserRole;
import spring.security.jwt.repository.UserRepository;
import spring.security.jwt.dto.UserRegisterDTO;
import spring.security.jwt.repository.UserRoleRepository;
import spring.security.jwt.service.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

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
    private UserRoleRepository userRoleRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public void register(UserRegisterDTO dto) {
        // 将登录密码进行加密
        String cryptPassword = bCryptPasswordEncoder.encode(dto.getPassword());
        User user = userMapper.convertOfUserRegisterDTO(dto);
        user.setPassword(cryptPassword);

        userRepository.save(user);
    }

    public User getUserByName(String userName) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepository.findByUserName(userName);
        return userOptional
                .orElseThrow(() -> new UsernameNotFoundException("User not found with userName: " + userName));
    }

    public List<String> listUserRoles(String userName) {
        return userRoleRepository.findByUserName(userName)
                .stream()
                .map(UserRole::getRole)
                .collect(Collectors.toList());
    }
}
