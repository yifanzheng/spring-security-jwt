package spring.security.jwt.service;

import spring.security.jwt.entity.User;
import spring.security.jwt.repository.UserRepository;
import spring.security.jwt.service.dto.UserDTO;
import spring.security.jwt.service.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

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

    public void register(UserDTO dto) {
        User user = userMapper.convertToUserDTO(dto);
        userRepository.save(user);
    }

    public User getUserByName(String username, String password) {
        Optional<User> usernameOptional = userRepository.findByUsernameAndPasssword(username, password);
        return usernameOptional
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
    }
}
