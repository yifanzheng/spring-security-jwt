package spring.security.jwt.service.mapper;

import spring.security.jwt.entity.User;
import spring.security.jwt.service.dto.UserDTO;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;

/**
 * UserMapper
 *
 * @author star
 */
@Service
public class UserMapper {

    public User convertToUserDTO(UserDTO dto) {
        User user = new User();
        BeanUtils.copyProperties(dto, user);
        return user;
    }
}
