package spring.security.jwt.service.mapper;

import spring.security.jwt.dto.UserDTO;
import spring.security.jwt.entity.User;
import spring.security.jwt.dto.UserRegisterDTO;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;

/**
 * UserMapper
 *
 * @author star
 */
@Service
public class UserMapper {

    public User convertOfUserRegisterDTO(UserRegisterDTO dto) {
        User user = new User();
        BeanUtils.copyProperties(dto, user);

        return user;
    }
}
