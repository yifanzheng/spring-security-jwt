package spring.security.jwt.service.mapper;

import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import spring.security.jwt.dto.UserRegisterDTO;
import spring.security.jwt.entity.User;

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
