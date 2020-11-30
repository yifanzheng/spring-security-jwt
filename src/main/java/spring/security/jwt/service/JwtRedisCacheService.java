package spring.security.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import spring.security.jwt.api.RedisTemplateAPI;
import spring.security.jwt.security.JwtInfo;

import java.util.Optional;

/**
 * JwtRedisCacheService
 *
 * @author star
 */
@Service
public class JwtRedisCacheService {

    @Autowired
    private RedisTemplateAPI redisTemplateAPI;

    public void setValue(String key, JwtInfo value, long expireTime) {
       redisTemplateAPI.setValue(key, value, expireTime);
    }

    public Optional<JwtInfo> getValue(String key) {
        Object value = redisTemplateAPI.getValue(key);
        return Optional.ofNullable((JwtInfo)value);
    }
}
