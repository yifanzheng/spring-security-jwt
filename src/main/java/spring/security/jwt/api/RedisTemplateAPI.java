package spring.security.jwt.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Redis 操作 API
 *
 * @author star
 */
@Service
public class RedisTemplateAPI {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 删除指定 key 的缓存
     *
     * @param key 键
     */
    public void delete(String key) {
        redisTemplate.delete(key);
    }

    /**
     * 存入缓存值并设置过期时间（秒）
     *
     * @param key     键
     * @param value   缓存值
     * @param expireTime 过期时间（以ms为单位）
     */
    public void setValue(String key, Object value, long expireTime) {
        redisTemplate.opsForValue().set(key, value, expireTime, TimeUnit.MILLISECONDS);
    }

    /**
     * 根据 key 获取缓存值
     *
     * @param key 键
     */
    public Object getValue(String key) {
        return redisTemplate.opsForValue().get(key);
    }

}