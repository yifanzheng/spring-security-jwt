package spring.security.jwt.api;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * @author star
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class StringRedisTemplateAPITest {

    @Autowired
    private RedisTemplateAPI redisTemplateAPI;

    @Test
    public void testRedisTemplate() {
        String key = "test";
        String value = "value";
        // 设置缓存值
        redisTemplateAPI.setValue(key, value, 30000);
        String value1 = (String)redisTemplateAPI.getValue(key);
        Assert.assertEquals(value, value1);
        // 删除缓存值
        redisTemplateAPI.delete(key);
        String value2 = (String)redisTemplateAPI.getValue(key);
        Assert.assertNull(value2);

    }
}
