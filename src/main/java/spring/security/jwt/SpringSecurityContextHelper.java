package spring.security.jwt;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

/**
 * SpringSecurityContextHelper
 *
 * @author star
 */
@Component
public class SpringSecurityContextHelper implements ApplicationContextAware {

    private static ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
       SpringSecurityContextHelper.applicationContext = applicationContext;
        HikariDataSource
    }

    /**
     * 根据一个 bean 的类型获取相应的 bean
     */
    public static <T> T getBean(Class<T> requiredType) {
        if (applicationContext == null) {
            return null;
        }
        return applicationContext.getBean(requiredType);
    }
}
