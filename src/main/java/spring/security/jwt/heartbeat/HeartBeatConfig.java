package spring.security.jwt.heartbeat;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * HeartBeatConfig
 *
 * @author star
 */
@Configuration
public class HeartBeatConfig {

    /**
     * 延迟执行时间
     */
    @Value("${heart-beat.delayHandlerTime}")
    private Long delayHandlerTime;

    /**
     * 间隔执行时间
     */
    @Value("${heart-beat.intervalTime}")
    private Long intervalTime;

    public Long getDelayHandlerTime() {
        return delayHandlerTime;
    }

    public void setDelayHandlerTime(Long delayHandlerTime) {
        this.delayHandlerTime = delayHandlerTime;
    }

    public Long getIntervalTime() {
        return intervalTime;
    }

    public void setIntervalTime(Long intervalTime) {
        this.intervalTime = intervalTime;
    }
}