package spring.security.jwt.heartbeat;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spring.security.jwt.dto.HeartBeatRecordDTO;
import spring.security.jwt.util.IpUtils;

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/**
 * AbstractHeartBeatHandler
 *
 * @author star
 */
public abstract class AbstractHeartBeatHandler {

    private ScheduledExecutorService scheduledExecutorService;

    private HeartBeatLogger heartBeatLogger;

    private static final int threadNum = 1;

    protected abstract void handle(HeartBeatRecordDTO recordDTO);

    /**
     * 初始化
     */
    public void init(HeartBeatConfig config, HeartBeatLogger logger) {
        this.heartBeatLogger = logger;
        // 初始化定时任务线程池
        ThreadFactory threadFactory = new ThreadFactoryBuilder()
                .setNameFormat("AbstractHeartBeatHandler-%s")
                .build();
        scheduledExecutorService = Executors.newScheduledThreadPool(threadNum, threadFactory);
        scheduledExecutorService.scheduleWithFixedDelay(new HeartBeatTask(this.getHeartBeatRecord()),
                config.getDelayHandlerTime(), config.getIntervalTime(),
                TimeUnit.MILLISECONDS);
    }

    /**
     * 销毁定时任务线程池
     */
    protected void destroy() {
        if (Objects.nonNull(scheduledExecutorService) && !scheduledExecutorService.isShutdown()) {
            scheduledExecutorService.shutdown();
            scheduledExecutorService = null;
        }
        heartBeatLogger.info("心跳定时任务已关闭");
    }

    private HeartBeatRecordDTO getHeartBeatRecord() {
        HeartBeatRecordDTO recordDTO = new HeartBeatRecordDTO();
        try {
            recordDTO.setProjectPath(HeartBeatRecordHelper.getProjectPath());
            recordDTO.setServerIp(IpUtils.getLocalIP());
            recordDTO.setProcessNum(HeartBeatRecordHelper.getProcessId());
            recordDTO.setProcessStartTime(HeartBeatRecordHelper.getProcessStartTime());
            recordDTO.setHeartBeatTime(Instant.now());
        } catch (Exception e) {
            heartBeatLogger.error("Get heart beat info error.", e);
        }
        return recordDTO;
    }

    private class HeartBeatTask implements Runnable {

        private final HeartBeatRecordDTO heartBeatRecord;

        public HeartBeatTask(HeartBeatRecordDTO heartBeatRecord) {
            this.heartBeatRecord = heartBeatRecord;
        }

        @Override
        public void run() {
            handle(this.heartBeatRecord);
        }
    }
}
