package spring.security.jwt.heartbeat;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.time.Instant;

/**
 * HeartBeatRecordHelper
 *
 * @author star
 */
public class HeartBeatRecordHelper {

    private HeartBeatRecordHelper() {

    }

    /**
     * 获取进程号
     *
     * @return 进程号
     */
    public static Integer getProcessId() {
        RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
        String processName = runtimeMXBean.getName();
        return Integer.valueOf(processName.split("@")[0]);

    }

    /**
     * 获取项目名称
     *
     * @return 项目路径
     */
    public static String getProjectPath() {
        return System.getProperty("user.dir");
    }

    /**
     * 获取进程启动时间
     *
     * @return 时间
     */
    public static Instant getProcessStartTime() {
        RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
        return Instant.ofEpochMilli(runtimeMXBean.getStartTime());
    }
}
