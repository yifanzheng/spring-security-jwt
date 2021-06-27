package spring.security.jwt.dto;

import java.time.Instant;

/**
 * HeartBeatRecordDTO
 *
 * @author star
 */
public class HeartBeatRecordDTO {

    /**
     * 项目名字
     */
    private String projectPath;

    /**
     * 服务器ip
     */
    private String serverIp;

    /**
     * 进程号
     */
    private Integer processNum;

    /**
     * 进程开启时间
     */
    private Instant processStartTime;

    /**
     * 心跳时间
     */
    private Instant heartBeatTime;

    public String getProjectPath() {
        return projectPath;
    }

    public void setProjectPath(String projectPath) {
        this.projectPath = projectPath;
    }

    public String getServerIp() {
        return serverIp;
    }

    public void setServerIp(String serverIp) {
        this.serverIp = serverIp;
    }

    public Integer getProcessNum() {
        return processNum;
    }

    public void setProcessNum(Integer processNum) {
        this.processNum = processNum;
    }

    public Instant getProcessStartTime() {
        return processStartTime;
    }

    public void setProcessStartTime(Instant processStartTime) {
        this.processStartTime = processStartTime;
    }

    public Instant getHeartBeatTime() {
        return heartBeatTime;
    }

    public void setHeartBeatTime(Instant heartBeatTime) {
        this.heartBeatTime = heartBeatTime;
    }
}
