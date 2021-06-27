package spring.security.jwt.entity;

import javax.persistence.*;
import java.time.Instant;

/**
 * 心跳记录
 *
 * @author star
 */
@Entity
@Table(name = "heart_beat_record")
public class HeartBeatRecord extends AbstractAuditingEntity {

    private static final long serialVersionUID = 2986726195041013116L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "project_path", columnDefinition = "varchar(255)")
    private String projectPath;

    @Column(name = "server_ip", columnDefinition = "varchar(15)")
    private String serverIp;

    @Column(name = "process_num")
    private Integer processNum;

    /**
     * 进程开启时间
     */
    @Column(name = "process_start_time")
    private Instant processStartTime;

    /**
     * 心跳时间
     */
    @Column(name = "heart_beat_time")
    private Instant heartBeatTime;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

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
