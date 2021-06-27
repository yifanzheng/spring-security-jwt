package spring.security.jwt.heartbeat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import spring.security.jwt.dto.HeartBeatRecordDTO;
import spring.security.jwt.entity.HeartBeatRecord;
import spring.security.jwt.repository.HeartBeatRecordRepository;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.time.Instant;
import java.util.Optional;

/**
 * HeartBeatHandler
 *
 * @author star
 */
@Component
public class HeartBeatHandler extends AbstractHeartBeatHandler {

    private static final Logger log = LoggerFactory.getLogger(HeartBeatHandler.class);

    @Autowired
    private HeartBeatRecordRepository heartBeatRecordRepository;

    @Autowired
    private HeartBeatConfig heartBeatConfig;

    @PostConstruct
    private void init() {
        super.init(heartBeatConfig, new HeartBeatLogger() {
            @Override
            public void error(String message) {
                log.error(message);
            }

            @Override
            public void error(String message, Throwable e) {
                log.error(message, e);
            }

            @Override
            public void info(String message) {
                log.info(message);
            }
        });
    }

    @PreDestroy
    @Override
    public void destroy() {
        super.destroy();
    }

    /**
     * 处理心跳记录
     *
     * @param recordDTO 心跳记录信息
     */
    @Override
    public void handle(HeartBeatRecordDTO recordDTO) {
        Optional<HeartBeatRecord> heartBeatRecordOptional =
                heartBeatRecordRepository.findByProjectPathAndServerIpAndProcessNum(recordDTO.getProjectPath(),
                        recordDTO.getServerIp(), recordDTO.getProcessNum());
        if (heartBeatRecordOptional.isPresent()) {
            HeartBeatRecord heartBeatRecord = heartBeatRecordOptional.get();
            heartBeatRecord.setHeartBeatTime(Instant.now());
            heartBeatRecordRepository.save(heartBeatRecord);
            return;
        }
        HeartBeatRecord heartBeatRecord = new HeartBeatRecord();
        BeanUtils.copyProperties(recordDTO, heartBeatRecord);
        heartBeatRecordRepository.save(heartBeatRecord);
    }
}
