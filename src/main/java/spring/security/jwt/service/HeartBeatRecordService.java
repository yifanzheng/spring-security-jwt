package spring.security.jwt.service;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import spring.security.jwt.dto.HeartBeatRecordDTO;
import spring.security.jwt.entity.HeartBeatRecord;
import spring.security.jwt.repository.HeartBeatRecordRepository;

/**
 * HeartBeatRecordService
 *
 * @author star
 */
@Service
public class HeartBeatRecordService {

    @Autowired
    private HeartBeatRecordRepository heartBeatRecordRepository;

    public Page<HeartBeatRecordDTO> listByPage(Pageable pageable) {
        Page<HeartBeatRecord> heartBeatRecordPage = heartBeatRecordRepository.findAll(pageable);
        return heartBeatRecordPage.map(heartBeatRecord -> {
            HeartBeatRecordDTO recordDTO = new HeartBeatRecordDTO();
            BeanUtils.copyProperties(heartBeatRecord, recordDTO);
            return recordDTO;
        });
    }
}
