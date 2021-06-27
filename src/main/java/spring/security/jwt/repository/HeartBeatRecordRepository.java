package spring.security.jwt.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import spring.security.jwt.entity.HeartBeatRecord;

import java.util.Optional;

/**
 * HeartBeatRecordRepository
 *
 * @author star
 */
public interface HeartBeatRecordRepository extends JpaRepository<HeartBeatRecord, Long> {

    Optional<HeartBeatRecord> findByProjectPathAndServerIpAndProcessNum(@Param("projectPath") String projectPath,
                                                                       @Param("serverIp") String serverIp,
                                                                       @Param("processNum") Integer processNum);

}
