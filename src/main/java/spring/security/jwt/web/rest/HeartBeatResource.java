package spring.security.jwt.web.rest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.data.web.SortDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import spring.security.jwt.dto.HeartBeatRecordDTO;
import spring.security.jwt.dto.PageDTO;
import spring.security.jwt.heartbeat.HeartBeatHandler;
import spring.security.jwt.service.HeartBeatRecordService;

/**
 * @author star
 */
@RestController
@RequestMapping("/api")
public class HeartBeatResource {

    @Autowired
    private HeartBeatRecordService heartBeatRecordService;

    @GetMapping("/heartBeat/list")
    public ResponseEntity<PageDTO<HeartBeatRecordDTO>> listByPage(@PageableDefault(sort = {"heartBeatTime"},
            direction = Sort.Direction.DESC) Pageable pageable) {
        Page<HeartBeatRecordDTO> page = heartBeatRecordService.listByPage(pageable);

        return ResponseEntity.ok(PageDTO.of(page.getTotalPages(), page.getContent()));
    }
}
