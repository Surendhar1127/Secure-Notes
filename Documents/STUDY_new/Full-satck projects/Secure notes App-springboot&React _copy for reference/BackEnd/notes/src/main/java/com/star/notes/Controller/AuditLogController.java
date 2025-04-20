package com.star.notes.Controller;


import com.star.notes.Model.AuditLog;
import com.star.notes.Service.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/audit")
public class AuditLogController {


    @Autowired
    private AuditLogService auditLogService;


    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping
    public List<AuditLog>  getAuditLogs() {
        return auditLogService.getAllAuditLog();
    }



    @GetMapping("/note/{noteId}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public List<AuditLog>  getAuditLogsByNoteId(@PathVariable Long noteId) {

        return auditLogService.getAuditLogsByNoteId(noteId);
    }
}
