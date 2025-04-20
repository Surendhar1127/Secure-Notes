package com.star.notes.Implementation;


import com.star.notes.Model.AuditLog;
import com.star.notes.Model.Note;
import com.star.notes.Repository.AuditLogRep;
import com.star.notes.Service.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuditLogServiceServiceImpl implements AuditLogService {

@Autowired
private AuditLogRep auditLogRep;

    @Override
    public void logNoteCreate(String username, Note note){
        AuditLog auditLog = new AuditLog();

        auditLog.setUsername(username);
        auditLog.setAction("CREATE");
        auditLog.setNoteId(note.getId());
        auditLog.setNoteContent(note.getContent());
        auditLog.setTimestamp(LocalDateTime.now());

auditLogRep.save(auditLog);
    }

    @Override
    public void logNoteUpdate(String username, Note note){
        AuditLog auditLog = new AuditLog();

        auditLog.setUsername(username);
        auditLog.setAction("UPDATE");
        auditLog.setNoteId(note.getId());
        auditLog.setNoteContent(note.getContent());
        auditLog.setTimestamp(LocalDateTime.now());

        auditLogRep.save(auditLog);
    }

    @Override
    public void logNoteDelete(String username, Long noteId){
        AuditLog auditLog = new AuditLog();

        auditLog.setUsername(username);
        auditLog.setAction("DELETE");
        auditLog.setNoteId(noteId);
        auditLog.setTimestamp(LocalDateTime.now());

        auditLogRep.save(auditLog);
    }

    @Override
    public List<AuditLog> getAllAuditLog() {
        return auditLogRep.findAll();
    }

    @Override
    public List<AuditLog> getAuditLogsByNoteId(Long noteId) {
        return auditLogRep.findByNoteId(noteId);
    }
}
