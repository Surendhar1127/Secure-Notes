package com.star.notes.Service;

import com.star.notes.Model.AuditLog;
import com.star.notes.Model.Note;

import java.util.List;

public interface AuditLogService {
    void logNoteUpdate(String username, Note note);

    void logNoteCreate(String username, Note note);

    void logNoteDelete(String username, Long noteId);

    List<AuditLog> getAllAuditLog();

    List<AuditLog> getAuditLogsByNoteId(Long noteId);
}
