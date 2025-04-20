package com.star.notes.Repository;

import com.star.notes.Model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuditLogRep extends JpaRepository<AuditLog, Long> {
    List<AuditLog> findByNoteId(Long noteId);
}
