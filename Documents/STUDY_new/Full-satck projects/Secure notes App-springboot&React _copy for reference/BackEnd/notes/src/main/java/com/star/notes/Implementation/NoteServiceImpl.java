package com.star.notes.Implementation;

import com.star.notes.Model.Note;
import com.star.notes.Repository.NoteRepo;
import com.star.notes.Service.AuditLogService;
import com.star.notes.Service.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class NoteServiceImpl implements NoteService {

    @Autowired
    private NoteRepo noteRepo;

    @Autowired
    private AuditLogService auditLogService;

    @Override
    public Note createNoteForUser(String username, String content) {
        Note note = new Note();
        note.setContent(content);
        note.setOwnerUsername(username);
        Note savedNote=noteRepo.save(note);
        auditLogService.logNoteCreate(username,note);
        return savedNote;
    }

    @Override
    public Note updateNoteForUser(Long noteId, String content, String username) {
        Note note=noteRepo.findById(noteId).orElseThrow(()->new RuntimeException("Note not found"));
        note.setOwnerUsername(username);
        note.setContent(content);
        Note updatedNote=noteRepo.save(note);
        auditLogService.logNoteUpdate(username,note);
        return updatedNote;
    }

    @Override
    public void deleteNoteForUser(Long noteId, String username) {
        Note note=noteRepo.findById(noteId).orElseThrow(()->new RuntimeException("Note not found"));
auditLogService.logNoteDelete(username,noteId);
        noteRepo.delete(note);
    }

    @Override
    public List<Note> getNotesForUser(String username) {
        List<Note> notes=noteRepo.findByOwnerUsername(username);
        return notes;
    }


}
