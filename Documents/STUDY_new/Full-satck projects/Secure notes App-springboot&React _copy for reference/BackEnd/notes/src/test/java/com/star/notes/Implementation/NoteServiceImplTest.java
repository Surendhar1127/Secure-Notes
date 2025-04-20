package com.star.notes.Implementation;

import com.star.notes.Model.Note;
import com.star.notes.Repository.NoteRepo;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NoteServiceImplTest {

    @Mock
    NoteRepo noteRepo;

    @Mock
    AuditLogServiceServiceImpl auditLogServiceServiceImpl;

    @InjectMocks
    NoteServiceImpl noteService;

    @BeforeAll
    static void initAll() {
        System.out.println("Before All Tests");
    }

    @Test
     void deleteNoteForUserTest() {
       Note note = new Note();
       Long noteId = 1L;
       String userName = "Note Title";
       note.setId(noteId);
       note.setOwnerUsername(userName);
       note.setContent("test content");
        when(noteRepo.findById(noteId)).thenReturn(Optional.of(note));

        // Act
        noteService.deleteNoteForUser(noteId, userName);

        // Verify delete called
        verify(noteRepo, times(1)).delete(note);
        verify(auditLogServiceServiceImpl, times(1)).logNoteDelete(userName, noteId);
        System.out.println("Tested successfully");
    }
}