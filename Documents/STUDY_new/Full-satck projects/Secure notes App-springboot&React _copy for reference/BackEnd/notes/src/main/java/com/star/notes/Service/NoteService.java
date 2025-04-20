package com.star.notes.Service;

import com.star.notes.Model.Note;

import java.util.List;
import java.util.Optional;

public interface NoteService {

    Note createNoteForUser(String username, String content);

    Note updateNoteForUser(Long noteId, String content,String username);

    void deleteNoteForUser(Long noteId, String username);

    List<Note> getNotesForUser(String username);
}
