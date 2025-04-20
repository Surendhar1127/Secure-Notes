package com.star.notes.Repository;

import com.star.notes.Model.Note;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface NoteRepo extends JpaRepository<Note,Long> {

    List<Note> findByOwnerUsername(String username);
}
