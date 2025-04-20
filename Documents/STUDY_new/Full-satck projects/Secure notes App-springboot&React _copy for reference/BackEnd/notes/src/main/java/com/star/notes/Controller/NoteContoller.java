package com.star.notes.Controller;


import com.star.notes.Model.Note;
import com.star.notes.Service.NoteService;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notes")
public class NoteContoller {


    @Autowired
    private NoteService noteService;

    @PostMapping
    public Note createNote(@RequestBody  String content, @AuthenticationPrincipal UserDetails userDetails){
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Authenticated: " +auth);
        System.out.println("Is Authenticated: " + auth.isAuthenticated());
        System.out.println("Authenticated User: " + auth.getName());
        System.out.println("Authorities: " + auth.getAuthorities());
        String userName=userDetails.getUsername();
        System.out.println("USER DETAILS: " + userName);
        return noteService.createNoteForUser(userName,content);

    }

    @PutMapping("/{noteId}")
    public Note updateNote(@RequestBody String content,
                           @PathVariable Long noteId,
                           @AuthenticationPrincipal UserDetails userDetails){
        String userName=userDetails.getUsername();
        System.out.println("USER DETAILS: " + userName);
        return noteService.updateNoteForUser(noteId,content,userName);
    }

    @GetMapping
    public List<Note> getUserNotes(@AuthenticationPrincipal UserDetails userDetails) {
        System.out.println("USER DETAILS: " + userDetails);
        String username = userDetails.getUsername();
        System.out.println("USER DETAILS: " + username);
        return noteService.getNotesForUser(username);
    }

    @DeleteMapping("/{noteId}")
    public void deleteNote(@PathVariable Long noteId,
                           @AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        noteService.deleteNoteForUser(noteId, username);
    }
}
