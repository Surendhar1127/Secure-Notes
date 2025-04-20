package com.star.notes.Model;


import jakarta.persistence.*;
import lombok.Data;
import lombok.Generated;

@Data
@Entity
public class Note {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
   // @Lob
    private String content;

    private String ownerUsername;
}
