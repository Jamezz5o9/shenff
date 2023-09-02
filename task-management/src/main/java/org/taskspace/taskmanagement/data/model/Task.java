package org.taskspace.taskmanagement.data.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.taskspace.usermanagement.data.models.AppUser;

import java.time.LocalDate;

@Setter
@Getter
@Entity(name = "task")
public class Task {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @JsonIgnore
    private Long id;

    private String taskId;

    private String taskTitle;

    private String taskBody;

    @Enumerated(EnumType.STRING)
    private Priority taskPriority;

    private boolean completed;

    @ManyToOne
    private AppUser appUser;

    @Enumerated(EnumType.STRING)
    private TaskStatus taskStatus;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm")
    @Column(name = "created_at", insertable = false, updatable = false)
    private LocalDate createdAt;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm")
    @Column(name = "modified_at", insertable = false, updatable = false)
    private LocalDate modifiedAt;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm")
    @Column(name = "deleted_at", insertable = false, updatable = false)
    private LocalDate deletedAt;
}
