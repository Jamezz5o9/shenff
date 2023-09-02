package org.taskspace.taskmanagement.data.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.taskspace.taskmanagement.data.model.Task;
import org.taskspace.taskmanagement.data.model.TaskStatus;
import org.taskspace.usermanagement.data.models.AppUser;

import java.util.List;
import java.util.Optional;

public interface TaskRepository extends JpaRepository<Task, Long> {
    Optional<Task> findByTaskIdAndAppUser(String taskId, AppUser appUser);

    List<Task> findAllByIdAndTaskStatus(long id, TaskStatus status);
}
