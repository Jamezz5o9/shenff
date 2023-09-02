package org.taskspace.taskmanagement.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.taskspace.taskmanagement.data.model.Task;
import org.taskspace.taskmanagement.data.request.TaskRequest;
import org.taskspace.taskmanagement.service.TaskService;
import org.taskspace.usermanagement.security.UserPrincipal;

import java.util.List;

@Component
@RequiredArgsConstructor

public class TaskController {
    private final TaskService taskService;

    public Task createTask(TaskRequest request, UserPrincipal userPrincipal){
        return taskService.createTask(request, userPrincipal);
    }

    public List<Task> getAllUserTask(UserPrincipal userPrincipal){
        return taskService.getAllTasks(userPrincipal);
    }

    public Task updateTask(String taskId, TaskRequest request, boolean isCompleted, UserPrincipal userPrincipal){
        return taskService.updateTask(taskId, request, isCompleted, userPrincipal);
    }

    public String deleteTask(String taskId, UserPrincipal userPrincipal){
        return taskService.deleteTask(taskId, userPrincipal);
    }
}