package org.taskspace.taskmanagement.service;

import org.taskspace.taskmanagement.data.model.Task;
import org.taskspace.taskmanagement.data.request.TaskRequest;
import org.taskspace.usermanagement.security.UserPrincipal;

import java.util.List;

public interface TaskService {

    Task createTask(TaskRequest request, UserPrincipal userPrincipal);

    List<Task> getAllTasks(UserPrincipal userPrincipal);

    Task updateTask(String taskId, TaskRequest request,  boolean isCompleted, UserPrincipal userPrincipal);

    String deleteTask(String taskId, UserPrincipal userPrincipal);
}
