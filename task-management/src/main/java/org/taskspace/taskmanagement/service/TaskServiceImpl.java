package org.taskspace.taskmanagement.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.taskspace.taskmanagement.data.model.Priority;
import org.taskspace.taskmanagement.data.model.Task;
import org.taskspace.taskmanagement.data.repositories.TaskRepository;
import org.taskspace.taskmanagement.data.request.TaskRequest;
import org.taskspace.taskmanagement.exception.TaskSpaceException;
import org.taskspace.usermanagement.data.models.AppUser;
import org.taskspace.usermanagement.exception.TaskSpaceUserManagementException;
import org.taskspace.usermanagement.security.UserPrincipal;
import org.taskspace.usermanagement.service.UserService;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

import static org.taskspace.taskmanagement.data.model.TaskStatus.ACTIVE;
import static org.taskspace.taskmanagement.data.model.TaskStatus.DELETED;
import static org.taskspace.taskmanagement.utils.TaskUtils.generateTaskId;

@Service
@RequiredArgsConstructor
@Slf4j
public class TaskServiceImpl implements TaskService{
    private final TaskRepository taskRepository;
    private final ModelMapper mapper;
    private final UserService userService;

    public Task createTask(TaskRequest request, UserPrincipal userPrincipal){
        AppUser foundUser = internalFindUserByEmail(userPrincipal.getEmail());
        Task task = mapper.map(request, Task.class);
        task.setCreatedAt(LocalDate.from(Instant.now()));
        task.setTaskPriority(Priority.valueOf(request.getTaskPriority()));
        task.setTaskId(generateTaskId());
        task.setTaskStatus(ACTIVE);
        task.setAppUser(foundUser);
        return taskRepository.save(task);
    }

    public List<Task> getAllTasks(UserPrincipal userPrincipal){
        log.info("Email: " + userPrincipal.getEmail());
        AppUser foundUser = internalFindUserByEmail(userPrincipal.getEmail());
       return taskRepository.findAllByIdAndTaskStatus(foundUser.getId(), ACTIVE);
    }

    public Task updateTask(String taskId, TaskRequest request, boolean isCompleted, UserPrincipal userPrincipal){
        AppUser foundUser = internalFindUserByEmail(userPrincipal.getEmail());
        Task foundTask = taskRepository.findByTaskIdAndAppUser(taskId, foundUser)
                .orElseThrow((()-> new TaskSpaceException("Task Id Does not Exist")));
        Task updatedTask = mapper.map(request, foundTask.getClass());
        updatedTask.setModifiedAt(LocalDate.now());
        if(request.getTaskPriority() != null) foundTask.setTaskPriority(Priority.valueOf(request.getTaskPriority()));
        if(isCompleted) foundTask.setCompleted(true);
        return taskRepository.save(updatedTask);
    }


    public String deleteTask(String taskId, UserPrincipal userPrincipal){
        AppUser foundUser = internalFindUserByEmail(userPrincipal.getEmail());
        Task foundTask = taskRepository.findByTaskIdAndAppUser(taskId, foundUser)
                .orElseThrow((()-> new TaskSpaceException("Task Id Does not Exist")));
        foundTask.setDeletedAt(LocalDate.now());
        foundTask.setTaskStatus(DELETED);
        taskRepository.save(foundTask);
        return "Task Successfully Deleted";
    }

    private AppUser internalFindUserByEmail(String email){
       return userService.findByEmailIgnoreCase(email)
                .orElseThrow(()-> new TaskSpaceUserManagementException("User not Found"));
    }
}