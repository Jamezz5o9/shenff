package org.taskspace.taskmanagement.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.modelmapper.ModelMapper;
import org.taskspace.taskmanagement.data.model.Priority;
import org.taskspace.taskmanagement.data.model.Task;
import org.taskspace.taskmanagement.data.repositories.TaskRepository;
import org.taskspace.taskmanagement.data.request.TaskRequest;
import org.taskspace.usermanagement.data.models.AppUser;
import org.taskspace.usermanagement.security.UserPrincipal;
import org.taskspace.usermanagement.service.UserService;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.test.util.AssertionErrors.assertEquals;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TaskServiceImplTest {

    @InjectMocks
    private TaskServiceImpl taskService;

    @Mock
    private TaskRepository taskRepository;

    @Mock
    private ModelMapper mapper;

    @Mock
    private UserService userService;

    @Captor
    private ArgumentCaptor<Task> taskCaptor;

    @Mock
    private UserPrincipal userPrincipal;

    private AppUser user;

    @BeforeEach
    void setUp(){

        user = new AppUser();
        user.setEmail("test@example.com");
    }

    @Test
    public void testCreateTask() {
        // Arrange
        TaskRequest taskRequest = new TaskRequest();
        taskRequest.setTaskPriority("HIGH");

        Task taskToSave = new Task();
        taskToSave.setAppUser(user);

        when(userService.findByEmailIgnoreCase(userPrincipal.getEmail())).thenReturn(Optional.of(user));
        when(mapper.map(taskRequest, Task.class)).thenReturn(taskToSave);
        when(taskRepository.save(any(Task.class))).thenReturn(taskToSave);

        // Act
        taskService.createTask(taskRequest, userPrincipal);

        // Assert
        verify(userService, times(1)).findByEmailIgnoreCase(userPrincipal.getEmail());
        verify(mapper, times(1)).map(taskRequest, Task.class);
        verify(taskRepository, times(1)).save(taskCaptor.capture());

        assertEquals("Task should have the correct priority", Priority.HIGH, taskCaptor.getValue().getTaskPriority());
        assertEquals("Task should have the correct user", user, taskCaptor.getValue().getAppUser());
        taskCaptor.getValue();
    }

    @Test
    public void testGetAllTasks() {

        when(userService.findByEmailIgnoreCase(userPrincipal.getEmail())).thenReturn(Optional.of(user));
        when(taskRepository.findAllById(Collections.singleton(user.getId()))).thenReturn(Collections.emptyList());

        // Act
        List<Task> tasks = taskService.getAllTasks(userPrincipal);

        // Assert
        verify(userService, times(1)).findByEmailIgnoreCase(userPrincipal.getEmail());
        verify(taskRepository, times(1)).findAllById(Collections.singleton(user.getId()));

        assertEquals("Should return an empty list", 0, tasks.size());
        // Add more assertions as needed
    }

    @Test
    public void testDeleteTask() {
        // Arrange
        String taskId = "123";

        Task existingTask = new Task();
        existingTask.setTaskId(taskId);
        existingTask.setAppUser(user);

        when(userService.findByEmailIgnoreCase(userPrincipal.getEmail())).thenReturn(Optional.of(user));
        when(taskRepository.findByTaskIdAndAppUser(taskId, user)).thenReturn(Optional.of(existingTask));

        // Act
        String result = taskService.deleteTask(taskId, userPrincipal);

        // Assert
        verify(userService, times(1)).findByEmailIgnoreCase(userPrincipal.getEmail());
        verify(taskRepository, times(1)).findByTaskIdAndAppUser(taskId, user);

        assertEquals("Should return success message", "Task Successfully Deleted", result);
        // Add more assertions as needed
    }
}