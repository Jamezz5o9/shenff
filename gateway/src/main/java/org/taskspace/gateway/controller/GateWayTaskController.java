package org.taskspace.gateway.controller;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.taskspace.gateway.response.ApiResponse;
import org.taskspace.taskmanagement.controller.TaskController;
import org.taskspace.taskmanagement.data.model.Task;
import org.taskspace.taskmanagement.data.request.TaskRequest;
import org.taskspace.usermanagement.annotation.CurrentUser;
import org.taskspace.usermanagement.security.UserPrincipal;

import java.util.List;

@RestController
@RequestMapping("/task")
@RequiredArgsConstructor
@Tag(name = "TaskSpace tasks Management", description = "Endpoints for managing all Tasks")
@SecurityRequirement(name = "BearerAuth")
public class GateWayTaskController {

    private final TaskController taskController;

    @PostMapping()
    public ResponseEntity<ApiResponse> createTask(@RequestBody @Valid TaskRequest request,
                                                  @CurrentUser UserPrincipal userPrincipal) {
        Task createdTask = taskController.createTask(request, userPrincipal);
        return new ResponseEntity<>(new ApiResponse(true, createdTask), HttpStatus.OK);
    }


    @GetMapping()
    public ResponseEntity<ApiResponse> getAllUserTask(@CurrentUser UserPrincipal userPrincipal) {
        List<Task> userTasks = taskController.getAllUserTask(userPrincipal);
        return new ResponseEntity<>(new ApiResponse(true, userTasks), HttpStatus.OK);
    }


    @PutMapping()
    public ResponseEntity<ApiResponse> updateTask(@RequestParam("taskId") String taskId,
                                                  @RequestParam("completed") boolean isCompleted,
                                                  TaskRequest request,
                                                  @CurrentUser UserPrincipal userPrincipal) {
        Task updatedTask = taskController.updateTask(taskId, request, isCompleted, userPrincipal);
        return new ResponseEntity<>(new ApiResponse(true, updatedTask), HttpStatus.OK);
    }


    @DeleteMapping()
    public ResponseEntity<ApiResponse> deleteTask(@RequestParam("taskId") String taskId,
                                                  @CurrentUser UserPrincipal userPrincipal) {
        String deletedTask = taskController.deleteTask(taskId, userPrincipal);
        return new ResponseEntity<>(new ApiResponse(true, deletedTask), HttpStatus.OK);
    }
}