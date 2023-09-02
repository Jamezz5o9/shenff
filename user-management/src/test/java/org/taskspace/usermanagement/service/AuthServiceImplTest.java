package org.taskspace.usermanagement.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.taskspace.usermanagement.data.dto.request.UserRequest;
import org.taskspace.usermanagement.data.models.AppUser;
import org.taskspace.usermanagement.data.models.Role;
import org.taskspace.usermanagement.data.repository.UserRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthServiceImplTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private ModelMapper modelMapper;

    @Captor
    private ArgumentCaptor<AppUser> userArgumentCaptor;
    @Mock
    private RoleService roleService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthServiceImpl authService;

    private AppUser mockedUser;
    Role userRole;
    private UserRequest userRequest;

    @BeforeEach
    void setUp() {
        mockedUser = new AppUser();
        mockedUser.setId(1L);
        mockedUser.setName("Lekan Sofuyi");
        mockedUser.setEmail("lekan.sofuyi@gmail.com");
        mockedUser.setPassword("pass1234");

        userRole = new Role();
        userRole.setId(1L);
        userRole.setName("USER");

        userRequest = new UserRequest();
        userRequest.setEmail("lekan.sofuyi@gmail.com");
        userRequest.setPassword("pass1234");
        userRequest.setName("Lekan Sofuyi");
    }

    @Test
    public void testRegisterNewUserAccount_Success() {

        when(roleService.findUserRoleByName("USER")).thenReturn(userRole);

        // Mocking userRepository.existsByEmail()
        when(userRepository.existsByEmail(anyString())).thenReturn(false);

        // Mocking passwordEncoder
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");

        // Mocking saveAUser()
        when(modelMapper.map(userRequest, AppUser.class)).thenReturn(mockedUser);
        when(userRepository.save(any(AppUser.class))).thenReturn(mockedUser);

        // Call the method
        AppUser registeredUser = authService.registerNewUserAccount(userRequest);

        // Assertions
        verify(userRepository, times(1)).save(userArgumentCaptor.capture());
        AppUser capturedUser = userArgumentCaptor.getValue();
        assertEquals("lekan.sofuyi@gmail.com", capturedUser.getEmail());
        assertEquals("encodedPassword", capturedUser.getPassword());
        assertNotNull(registeredUser);
        assertEquals("USER", registeredUser.getRoles().getName());
    }
}