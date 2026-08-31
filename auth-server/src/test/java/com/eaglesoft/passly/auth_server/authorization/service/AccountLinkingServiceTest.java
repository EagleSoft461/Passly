package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.AccountLinkingException;
import com.eaglesoft.passly.auth_server.authorization.exception.UnverifiedEmailException;
import com.eaglesoft.passly.auth_server.authorization.model.ExternalUserInfo;
import com.eaglesoft.passly.auth_server.domain.LinkedAccount;
import com.eaglesoft.passly.auth_server.domain.User;
import com.eaglesoft.passly.auth_server.repository.LinkedAccountRepository;
import com.eaglesoft.passly.auth_server.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AccountLinkingServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private LinkedAccountRepository linkedAccountRepository;

    private AccountLinkingService service;

    @BeforeEach
    void setUp() {
        service = new AccountLinkingService(userRepository, linkedAccountRepository);
    }

    @Test
    void shouldRejectUnverifiedEmail() {
        ExternalUserInfo userInfo = new ExternalUserInfo(
                "google-sub-123", "ali@gmail.com", false, "Ali", null);

        assertThatThrownBy(() -> service.linkOrCreateUser(LinkedAccount.Provider.GOOGLE, userInfo))
                .isInstanceOf(UnverifiedEmailException.class)
                .hasMessage("Email verification required");

        verifyNoInteractions(userRepository, linkedAccountRepository);
    }

    @Test
    void shouldRejectNullEmailVerified() {
        ExternalUserInfo userInfo = new ExternalUserInfo(
                "google-sub-123", "ali@gmail.com", null, "Ali", null);

        assertThatThrownBy(() -> service.linkOrCreateUser(LinkedAccount.Provider.GOOGLE, userInfo))
                .isInstanceOf(UnverifiedEmailException.class);

        verifyNoInteractions(userRepository, linkedAccountRepository);
    }

    @Test
    void shouldReturnExistingUserForKnownProviderAndSub() {
        ExternalUserInfo userInfo = new ExternalUserInfo(
                "google-sub-123", "ali@gmail.com", true, "Ali Yılmaz", "http://pic.url");

        User existingUser = new User("ali@gmail.com");
        existingUser.setDisplayName("Ali Y.");  // User has customized name

        LinkedAccount existingLink = new LinkedAccount(existingUser, LinkedAccount.Provider.GOOGLE, "google-sub-123");

        when(linkedAccountRepository.findByProviderAndProviderUserId(
                LinkedAccount.Provider.GOOGLE, "google-sub-123"))
                .thenReturn(Optional.of(existingLink));

        User result = service.linkOrCreateUser(LinkedAccount.Provider.GOOGLE, userInfo);

        assertThat(result).isSameAs(existingUser);
        assertThat(result.getDisplayName()).isEqualTo("Ali Y.");  // Not overwritten

        verify(linkedAccountRepository).findByProviderAndProviderUserId(
                LinkedAccount.Provider.GOOGLE, "google-sub-123");
        verifyNoInteractions(userRepository);
        verifyNoMoreInteractions(linkedAccountRepository);
    }

    @Test
    void shouldUpdateDisplayNameForReturningUserIfNull() {
        ExternalUserInfo userInfo = new ExternalUserInfo(
                "google-sub-123", "ali@gmail.com", true, "Ali Yılmaz", null);

        User existingUser = new User("ali@gmail.com");
        existingUser.setDisplayName(null);  // No display name set yet

        LinkedAccount existingLink = new LinkedAccount(existingUser, LinkedAccount.Provider.GOOGLE, "google-sub-123");

        when(linkedAccountRepository.findByProviderAndProviderUserId(
                LinkedAccount.Provider.GOOGLE, "google-sub-123"))
                .thenReturn(Optional.of(existingLink));

        User result = service.linkOrCreateUser(LinkedAccount.Provider.GOOGLE, userInfo);

        assertThat(result.getDisplayName()).isEqualTo("Ali Yılmaz");  // Updated
    }

    @Test
    void shouldLinkToExistingUserByEmail() {
        ExternalUserInfo userInfo = new ExternalUserInfo(
                "github-sub-456", "ali@gmail.com", true, "Ali", null);

        User existingUser = new User("ali@gmail.com");

        when(linkedAccountRepository.findByProviderAndProviderUserId(
                LinkedAccount.Provider.GITHUB, "github-sub-456"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("ali@gmail.com"))
                .thenReturn(Optional.of(existingUser));
        when(linkedAccountRepository.save(any(LinkedAccount.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        User result = service.linkOrCreateUser(LinkedAccount.Provider.GITHUB, userInfo);

        assertThat(result).isSameAs(existingUser);

        ArgumentCaptor<LinkedAccount> captor = ArgumentCaptor.forClass(LinkedAccount.class);
        verify(linkedAccountRepository).save(captor.capture());

        LinkedAccount saved = captor.getValue();
        assertThat(saved.getUser()).isSameAs(existingUser);
        assertThat(saved.getProvider()).isEqualTo(LinkedAccount.Provider.GITHUB);
        assertThat(saved.getProviderUserId()).isEqualTo("github-sub-456");
    }

    @Test
    void shouldCreateNewUserWhenNoMatchFound() {
        ExternalUserInfo userInfo = new ExternalUserInfo(
                "google-sub-789", "newuser@gmail.com", true, "New User", null);

        when(linkedAccountRepository.findByProviderAndProviderUserId(any(), any()))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("newuser@gmail.com"))
                .thenReturn(Optional.empty());
        when(userRepository.save(any(User.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(linkedAccountRepository.save(any(LinkedAccount.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        User result = service.linkOrCreateUser(LinkedAccount.Provider.GOOGLE, userInfo);

        assertThat(result).isNotNull();
        assertThat(result.getEmail()).isEqualTo("newuser@gmail.com");
        assertThat(result.isEmailVerified()).isTrue();
        assertThat(result.getDisplayName()).isEqualTo("New User");

        verify(userRepository).save(any(User.class));
        verify(linkedAccountRepository).save(any(LinkedAccount.class));
    }

    @Test
    void shouldHandleDataIntegrityViolationOnUserCreation() {
        ExternalUserInfo userInfo = new ExternalUserInfo(
                "google-sub-999", "concurrent@gmail.com", true, "User", null);

        when(linkedAccountRepository.findByProviderAndProviderUserId(any(), any()))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("concurrent@gmail.com"))
                .thenReturn(Optional.empty());
        when(userRepository.save(any(User.class)))
                .thenThrow(new DataIntegrityViolationException("Duplicate email"));

        assertThatThrownBy(() -> service.linkOrCreateUser(LinkedAccount.Provider.GOOGLE, userInfo))
                .isInstanceOf(AccountLinkingException.class)
                .hasMessageContaining("concurrent registration");
    }

    @Test
    void shouldHandleDataIntegrityViolationOnLinkedAccountCreation() {
        ExternalUserInfo userInfo = new ExternalUserInfo(
                "google-sub-999", "user@gmail.com", true, "User", null);

        User existingUser = new User("user@gmail.com");

        when(linkedAccountRepository.findByProviderAndProviderUserId(any(), any()))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("user@gmail.com"))
                .thenReturn(Optional.of(existingUser));
        when(linkedAccountRepository.save(any(LinkedAccount.class)))
                .thenThrow(new DataIntegrityViolationException("Duplicate provider+sub"));

        assertThatThrownBy(() -> service.linkOrCreateUser(LinkedAccount.Provider.GOOGLE, userInfo))
                .isInstanceOf(AccountLinkingException.class)
                .hasMessageContaining("already linked to another user");
    }

    @Test
    void shouldNotOverwriteCustomizedDisplayName() {
        ExternalUserInfo userInfo = new ExternalUserInfo(
                "google-sub-123", "ali@gmail.com", true, "Ali Yılmaz Full Name", null);

        User existingUser = new User("ali@gmail.com");
        existingUser.setDisplayName("Ali Y.");  // User customized it

        LinkedAccount existingLink = new LinkedAccount(existingUser, LinkedAccount.Provider.GOOGLE, "google-sub-123");

        when(linkedAccountRepository.findByProviderAndProviderUserId(
                LinkedAccount.Provider.GOOGLE, "google-sub-123"))
                .thenReturn(Optional.of(existingLink));

        User result = service.linkOrCreateUser(LinkedAccount.Provider.GOOGLE, userInfo);

        // Display name should NOT be overwritten
        assertThat(result.getDisplayName()).isEqualTo("Ali Y.");
    }

    @Test
    void shouldSetDisplayNameOnNewUserCreation() {
        ExternalUserInfo userInfo = new ExternalUserInfo(
                "google-sub-new", "new@gmail.com", true, "New User Name", null);

        when(linkedAccountRepository.findByProviderAndProviderUserId(any(), any()))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail(any()))
                .thenReturn(Optional.empty());
        when(userRepository.save(any(User.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(linkedAccountRepository.save(any(LinkedAccount.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        User result = service.linkOrCreateUser(LinkedAccount.Provider.GOOGLE, userInfo);

        assertThat(result.getDisplayName()).isEqualTo("New User Name");
    }

    @Test
    void shouldMultiProviderLink() {
        // User already has Google linked, now linking GitHub
        ExternalUserInfo userInfo = new ExternalUserInfo(
                "github-sub-new", "ali@gmail.com", true, "Ali", null);

        User existingUser = new User("ali@gmail.com");

        when(linkedAccountRepository.findByProviderAndProviderUserId(
                LinkedAccount.Provider.GITHUB, "github-sub-new"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("ali@gmail.com"))
                .thenReturn(Optional.of(existingUser));
        when(linkedAccountRepository.save(any(LinkedAccount.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        User result = service.linkOrCreateUser(LinkedAccount.Provider.GITHUB, userInfo);

        assertThat(result).isSameAs(existingUser);

        ArgumentCaptor<LinkedAccount> captor = ArgumentCaptor.forClass(LinkedAccount.class);
        verify(linkedAccountRepository).save(captor.capture());

        assertThat(captor.getValue().getProvider()).isEqualTo(LinkedAccount.Provider.GITHUB);
        assertThat(captor.getValue().getProviderUserId()).isEqualTo("github-sub-new");
    }
}
