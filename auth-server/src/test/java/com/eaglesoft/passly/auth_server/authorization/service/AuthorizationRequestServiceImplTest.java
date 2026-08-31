package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import com.eaglesoft.passly.auth_server.authorization.repository.AuthorizationRequestRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationRequestServiceImplTest {

    @Mock
    private AuthorizationRequestRepository repository;

    @InjectMocks
    private AuthorizationRequestServiceImpl service;

    private AuthorizationRequest sampleRequest() {
        return new AuthorizationRequest(
                "state-123",
                "passly-demo-client",
                "http://localhost:8080/login/oauth2/code/passly-demo",
                "challenge-abc",
                "S256",
                "GOOGLE",
                Instant.now().plusSeconds(300)
        );
    }

    @Test
    void shouldSaveAuthorizationRequest() {
        AuthorizationRequest request = sampleRequest();

        service.save(request);

        verify(repository, times(1)).save(request);
        verifyNoMoreInteractions(repository);
    }

    @Test
    void shouldConsumeExistingAuthorizationRequest() {
        AuthorizationRequest request = sampleRequest();
        when(repository.consume("state-123")).thenReturn(Optional.of(request));

        Optional<AuthorizationRequest> result = service.consume("state-123");

        assertThat(result).isPresent();
        assertThat(result.get()).isEqualTo(request);
        verify(repository, times(1)).consume("state-123");
    }

    @Test
    void shouldReturnEmptyWhenAuthorizationRequestDoesNotExist() {
        when(repository.consume("unknown-state")).thenReturn(Optional.empty());

        Optional<AuthorizationRequest> result = service.consume("unknown-state");

        assertThat(result).isEmpty();
        verify(repository, times(1)).consume("unknown-state");
    }

    @Test
    void shouldPropagateRepositoryExceptionOnSave() {
        AuthorizationRequest request = sampleRequest();
        doThrow(new IllegalStateException("Redis unavailable"))
                .when(repository).save(any());

        assertThatThrownBy(() -> service.save(request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Redis unavailable");
    }

    @Test
    void shouldPropagateRepositoryExceptionOnConsume() {
        when(repository.consume("state-123"))
                .thenThrow(new IllegalStateException("Redis unavailable"));

        assertThatThrownBy(() -> service.consume("state-123"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Redis unavailable");
    }
}
