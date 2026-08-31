package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.AccountLinkingException;
import com.eaglesoft.passly.auth_server.authorization.exception.UnverifiedEmailException;
import com.eaglesoft.passly.auth_server.authorization.model.ExternalUserInfo;
import com.eaglesoft.passly.auth_server.domain.LinkedAccount;
import com.eaglesoft.passly.auth_server.domain.User;
import com.eaglesoft.passly.auth_server.repository.LinkedAccountRepository;
import com.eaglesoft.passly.auth_server.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Application service responsible for linking external provider accounts to Passly users.
 *
 * Flow:
 * 1. Validate email_verified = true (security requirement)
 * 2. Check if (provider, sub) already linked → return existing user
 * 3. Check if email exists → link to existing user
 * 4. Otherwise create new user
 * 5. Ensure LinkedAccount record exists
 */
@Service
public class AccountLinkingService {

    private static final Logger logger = LoggerFactory.getLogger(AccountLinkingService.class);

    private final UserRepository userRepository;
    private final LinkedAccountRepository linkedAccountRepository;

    public AccountLinkingService(
            UserRepository userRepository,
            LinkedAccountRepository linkedAccountRepository) {
        this.userRepository = userRepository;
        this.linkedAccountRepository = linkedAccountRepository;
    }

    /**
     * Links or creates a user account based on external identity.
     *
     * @param provider The identity provider (GOOGLE, GITHUB)
     * @param externalUserInfo The external user information
     * @return The linked Passly User
     * @throws UnverifiedEmailException if email is not verified
     * @throws AccountLinkingException if account linking fails due to database constraints
     */
    @Transactional
    public User linkOrCreateUser(
            LinkedAccount.Provider provider,
            ExternalUserInfo externalUserInfo) {

        // Step 1: Validate email verification (security requirement)
        if (externalUserInfo.emailVerified() == null || !externalUserInfo.emailVerified()) {
            throw new UnverifiedEmailException("Email verification required");
        }

        // Step 2: Check if (provider, sub) already exists (returning user)
        Optional<LinkedAccount> existingLink = linkedAccountRepository
                .findByProviderAndProviderUserId(provider, externalUserInfo.sub());

        if (existingLink.isPresent()) {
            User user = existingLink.get().getUser();

            // Update display name only if currently null/blank
            updateDisplayNameIfNeeded(user, externalUserInfo.name());

            logger.info("Returning user authenticated: userId={}, provider={}",
                    user.getId(), provider);
            return user;
        }

        // Step 3: Check if user with email exists (multi-provider linking scenario)
        Optional<User> existingUser = userRepository.findByEmail(externalUserInfo.email());

        User user;
        if (existingUser.isPresent()) {
            user = existingUser.get();
            logger.info("Linking provider to existing user: userId={}, provider={}",
                    user.getId(), provider);
        } else {
            // Step 4: Create new user
            try {
                user = createNewUser(externalUserInfo);
                logger.info("New user created: userId={}, provider={}",
                        user.getId(), provider);
            } catch (DataIntegrityViolationException ex) {
                // Race condition: another thread created user with same email
                throw new AccountLinkingException(
                        "Account linking failed due to concurrent registration"
                );
            }
        }

        // Step 5: Create LinkedAccount
        try {
            LinkedAccount linkedAccount = new LinkedAccount(user, provider, externalUserInfo.sub());
            linkedAccountRepository.save(linkedAccount);
            logger.info("Account linked: userId={}, provider={}", user.getId(), provider);
        } catch (DataIntegrityViolationException ex) {
            // This provider+sub is already linked (should not happen, but defensive)
            throw new AccountLinkingException(
                    "External account is already linked to another user"
            );
        }

        return user;
    }

    private User createNewUser(ExternalUserInfo externalUserInfo) {
        User user = new User(externalUserInfo.email());
        user.setEmailVerified(true);  // Provider verified it

        // Set display name from provider if available
        if (externalUserInfo.name() != null && !externalUserInfo.name().isBlank()) {
            user.setDisplayName(externalUserInfo.name());
        }

        return userRepository.save(user);
    }

    private void updateDisplayNameIfNeeded(User user, String externalName) {
        // Only update if current display name is null/blank
        // Never overwrite user-modified display names
        if ((user.getDisplayName() == null || user.getDisplayName().isBlank())
                && externalName != null && !externalName.isBlank()) {
            user.setDisplayName(externalName);
        }
    }
}
