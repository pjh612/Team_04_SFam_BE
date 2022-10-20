package com.kdt.team04.domain.auth.service;

import static java.time.LocalDateTime.now;

import java.text.MessageFormat;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kdt.team04.common.exception.EntityNotFoundException;
import com.kdt.team04.common.exception.ErrorCode;
import com.kdt.team04.common.security.jwt.TokenResponse;
import com.kdt.team04.domain.auth.dto.model.entity.Token;
import com.kdt.team04.domain.auth.repository.TokenRepository;

@Service
@Transactional(readOnly = true)
public class JpaTokenService implements TokenService {

	private final TokenRepository tokenRepository;

	public JpaTokenService(TokenRepository tokenRepository) {
		this.tokenRepository = tokenRepository;
	}

	@Override
	public TokenResponse findByToken(String token) {
		Token foundToken = tokenRepository.findById(token).orElseThrow(() -> new EntityNotFoundException(
			ErrorCode.TOKEN_NOT_FOUND, MessageFormat.format("Token = {0}", token)));

		return new TokenResponse(foundToken.getToken(), foundToken.getUserId());
	}

	@Override
	public TokenResponse findByUserId(Long userId) {
		Token foundToken = tokenRepository.findByUserId(userId).orElseThrow(() -> new EntityNotFoundException(
			ErrorCode.TOKEN_NOT_FOUND, MessageFormat.format("userId = {0}", userId)));

		return new TokenResponse(foundToken.getToken(), foundToken.getUserId());
	}

	@Override
	@Transactional
	public String save(Long userId, String refreshToken, Long expirySeconds) {
		Optional<Token> token = tokenRepository.findByUserId(userId);
		if (token.isPresent()) {
			Token updateToken = token.get();
			updateToken.updateToken(refreshToken, now().plusSeconds(expirySeconds));

			return this.tokenRepository.save(updateToken).getToken();
		}

		return this.tokenRepository.save(new Token(userId, refreshToken, now().plusSeconds(expirySeconds))).getToken();
	}

	@Override
	@Transactional
	public void delete(Long userId) {
		Token foundToken = tokenRepository.findByUserId(userId).orElseThrow(() -> new EntityNotFoundException(
			ErrorCode.TOKEN_NOT_FOUND, MessageFormat.format("userId = {0}", userId)));
		tokenRepository.delete(foundToken);
	}
}
