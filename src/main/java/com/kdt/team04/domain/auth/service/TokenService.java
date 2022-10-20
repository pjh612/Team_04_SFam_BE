package com.kdt.team04.domain.auth.service;

import com.kdt.team04.common.security.jwt.TokenResponse;

public interface TokenService {
	TokenResponse findByToken(String token);
	TokenResponse findByUserId(Long userId);

	String save(Long userId, String refreshToken, Long expirySeconds);
	void delete(Long userId);
}
