package com.kdt.team04.domain.auth.service;

import static org.apache.commons.lang3.math.NumberUtils.toLong;

import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kdt.team04.common.redis.RedisService;
import com.kdt.team04.common.security.jwt.TokenResponse;
import com.kdt.team04.common.security.jwt.exception.JwtTokenNotFoundException;

@Primary
@Service
public class RedisTokenService implements TokenService {

	private final RedisService redisService;

	public RedisTokenService(RedisService redisService) {
		this.redisService = redisService;
	}

	@Override
	public TokenResponse findByToken(String token) {
		long storedUserId = redisService.getData(token)
			.map(data -> {
				long userId = toLong(data, -1);
				return userId == -1 ? null : userId;
			})
			.orElseThrow(() -> new JwtTokenNotFoundException("Refresh token not found."));

		return new TokenResponse(token, storedUserId);
	}

	@Override
	public TokenResponse findByUserId(Long userId) {
		String token = redisService.getData(userId.toString())
			.orElseThrow(() -> new JwtTokenNotFoundException("Refresh token not found."));

		return new TokenResponse(token, userId);
	}

	@Override
	@Transactional
	public String save(Long userId, String refreshToken, Long expirySeconds) {
		redisService.setDataWithExpiration(String.valueOf(userId), refreshToken, expirySeconds);
		return refreshToken;
	}

	@Override
	@Transactional
	public void delete(Long userId) {
		redisService.deleteData(String.valueOf(userId));
	}
}
