package com.kdt.team04.domain.auth.service;

import java.text.MessageFormat;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kdt.team04.common.exception.BusinessException;
import com.kdt.team04.common.exception.EntityNotFoundException;
import com.kdt.team04.common.exception.ErrorCode;
import com.kdt.team04.common.security.jwt.Jwt;
import com.kdt.team04.common.security.jwt.JwtAuthentication;
import com.kdt.team04.common.security.jwt.JwtAuthenticationToken;
import com.kdt.team04.domain.auth.dto.JwtToken;
import com.kdt.team04.domain.auth.dto.request.SignUpRequest;
import com.kdt.team04.domain.auth.dto.response.SignInResponse;
import com.kdt.team04.domain.auth.dto.response.SignUpResponse;
import com.kdt.team04.domain.user.Role;
import com.kdt.team04.domain.user.dto.request.CreateUserRequest;
import com.kdt.team04.domain.user.dto.response.UserResponse;
import com.kdt.team04.domain.user.entity.UserSettings;
import com.kdt.team04.domain.user.service.UserService;

@Service
public class AuthService {

	private final UserService userService;
	private final PasswordEncoder passwordEncoder;
	private final Jwt jwt;

	public AuthService(UserService userService, PasswordEncoder passwordEncoder, Jwt jwt) {
		this.userService = userService;
		this.passwordEncoder = passwordEncoder;
		this.jwt = jwt;
	}

	@Transactional
	public SignInResponse signIn(String username, String password) {
		UserResponse foundUser;
		try {
			foundUser = userService.findByUsername(username);
		} catch (EntityNotFoundException e) {
			throw new BusinessException(ErrorCode.AUTHENTICATION_FAILED,
				MessageFormat.format("username : {0} not found", username));
		}
		if (!passwordEncoder.matches(password, foundUser.password())) {
			throw new BusinessException(ErrorCode.AUTHENTICATION_FAILED,
				MessageFormat.format("Password = {0}", password));
		}

		Jwt.Claims claims = Jwt.Claims.builder(foundUser.id(), username, new String[] {String.valueOf(Role.USER)})
			.build();
		JwtToken accessToken = jwt.generateAccessToken(claims);
		JwtToken refreshToken = jwt.generateRefreshToken(foundUser.id());
		JwtAuthentication authentication = new JwtAuthentication(
			accessToken.token(),
			foundUser.id(),
			foundUser.username(),
			foundUser.email()
		);
		JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(authentication, null,
			jwt.getAuthorities(jwt.verify(accessToken.token())));

		UserSettings foundUserSettings = foundUser.userSettings() == null
			? new UserSettings(null, null, null)
			: foundUser.userSettings();

		return new SignInResponse(
			foundUser.id(),
			username,
			foundUser.nickname(),
			foundUser.email(),
			foundUser.profileImageUrl(),
			foundUser.role(),
			foundUserSettings.getLocation().getLatitude(),
			foundUserSettings.getLocation().getLongitude(),
			foundUserSettings.getSearchDistance(),
			accessToken,
			refreshToken,
			authenticationToken
		);
	}

	@Transactional
	public SignUpResponse signUp(SignUpRequest request) {
		String encodedPassword = passwordEncoder.encode(request.password());
		Long userId = userService.create(
			new CreateUserRequest(
				request.username(),
				encodedPassword,
				request.nickname(),
				request.email(),
				null,
				Role.USER));

		return new SignUpResponse(userId);
	}

	public void signOut(Long userId) {
		jwt.invalidateRefreshToken(userId);
	}
}
