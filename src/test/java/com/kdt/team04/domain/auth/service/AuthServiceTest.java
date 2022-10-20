package com.kdt.team04.domain.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import com.kdt.team04.common.exception.BusinessException;
import com.kdt.team04.common.exception.EntityNotFoundException;
import com.kdt.team04.common.security.jwt.Jwt;
import com.kdt.team04.domain.auth.dto.JwtToken;
import com.kdt.team04.domain.auth.dto.request.SignUpRequest;
import com.kdt.team04.domain.auth.dto.response.SignInResponse;
import com.kdt.team04.domain.auth.dto.response.SignUpResponse;
import com.kdt.team04.domain.user.Role;
import com.kdt.team04.domain.user.dto.request.CreateUserRequest;
import com.kdt.team04.domain.user.dto.response.UserResponse;
import com.kdt.team04.domain.user.service.UserService;

@Transactional
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

	@InjectMocks
	AuthService authService;

	@Mock
	UserService userService;

	@Mock
	Jwt jwt;

	@Mock
	PasswordEncoder passwordEncoder;

	@Test
	@DisplayName("SignIn 성공 테스트")
	void testSignInSuccess() {
		//given
		String password = "@Test1234";
		String encodedPassword = "$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.";
		UserResponse userResponse = new UserResponse(1L,
			"test00",
			encodedPassword,
			"nickname",
			null,
			"test00@gmail.com",
			null,
			Role.USER
		);

		List<GrantedAuthority> authorities = new ArrayList<>(
			Collections.singleton(new SimpleGrantedAuthority("USER")));
		Jwt.Claims claims = Jwt.Claims.builder(userResponse.id(), userResponse.username(),
			new String[] {String.valueOf(Role.USER)}).build();
		JwtToken accessToken = new JwtToken("accessToken", "accessToken", 60);
		JwtToken refreshToken = new JwtToken("refreshToken", "refreshToken", 120);
		given(passwordEncoder.matches(password, encodedPassword)).willReturn(true);
		given(userService.findByUsername(userResponse.username())).willReturn(userResponse);
		given(jwt.generateAccessToken(any(Jwt.Claims.class))).willReturn(accessToken);
		given(jwt.verify("accessToken")).willReturn(claims);
		given(jwt.generateRefreshToken(userResponse.id())).willReturn(refreshToken);
		given(jwt.getAuthorities(any(Jwt.Claims.class))).willReturn(authorities);

		//when
		SignInResponse signInResponse = authService.signIn(userResponse.username(), password);

		//then
		verify(passwordEncoder, times(1)).matches(password, encodedPassword);
		verify(userService, times(1)).findByUsername(userResponse.username());
		verify(jwt, times(1)).verify("accessToken");
		verify(jwt, times(1)).generateAccessToken(any(Jwt.Claims.class));
		verify(jwt, times(1)).generateRefreshToken(userResponse.id());

		assertThat(signInResponse.id()).isEqualTo(userResponse.id());
		assertThat(signInResponse.username()).isEqualTo(userResponse.username());
		assertThat(signInResponse.nickname()).isEqualTo(userResponse.nickname());
	}

	@Test
	@DisplayName("비밀번호가 맞지 않으면 SignIn에 실패한다.")
	void testSignInFail() {
		//given
		String password = "@Test1234";
		String encodedPassword = "$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.";
		UserResponse userResponse = new UserResponse(1L,
			"test00",
			encodedPassword,
			"nickname",
			null,
			"test00@gmail.com",
			null,
			Role.USER
		);
		given(userService.findByUsername(userResponse.username())).willReturn(userResponse);
		given(passwordEncoder.matches(password, encodedPassword)).willReturn(false);
		//when, then
		assertThatThrownBy(() -> authService.signIn(userResponse.username(), password)).isInstanceOf(
			BusinessException.class);

		verify(userService, times(1)).findByUsername(userResponse.username());
		verify(passwordEncoder, times(1)).matches(password, encodedPassword);
	}

	@Test
	@DisplayName("Username이 맞지 않으면 SignIn에 실패한다.")
	void testSignInWithNotFoundUser() {
		//given
		String password = "@Test1234";
		String notExistUsername = "noname";

		given(userService.findByUsername(notExistUsername)).willThrow(EntityNotFoundException.class);
		//when, then
		assertThatThrownBy(() -> authService.signIn("noname", password)).isInstanceOf(BusinessException.class)
			.hasMessageContaining(
				MessageFormat.format("username : {0} not found", notExistUsername));

		verify(userService, times(1)).findByUsername(notExistUsername);
	}

	@Test
	@DisplayName("SignUp 성공 테스트")
	void testSignUpSuccess() {
		//given
		String password = "@Test1234";
		String encodedPassword = "$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.";
		Long userId = 1L;
		CreateUserRequest userCreateRequest = new CreateUserRequest("username", encodedPassword,
			"nickname", "username@gmail.com", null, Role.USER);
		SignUpRequest signUpRequest = new SignUpRequest("username", password, "nickname", userCreateRequest.email());

		given(passwordEncoder.encode(password)).willReturn(encodedPassword);
		given(userService.create(userCreateRequest)).willReturn(userId);

		//when
		SignUpResponse signUpResponse = authService.signUp(signUpRequest);

		//then
		assertThat(signUpResponse.id()).isEqualTo(userId);
	}

}