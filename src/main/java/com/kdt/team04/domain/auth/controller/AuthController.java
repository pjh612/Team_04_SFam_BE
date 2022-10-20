package com.kdt.team04.domain.auth.controller;

import static org.springframework.http.HttpHeaders.SET_COOKIE;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.springframework.http.ResponseCookie;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kdt.team04.common.ApiResponse;
import com.kdt.team04.common.config.resolver.AuthUser;
import com.kdt.team04.common.security.CookieConfigProperties;
import com.kdt.team04.common.security.jwt.JwtAuthentication;
import com.kdt.team04.common.security.jwt.JwtConfigProperties;
import com.kdt.team04.domain.auth.dto.JwtToken;
import com.kdt.team04.domain.auth.dto.request.SignInRequest;
import com.kdt.team04.domain.auth.dto.request.SignUpRequest;
import com.kdt.team04.domain.auth.dto.response.SignInResponse;
import com.kdt.team04.domain.auth.dto.response.SignUpResponse;
import com.kdt.team04.domain.auth.service.AuthService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "로그인/회원가입 API")
@RestController
@RequestMapping("/api/users")
public class AuthController {

	private final AuthService authService;
	private final CookieConfigProperties cookieConfigProperties;
	private final JwtConfigProperties jwtConfigProperties;

	public AuthController(AuthService authService, CookieConfigProperties cookieConfigProperties, JwtConfigProperties jwtConfigProperties) {
		this.authService = authService;
		this.cookieConfigProperties = cookieConfigProperties;
		this.jwtConfigProperties = jwtConfigProperties;
	}

	@Operation(summary = "로그인", description = "로그인을 통해 토큰을 획득합니다.")
	@PostMapping("/signin")
	public ApiResponse<SignInResponse> signIn(HttpServletRequest request, HttpServletResponse response,
		@RequestBody @Valid SignInRequest signInRequest) {
		SignInResponse signInResponse = this.authService.signIn(
			signInRequest.username(),
			signInRequest.password()
		);

		signInResponse.jwtAuthenticationToken().setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		SecurityContextHolder.getContext().setAuthentication(signInResponse.jwtAuthenticationToken());

		JwtToken accessToken = signInResponse.accessToken();
		JwtToken refreshToken = signInResponse.refreshToken();
		ResponseCookie accessTokenCookie = createCookie(accessToken.header(), accessToken.token(),
			refreshToken.expirySeconds());
		ResponseCookie refreshTokenCookie = createCookie(refreshToken.header(), refreshToken.token(),
			refreshToken.expirySeconds());
		response.setHeader(SET_COOKIE, accessTokenCookie.toString());
		response.addHeader(SET_COOKIE, refreshTokenCookie.toString());

		return new ApiResponse<>(signInResponse);
	}

	private ResponseCookie createCookie(String header, String token, int expirySecond) {
		return ResponseCookie.from(header, token)
			.path("/")
			.httpOnly(true)
			.secure(cookieConfigProperties.secure())
			.domain(cookieConfigProperties.domain())
			.maxAge(expirySecond)
			.sameSite(cookieConfigProperties.sameSite().attributeValue())
			.build();
	}

	@Operation(summary = "회원가입")
	@PostMapping("/signup")
	public ApiResponse<SignUpResponse> signUp(@RequestBody @Valid SignUpRequest request) {
		return new ApiResponse<>(authService.signUp(request));
	}

	@Operation(summary = "로그아웃")
	@DeleteMapping("/signout")
	public ApiResponse<String> signOut(@AuthUser JwtAuthentication auth, HttpServletResponse response) {
		authService.signOut(auth.id());
		ResponseCookie accessTokenCookie = ResponseCookie.from(jwtConfigProperties.accessToken().header(), "")
			.path("/")
			.maxAge(0)
			.httpOnly(true)
			.secure(cookieConfigProperties.secure())
			.domain(cookieConfigProperties.domain())
			.build();
		ResponseCookie refreshTokenCookie = ResponseCookie.from(jwtConfigProperties.refreshToken().header(), "")
			.path("/")
			.maxAge(0)
			.httpOnly(true)
			.secure(cookieConfigProperties.secure())
			.domain(cookieConfigProperties.domain())
			.build();
		response.setHeader(SET_COOKIE, accessTokenCookie.toString());
		response.addHeader(SET_COOKIE, refreshTokenCookie.toString());

		return new ApiResponse<>("signed out");
	}
}
