package com.kdt.team04.common.security.oauth;

import static org.springframework.http.HttpHeaders.SET_COOKIE;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.kdt.team04.common.security.CookieConfigProperties;
import com.kdt.team04.common.security.jwt.Jwt;
import com.kdt.team04.domain.auth.dto.JwtToken;
import com.kdt.team04.domain.user.Role;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
	private final Jwt jwt;
	private final CookieConfigProperties cookieConfigProperties;

	public OAuth2SuccessHandler(Jwt jwt, CookieConfigProperties cookieConfigProperties) {
		this.jwt = jwt;
		this.cookieConfigProperties = cookieConfigProperties;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) {
		CustomOAuth2User oAuth2User = (CustomOAuth2User)authentication.getPrincipal();
		Jwt.Claims claims = Jwt.Claims.builder(
				oAuth2User.userId(),
				oAuth2User.username(),
				new String[] {String.valueOf(Role.USER)})
			.email(oAuth2User.email())
			.build();

		JwtToken accessToken = jwt.generateAccessToken(claims);
		JwtToken refreshToken = jwt.generateRefreshToken(oAuth2User.userId());

		ResponseCookie accessTokenCookie = createCookie(accessToken.header(), accessToken.token(),
			refreshToken.expirySeconds());
		ResponseCookie refreshTokenCookie = createCookie(refreshToken.header(), refreshToken.token(),
			refreshToken.expirySeconds());

		response.setHeader(SET_COOKIE, accessTokenCookie.toString());
		response.addHeader(SET_COOKIE, refreshTokenCookie.toString());
	}

	private ResponseCookie createCookie(String header, String token, int expirySeconds) {
		return ResponseCookie.from(header, token)
			.path("/")
			.httpOnly(true)
			.secure(cookieConfigProperties.secure())
			.domain(cookieConfigProperties.domain())
			.maxAge(expirySeconds)
			.sameSite(cookieConfigProperties.sameSite().attributeValue())
			.build();
	}
}
