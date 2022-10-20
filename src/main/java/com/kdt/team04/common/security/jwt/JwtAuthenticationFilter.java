package com.kdt.team04.common.security.jwt;

import static org.springframework.http.HttpHeaders.SET_COOKIE;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.kdt.team04.common.exception.EntityNotFoundException;
import com.kdt.team04.common.security.CookieConfigProperties;
import com.kdt.team04.common.security.jwt.exception.JwtAccessTokenNotFoundException;
import com.kdt.team04.common.security.jwt.exception.JwtRefreshTokenNotFoundException;
import com.kdt.team04.common.security.jwt.exception.JwtTokenNotFoundException;
import com.kdt.team04.domain.auth.dto.JwtToken;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
	private final Jwt jwt;
	private final JwtConfigProperties jwtConfigProperties;
	private final CookieConfigProperties cookieConfigProperties;
	private final Logger log = LoggerFactory.getLogger(getClass());

	public JwtAuthenticationFilter(Jwt jwt, JwtConfigProperties jwtConfigProperties,
		CookieConfigProperties cookieConfigProperties) {
		this.jwt = jwt;
		this.jwtConfigProperties = jwtConfigProperties;
		this.cookieConfigProperties = cookieConfigProperties;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		logRequest(request);

		try {
			authenticate(getAccessTokenCookie(request).getValue(), request, response);
		} catch (JwtTokenNotFoundException e) {
			log.warn(e.getMessage());
		}
		filterChain.doFilter(request, response);
	}

	private void logRequest(HttpServletRequest request) {
		log.info(String.format(
			"[%s] %s %s",
			request.getMethod(),
			request.getRequestURI().toLowerCase(),
			request.getQueryString() == null ? "" : request.getQueryString())
		);
	}

	private void authenticate(String accessToken, HttpServletRequest request, HttpServletResponse response) {
		try {
			Jwt.Claims claims = jwt.verify(accessToken);
			JwtAuthenticationToken authentication = createAuthenticationToken(claims, request, accessToken);
			SecurityContextHolder.getContext().setAuthentication(authentication);
		} catch (TokenExpiredException exception) {
			log.warn(exception.getMessage());
			refreshAuthentication(accessToken, request, response);
		} catch (JWTVerificationException exception) {
			log.warn(exception.getMessage());
		}
	}

	private JwtAuthenticationToken createAuthenticationToken(Jwt.Claims claims, HttpServletRequest request,
		String accessToken) {
		List<GrantedAuthority> authorities = jwt.getAuthorities(claims);
		JwtAuthentication authentication = new JwtAuthentication(accessToken, claims.getUserId(), claims.getUsername(),
			claims.getEmail());
		JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(authentication, null, authorities);
		authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

		return authenticationToken;
	}

	private void refreshAuthentication(String accessToken, HttpServletRequest request, HttpServletResponse response) {
		try {
			Cookie refreshTokenCookie = getRefreshTokenCookie(request);
			jwt.verifyRefreshToken(accessToken, refreshTokenCookie.getValue());
			JwtToken reissuedAccessToken = jwt.reIssueAccessToken(accessToken);
			Jwt.Claims reIssuedClaims = jwt.decode(reissuedAccessToken.token());
			JwtAuthenticationToken authentication = createAuthenticationToken(reIssuedClaims, request,
				reissuedAccessToken.token());
			SecurityContextHolder.getContext().setAuthentication(authentication);
			ResponseCookie cookie = ResponseCookie.from(reissuedAccessToken.header(), reissuedAccessToken.token())
				.path("/")
				.httpOnly(true)
				.sameSite(cookieConfigProperties.sameSite().attributeValue())
				.domain(cookieConfigProperties.domain())
				.secure(cookieConfigProperties.secure())
				.maxAge(refreshTokenCookie.getMaxAge())
				.build();
			response.addHeader(SET_COOKIE, cookie.toString());

		} catch (EntityNotFoundException | JwtTokenNotFoundException | JWTVerificationException e) {
			log.warn(e.getMessage());
		}
	}

	public Cookie getAccessTokenCookie(HttpServletRequest request) {
		if (request.getCookies() == null) {
			throw new JwtAccessTokenNotFoundException("AccessToken is not found.");
		}
		return Arrays.stream(request.getCookies())
			.filter(cookie -> cookie.getName().equals(jwtConfigProperties.accessToken().header()))
			.findFirst()
			.orElseThrow(() -> new JwtAccessTokenNotFoundException("AccessToken is not found"));
	}

	public Cookie getRefreshTokenCookie(HttpServletRequest request) {
		if (request.getCookies() != null) {
			return Arrays.stream(request.getCookies())
				.filter(cookie -> cookie.getName().equals(jwtConfigProperties.refreshToken().header()))
				.findFirst()
				.orElseThrow(() -> new JwtRefreshTokenNotFoundException("RefreshToken is not found."));
		} else {
			throw new JwtRefreshTokenNotFoundException();
		}
	}
}