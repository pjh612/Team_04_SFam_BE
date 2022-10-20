package com.kdt.team04.common.security.jwt;

import static com.google.common.base.Preconditions.checkArgument;
import static org.apache.logging.log4j.util.Strings.isNotBlank;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.kdt.team04.domain.auth.dto.JwtToken;
import com.kdt.team04.domain.auth.service.TokenService;

@Component
public class Jwt {
	private final JwtConfigProperties jwtConfigProperties;
	private final TokenService tokenService;
	private final Algorithm algorithm;
	private final JWTVerifier jwtVerifier;

	public Jwt(JwtConfigProperties jwtConfigProperties, TokenService tokenService) {
		this.jwtConfigProperties = jwtConfigProperties;
		this.algorithm = Algorithm.HMAC512(jwtConfigProperties.clientSecret());
		this.tokenService = tokenService;
		this.jwtVerifier = JWT.require(algorithm)
			.withIssuer(this.jwtConfigProperties.issuer())
			.build();
	}

	public JwtToken reIssueAccessToken(String accessToken) {
		JwtToken jwtToken = generateAccessToken(decode(accessToken));
		jwtVerifier.verify(jwtToken.token());

		return jwtToken;
	}

	public JwtToken generateAccessToken(Claims claims) {
		Date now = new Date();
		JWTCreator.Builder builder = JWT.create();

		builder.withSubject(claims.userId.toString());
		builder.withIssuer(jwtConfigProperties.issuer());
		builder.withIssuedAt(now);

		if (jwtConfigProperties.accessToken().expirySeconds() > 0) {
			builder.withExpiresAt(new Date(now.getTime() + jwtConfigProperties.accessToken().expirySeconds() * 1000L));
		}
		builder.withClaim("userId", claims.userId);
		builder.withClaim("username", claims.username);
		builder.withClaim("email", claims.email);
		builder.withArrayClaim("roles", claims.roles);

		return new JwtToken(
			jwtConfigProperties.accessToken().header(),
			builder.sign(algorithm),
			jwtConfigProperties.accessToken().expirySeconds());
	}

	public JwtToken generateRefreshToken(Long userId) {
		Date now = new Date();
		JWTCreator.Builder builder = JWT.create();
		builder.withIssuer(jwtConfigProperties.issuer());
		builder.withIssuedAt(now);
		if (jwtConfigProperties.refreshToken().expirySeconds() > 0) {
			builder.withExpiresAt(new Date(now.getTime() + jwtConfigProperties.refreshToken().expirySeconds() * 1000L));
		}

		String refreshToken = builder.sign(algorithm);

		tokenService.save(userId, refreshToken, (long)jwtConfigProperties.refreshToken().expirySeconds());

		return new JwtToken(
			jwtConfigProperties.refreshToken().header(),
			refreshToken,
			jwtConfigProperties.refreshToken().expirySeconds());
	}

	public void verifyRefreshToken(String accessToken, String refreshToken) {
		verify(refreshToken);
		Long userId = decode(accessToken).getUserId();
		TokenResponse token = tokenService.findByUserId(userId);
		if (!refreshToken.equals(token.token())) {
			throw new JWTVerificationException("Invalid refresh token.");
		}
	}

	public void invalidateRefreshToken(Long userId) {
		tokenService.delete(userId);
	}

	public Claims decode(String token) {
		return new Claims(JWT.decode(token));

	}

	public Claims verify(String token) {
		return new Claims(jwtVerifier.verify(token));

	}

	public List<GrantedAuthority> getAuthorities(Claims claims) {
		String[] roles = claims.roles;

		return roles == null || roles.length == 0
			? Collections.emptyList()
			: Arrays.stream(roles)
			.map(SimpleGrantedAuthority::new)
			.collect(Collectors.toList());
	}

	public static class Claims {
		private Long userId;
		private String username;
		private String email;
		private String[] roles;

		private Claims() {
		}

		Claims(DecodedJWT decodedJWT) {
			Claim userId = decodedJWT.getClaim("userId");
			if (!userId.isNull()) {
				this.userId = userId.asLong();
			}
			Claim username = decodedJWT.getClaim("username");
			if (!username.isNull()) {
				this.username = username.asString();
			}

			Claim email = decodedJWT.getClaim("email");
			if (!email.isNull()) {
				this.email = email.asString();
			}

			Claim roles = decodedJWT.getClaim("roles");
			if (!roles.isNull()) {
				this.roles = roles.asArray(String.class);
			}
		}

		private Claims(Long userId, String username, String email, String[] roles) {
			this.userId = userId;
			this.username = username;
			this.email = email;
			this.roles = roles;
		}

		public static ClaimsBuilder builder(Long userId, String username, String[] roles) {
			return new ClaimsBuilder(userId, username, roles);
		}

		public Long getUserId() {
			return userId;
		}

		public String getUsername() {
			return username;
		}

		public String getEmail() {
			return email;
		}

		public String[] getRoles() {
			return roles;
		}


		public static class ClaimsBuilder {
			private final Long userId;
			private final String username;
			private String email;
			private final String[] roles;


			public ClaimsBuilder(Long userId, String username, String[] roles) {
				checkArgument(userId != null, "userId must be provided");
				checkArgument(isNotBlank(username), "username must be provided");
				checkArgument(roles != null, "username must be provided");
				this.userId = userId;
				this.username = username;
				this.roles= roles;
			}

			public ClaimsBuilder email(String email) {
				this.email = email;

				return this;
			}

			public Claims build() {
				return new Claims(this.userId, this.username, this.email, this.roles);
			}
		}
	}
}
