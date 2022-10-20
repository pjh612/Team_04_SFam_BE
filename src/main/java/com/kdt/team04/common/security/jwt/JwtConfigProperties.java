package com.kdt.team04.common.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

@ConstructorBinding
@ConfigurationProperties(prefix = "jwt")
public record JwtConfigProperties(
	TokenProperties accessToken,
	TokenProperties refreshToken,
	String issuer,
	String clientSecret
) {
	public record TokenProperties(String header, int expirySeconds) {
	}
}
