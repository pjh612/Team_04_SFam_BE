package com.kdt.team04.common.config;

import static java.lang.String.format;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import com.kdt.team04.feign.division.config.DivisionApiProperties;
import com.kdt.team04.feign.kakao.config.KakaoApiProperties;

import feign.FeignException;
import feign.RetryableException;
import feign.Retryer;
import feign.codec.ErrorDecoder;

@EnableConfigurationProperties({DivisionApiProperties.class, KakaoApiProperties.class})
public class FeignConfig {
	@Bean
	public Retryer retryer() {
		return new Retryer.Default(2000, 5000, 3);
	}

	@Bean
	public ErrorDecoder decoder() {

		return (methodKey, response) -> {
			FeignException exception = feign.FeignException.errorStatus(methodKey, response);
			if (response.status() >= 500) {
				return new RetryableException(
					response.status(),
					format("%s 요청이 성공하지 못했습니다. Retry 합니다. - status: %s, headers: %s",
						methodKey,
						response.status(),
						response.headers()
					),
					response.request().httpMethod(),
					null,
					response.request());

			}
			return exception;
		};
	}
}
