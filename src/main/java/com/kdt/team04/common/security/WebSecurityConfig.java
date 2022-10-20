package com.kdt.team04.common.security;

import java.util.Arrays;
import java.util.Optional;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.kdt.team04.common.config.CorsConfigProperties;
import com.kdt.team04.common.security.jwt.Jwt;
import com.kdt.team04.common.security.jwt.JwtAuthenticationFilter;
import com.kdt.team04.common.security.jwt.JwtConfigProperties;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties({
	JwtConfigProperties.class,
	SecurityConfigProperties.class,
	CookieConfigProperties.class,
	CorsConfigProperties.class}
)
public class WebSecurityConfig {

	private final Jwt jwt;
	private final SecurityConfigProperties securityConfigProperties;
	private final Optional<OAuth2LoginConfigurer<HttpSecurity>> oAuth2LoginConfigurer;
	private final CookieConfigProperties cookieConfigProperties;
	private final JwtConfigProperties jwtConfigProperties;
	private final CorsConfigProperties corsConfigProperties;

	public WebSecurityConfig(Jwt jwt, SecurityConfigProperties securityConfigProperties,
		Optional<OAuth2LoginConfigurer<HttpSecurity>> oAuth2LoginConfigurer,
		CookieConfigProperties cookieConfigProperties,
		JwtConfigProperties jwtConfigProperties, CorsConfigProperties corsConfigProperties) {
		this.jwt = jwt;
		this.securityConfigProperties = securityConfigProperties;
		this.oAuth2LoginConfigurer = oAuth2LoginConfigurer;
		this.cookieConfigProperties = cookieConfigProperties;
		this.jwtConfigProperties = jwtConfigProperties;
		this.corsConfigProperties = corsConfigProperties;
	}

	public JwtAuthenticationFilter jwtAuthenticationFilter(Jwt jwt) {
		return new JwtAuthenticationFilter(jwt, jwtConfigProperties, cookieConfigProperties);
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return web -> web.ignoring()
			.antMatchers(HttpMethod.GET, this.securityConfigProperties.patterns().ignoring().get("GET"))
			.antMatchers(HttpMethod.POST, this.securityConfigProperties.patterns().ignoring().get("POST"))
			.antMatchers(HttpMethod.PATCH, this.securityConfigProperties.patterns().ignoring().get("PATCH"))
			.antMatchers(HttpMethod.DELETE, this.securityConfigProperties.patterns().ignoring().get("DELETE"))
			.antMatchers(HttpMethod.PUT, this.securityConfigProperties.patterns().ignoring().get("PUT"))
			.requestMatchers(PathRequest.toStaticResources().atCommonLocations());
	}

	AuthenticationEntryPoint authenticationEntryPoint() {
		return new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		final CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList(corsConfigProperties.origin()));
		configuration.addAllowedHeader("*");
		configuration.addAllowedMethod(String.join(", ", Arrays.asList(corsConfigProperties.method())));
		configuration.setAllowCredentials(true);
		configuration.setMaxAge(3600L);

		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration(corsConfigProperties.api(), configuration);
		return source;
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
			.antMatchers(HttpMethod.GET, this.securityConfigProperties.patterns().permitAll().get("GET"))
			.permitAll()
			.antMatchers(HttpMethod.POST, this.securityConfigProperties.patterns().permitAll().get("POST"))
			.permitAll()
			.antMatchers(HttpMethod.PATCH, this.securityConfigProperties.patterns().permitAll().get("PATCH"))
			.permitAll()
			.antMatchers(HttpMethod.DELETE, this.securityConfigProperties.patterns().permitAll().get("DELETE"))
			.permitAll()
			.antMatchers(HttpMethod.PUT, this.securityConfigProperties.patterns().permitAll().get("PUT"))
			.permitAll()
			.antMatchers(HttpMethod.OPTIONS, this.securityConfigProperties.patterns().permitAll().get("OPTIONS"))
			.permitAll()
			.anyRequest()
			.authenticated()
			.and()
			.formLogin().disable()
			.csrf().disable()
			.headers().disable()
			.httpBasic().disable()
			.rememberMe().disable()
			.logout().disable()
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.exceptionHandling()
			.authenticationEntryPoint(authenticationEntryPoint())
			.and()
			.addFilterBefore(jwtAuthenticationFilter(jwt), UsernamePasswordAuthenticationFilter.class)
			.cors()
		;

		if (oAuth2LoginConfigurer.isPresent()) {
			http.apply(oAuth2LoginConfigurer.get());
		}
		return http.build();
	}
}
