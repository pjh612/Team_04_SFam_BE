package com.kdt.team04.domain.user.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;

public record UserResponse(Long id, String username, String password, String nickname) {

	@Builder
	public record FindProfile(
		@Schema(description = "회원 고유 PK")
		Long id,

		@Schema(description = "회원 id")
		String username,

		@Schema(description = "회원 닉네임")
		String nickname
	) {}
}
