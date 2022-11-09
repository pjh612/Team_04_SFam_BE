package com.kdt.team04.domain.matches.proposal.controller;

import javax.validation.Valid;

import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kdt.team04.common.ApiResponse;
import com.kdt.team04.common.config.resolver.AuthUser;
import com.kdt.team04.common.security.jwt.Jwt;
import com.kdt.team04.common.security.jwt.JwtAuthentication;
import com.kdt.team04.domain.matches.proposal.dto.request.MatchChatRequest;
import com.kdt.team04.domain.matches.proposal.dto.response.MatchChatResponse;
import com.kdt.team04.domain.matches.proposal.service.MatchChatService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;

@Tag(name = "매칭 채팅 API")
@RestController
@Slf4j
@RequestMapping("/api/matches/proposals")
public class MatchChatController {

	private final MatchChatService matchChatService;
	private final Jwt jwt;

	public MatchChatController(MatchChatService matchChatService, Jwt jwt) {
		this.matchChatService = matchChatService;
		this.jwt = jwt;
	}

	@Operation(summary = "채팅 등록", description = "작성자와 승인된 신청자가 채팅을 등록한다.")
	@MessageMapping("/{id}/chats")
	public void chat(
		@Header("Authorization") String accessToken,
		@Parameter(description = "매칭 신청 ID") @DestinationVariable long id,
		@Valid @RequestBody MatchChatRequest request
	) {
		Jwt.Claims verify = jwt.verify(accessToken);

		matchChatService.chat(
			id,
			verify.getUserId(),
			request.targetId(),
			request.content(),
			request.chattedAt()
		);
	}

	@Operation(summary = "채팅 조회", description = "채팅 기록을 조회할 수 있다.")
	@GetMapping("/{id}/chats")
	public ApiResponse<MatchChatResponse> chat(
		@AuthUser JwtAuthentication auth,
		@Parameter(description = "매칭 신청 ID") @PathVariable Long id
	) {
		MatchChatResponse chats = matchChatService.findChatsByProposalId(id, auth.id());

		return new ApiResponse<>(chats);
	}
}
