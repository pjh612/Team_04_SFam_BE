/*
package com.kdt.team04.domain.matches.proposal.controller;

import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willDoNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.LongStream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kdt.team04.common.ApiResponse;
import com.kdt.team04.common.exception.BusinessException;
import com.kdt.team04.common.exception.ErrorCode;
import com.kdt.team04.common.exception.ErrorResponse;
import com.kdt.team04.common.security.WebSecurityConfig;
import com.kdt.team04.common.security.jwt.Jwt;
import com.kdt.team04.domain.auth.service.TokenService;
import com.kdt.team04.domain.matches.match.model.MatchStatus;
import com.kdt.team04.domain.matches.proposal.dto.request.MatchChatRequest;
import com.kdt.team04.domain.matches.proposal.dto.response.ChatItemResponse;
import com.kdt.team04.domain.matches.proposal.dto.response.MatchChatResponse;
import com.kdt.team04.domain.matches.proposal.dto.response.MatchChatViewMatchResponse;
import com.kdt.team04.domain.matches.proposal.service.MatchChatService;
import com.kdt.team04.domain.security.WithMockJwtAuthentication;
import com.kdt.team04.domain.user.dto.response.ChatTargetProfileResponse;
import com.kdt.team04.domain.user.dto.response.ChatWriterProfileResponse;

@WithMockJwtAuthentication
@WebMvcTest({MatchChatController.class, WebSecurityConfig.class})
class MatchChatControllerTest {

	private final static String BASE_END_POINT = "/api/matches/proposals";
	private final static Long DEFAULT_AUTH_ID = 1L;
	private final static BigInteger TARGET_USER_ID = BigInteger.valueOf(2);
	private final static Long DEFAULT_TARGET_USER_ID = 2L;
	private final static Long INVALID_USER_ID = 3L;
	private final static String DEFAULT_MESSAGE = "잘 부탁드립니다.";
	private final static String INVALID_MESSAGE = "  ";
	private final static Long DEFAULT_MATCH_PROPOSAL_ID = 4L;
	private final static Long INVALID_MATCH_PROPOSAL_ID = 4L;
	private final static Long NOT_APPROVE_PROPOSAL_ID = 5L;

	@Autowired
	MockMvc mockMvc;

	@Autowired
	ObjectMapper objectMapper;

	@MockBean
	MatchChatService matchChatService;

	@MockBean
	TokenService tokenService;

	@MockBean
	Jwt jwt;

	@Test
	@DisplayName("매치 신청이 수락된 사용자는 메시지를 보낼 수 있으며 전송 후 200 상태코드를 반환한다.")
	void sendMessageSuccess() throws Exception {
		// given
		LocalDateTime localDateTime = LocalDateTime.parse("2022-08-17 11:11:11",
			DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
		MatchChatRequest matchChatRequest =
			new MatchChatRequest(DEFAULT_TARGET_USER_ID, DEFAULT_MESSAGE, localDateTime);
		String request = objectMapper.writeValueAsString(matchChatRequest);

		willDoNothing().given(matchChatService)
			.chat(DEFAULT_MATCH_PROPOSAL_ID, DEFAULT_AUTH_ID,
				matchChatRequest.targetId(), matchChatRequest.content(), matchChatRequest.chattedAt());

		// when
		ResultActions resultActions = mockMvc
			.perform(
				post(BASE_END_POINT + "/{proposalId}/chats", DEFAULT_MATCH_PROPOSAL_ID)
					.contentType(MediaType.APPLICATION_JSON)
					.content(request)
			)
			.andDo(print());

		// then
		verify(matchChatService, times(1))
			.chat(DEFAULT_MATCH_PROPOSAL_ID, DEFAULT_AUTH_ID,
				matchChatRequest.targetId(), matchChatRequest.content(), matchChatRequest.chattedAt());

		resultActions
			.andExpect(status().isOk());
	}

	@Test
	@DisplayName("쪽지를 보낼 데이터가 없다면 400 상태코드를 반환한다.")
	void chatsNotArguments() throws Exception {
		// given
		ErrorCode errorCode = ErrorCode.UNACCEPTABLE_JSON_ERROR;
		String response = objectMapper.writeValueAsString(new ErrorResponse<>(errorCode));

		// when
		ResultActions resultActions = mockMvc
			.perform(
				post(BASE_END_POINT + "/{proposalId}/chats", DEFAULT_MATCH_PROPOSAL_ID)
			)
			.andDo(print());

		// then
		verify(matchChatService, never())
			.chat(null, null, null, null, null);

		resultActions
			.andExpect(status().isBadRequest())
			.andExpect(content().string(response));
	}

	@Test
	@DisplayName("쪽지를 보낼 데이터의 유효성이 맞지 않다면 400 상태코드를 반환한다.")
	void chatsInvalidArgument() throws Exception {
		// given
		LocalDateTime localDateTime = LocalDateTime.parse("2022-08-17 11:11:11",
			DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
		MatchChatRequest matchChatRequest =
			new MatchChatRequest(DEFAULT_TARGET_USER_ID, INVALID_MESSAGE, localDateTime);
		String request = objectMapper.writeValueAsString(matchChatRequest);

		ErrorCode errorCode = ErrorCode.METHOD_ARGUMENT_NOT_VALID;
		String response = objectMapper.writeValueAsString(new ErrorResponse<>(errorCode));

		// when
		ResultActions resultActions = mockMvc
			.perform(
				post(BASE_END_POINT + "/{proposalId}/chats", DEFAULT_MATCH_PROPOSAL_ID)
					.contentType(MediaType.APPLICATION_JSON)
					.content(request)
			)
			.andDo(print());

		// then
		verify(matchChatService, never())
			.chat(null, null, null, null, null);

		resultActions
			.andExpect(status().isBadRequest())
			.andExpect(content().string(response));
	}

	@Test
	@DisplayName("매치 신청이 수락이 안된 사용자는 쪽지를 보낼 수 없으며 400 상태코드를 반환한다.")
	void proposalNotApproved() throws Exception {
		// given
		LocalDateTime localDateTime = LocalDateTime.parse("2022-08-17 11:11:11",
			DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
		MatchChatRequest matchChatRequest =
			new MatchChatRequest(DEFAULT_TARGET_USER_ID, DEFAULT_MESSAGE, localDateTime);
		String request = objectMapper.writeValueAsString(matchChatRequest);

		ErrorCode errorCode = ErrorCode.PROPOSAL_NOT_APPROVED;
		String response = objectMapper.writeValueAsString(new ErrorResponse<>(errorCode));
		doThrow(new BusinessException(errorCode))
			.when(matchChatService)
			.chat(NOT_APPROVE_PROPOSAL_ID, DEFAULT_AUTH_ID,
				matchChatRequest.targetId(), matchChatRequest.content(), matchChatRequest.chattedAt());

		// when
		ResultActions resultActions = mockMvc
			.perform(
				post(BASE_END_POINT + "/{proposalId}/chats", NOT_APPROVE_PROPOSAL_ID)
					.contentType(MediaType.APPLICATION_JSON)
					.content(request)
			)
			.andDo(print());

		// then
		verify(matchChatService, times(1))
			.chat(NOT_APPROVE_PROPOSAL_ID, DEFAULT_AUTH_ID,
				matchChatRequest.targetId(), matchChatRequest.content(), matchChatRequest.chattedAt());

		resultActions
			.andExpect(status().isBadRequest())
			.andExpect(content().string(response));
	}

	@Test
	@DisplayName("수락 후 공고 신청자, 공고 작성자 외에는 쪽지를 주고 받을 수 없으며 보낼 시 400 상태코드를 반환한다.")
	void notProposalUser() throws Exception {
		// given
		LocalDateTime localDateTime = LocalDateTime.parse("2022-08-17 11:11:11",
			DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
		MatchChatRequest matchChatRequest =
			new MatchChatRequest(INVALID_USER_ID, DEFAULT_MESSAGE, localDateTime);
		String request = objectMapper.writeValueAsString(matchChatRequest);

		ErrorCode errorCode = ErrorCode.MATCH_CHAT_NOT_CORRECT_CHAT_PARTNER;
		String response = objectMapper.writeValueAsString(new ErrorResponse<>(errorCode));
		doThrow(new BusinessException(errorCode))
			.when(matchChatService)
			.chat(INVALID_MATCH_PROPOSAL_ID, DEFAULT_AUTH_ID,
				matchChatRequest.targetId(), matchChatRequest.content(), matchChatRequest.chattedAt());

		// when
		ResultActions resultActions = mockMvc
			.perform(
				post(BASE_END_POINT + "/{proposalId}/chats", INVALID_MATCH_PROPOSAL_ID)
					.contentType(MediaType.APPLICATION_JSON)
					.content(request)
			)
			.andDo(print());

		// then
		verify(matchChatService, times(1))
			.chat(INVALID_MATCH_PROPOSAL_ID, DEFAULT_AUTH_ID,
				matchChatRequest.targetId(), matchChatRequest.content(), matchChatRequest.chattedAt());

		resultActions
			.andExpect(status().isBadRequest())
			.andExpect(content().string(response));
	}

	@Test
	@DisplayName("매치 신청자 또는 공고자는 채팅기록을 조회할 수 있으며 200 상태코드를 반환한다.")
	void getChatSuccess() throws Exception {
		// given
		LocalDateTime localDateTime = LocalDateTime.parse("2022-08-17 11:11:11",
			DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

		ChatTargetProfileResponse targetProfileResponse =
			new ChatTargetProfileResponse(TARGET_USER_ID, "nickName", null);
		MatchChatViewMatchResponse matchChatViewMatchResponse =
			new MatchChatViewMatchResponse(DEFAULT_AUTH_ID, "title", MatchStatus.IN_GAME, targetProfileResponse);
		List<ChatItemResponse> chatItemResponses = LongStream.range(1, 6)
			.mapToObj(index ->
				new ChatItemResponse(
					"content" + index,
					localDateTime.plusHours(index),
					new ChatWriterProfileResponse(DEFAULT_AUTH_ID))
			)
			.toList();

		MatchChatResponse matchChatResponse = new MatchChatResponse(matchChatViewMatchResponse, chatItemResponses);
		String response = objectMapper.writeValueAsString(new ApiResponse<>(matchChatResponse));

		given(matchChatService.findChatsByProposalId(DEFAULT_MATCH_PROPOSAL_ID, DEFAULT_AUTH_ID))
			.willReturn(matchChatResponse);

		// when
		ResultActions resultActions = mockMvc.perform(
			get(BASE_END_POINT + "/{proposalId}/chats", DEFAULT_MATCH_PROPOSAL_ID)
				.contentType(MediaType.APPLICATION_JSON)
		).andDo(print());

		// then
		verify(matchChatService, times(1))
			.findChatsByProposalId(DEFAULT_MATCH_PROPOSAL_ID, DEFAULT_AUTH_ID);

		resultActions
			.andExpect(status().isOk())
			.andExpect(content().string(response));
	}

}*/
