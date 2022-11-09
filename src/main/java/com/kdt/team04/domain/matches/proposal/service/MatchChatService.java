package com.kdt.team04.domain.matches.proposal.service;

import static java.util.stream.Collectors.toMap;

import java.text.MessageFormat;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.annotation.PostConstruct;

import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kdt.team04.common.exception.BusinessException;
import com.kdt.team04.common.exception.ErrorCode;
import com.kdt.team04.domain.matches.proposal.dto.ChatMessage;
import com.kdt.team04.domain.matches.proposal.dto.MatchChatConverter;
import com.kdt.team04.domain.matches.proposal.dto.QueryMatchChatPartitionByProposalIdResponse;
import com.kdt.team04.domain.matches.proposal.dto.QueryMatchProposalSimpleResponse;
import com.kdt.team04.domain.matches.proposal.dto.response.ChatItemResponse;
import com.kdt.team04.domain.matches.proposal.dto.response.MatchChatResponse;
import com.kdt.team04.domain.matches.proposal.dto.response.MatchChatViewMatchResponse;
import com.kdt.team04.domain.matches.proposal.dto.response.ProposalIdResponse;
import com.kdt.team04.domain.matches.proposal.entity.MatchChat;
import com.kdt.team04.domain.matches.proposal.entity.MatchProposal;
import com.kdt.team04.domain.matches.proposal.entity.MatchProposalStatus;
import com.kdt.team04.domain.matches.proposal.repository.MatchChatRepository;
import com.kdt.team04.domain.user.dto.response.ChatWriterProfileResponse;

import lombok.RequiredArgsConstructor;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MatchChatService {

	private final MatchChatRepository matchChatRepository;
	private final MatchProposalGiverService matchProposalGiver;
	private final MatchChatConverter matchChatConverter;
	private final RedisTemplate<String, Object> redisTemplate;
	private final ChannelTopic channelTopic;
	private HashOperations<String, String, Long> opsHashChatRoom;

	@PostConstruct
	private void init() {
		opsHashChatRoom = redisTemplate.opsForHash();
	}

	@Transactional
	public void chat(Long proposalId, Long writerId, Long targetId, String content,
		LocalDateTime chattedAt) {
		QueryMatchProposalSimpleResponse matchProposalDto = matchProposalGiver.findSimpleProposalById(proposalId);

		if (matchProposalDto.getStatus() != MatchProposalStatus.APPROVED
			&& matchProposalDto.getStatus() != MatchProposalStatus.FIXED) {
			throw new BusinessException(
				ErrorCode.PROPOSAL_NOT_APPROVED,
				MessageFormat.format("proposalId = {0}", proposalId));
		}

		checkCorrectChatPartner(matchProposalDto.getMatchProposerId(), matchProposalDto.getMatchAuthorId(), writerId,
			targetId);

		MatchChat matchChat = matchChatConverter.toMatchChat(matchProposalDto.getId(), writerId, targetId, content,
			chattedAt);
		matchChatRepository.save(matchChat);

		ChatMessage request = new ChatMessage(proposalId, writerId, content);
		redisTemplate.convertAndSend(channelTopic.getTopic(), request);
	}

	private void checkCorrectChatPartner(Long proposerId, Long matchAuthorId, Long writerId, Long targetId) {
		if (
			(Objects.equals(proposerId, writerId) && Objects.equals(matchAuthorId, targetId))
				|| (Objects.equals(matchAuthorId, writerId) && Objects.equals(proposerId, targetId))
		) {
			return;
		}

		throw new BusinessException(ErrorCode.MATCH_CHAT_NOT_CORRECT_CHAT_PARTNER,
			MessageFormat.format(
				"proposerId= {0}, proposal match authorId = {1}, chat writerId = {2}, chat targetId = {3}",
				proposerId,
				matchAuthorId,
				writerId,
				targetId
			)
		);
	}

	public Map<Long, QueryMatchChatPartitionByProposalIdResponse> findAllLastChats(List<Long> matchProposalIds) {
		List<QueryMatchChatPartitionByProposalIdResponse> chatQueryDtos
			= matchChatRepository.findAllPartitionByProposalIdOrderByChattedAtDesc(matchProposalIds);

		Map<Long, QueryMatchChatPartitionByProposalIdResponse> lastChats = chatQueryDtos.stream()
			.filter(chat -> chat.getRowNumber() == 1L)
			.collect(toMap(
				QueryMatchChatPartitionByProposalIdResponse::getMatchProposalId,
				chat -> chat
			));

		return lastChats;
	}

	//특정 매치의 나의 채팅 기록
	public MatchChatResponse findChatsByProposalId(Long proposalId, Long userId) {
		MatchChatViewMatchResponse match = matchProposalGiver.findChatMatchByProposalId(proposalId, userId);

		List<MatchChat> matchChats = matchChatRepository.findAllByProposalId(proposalId);
		List<ChatItemResponse> chats = matchChats.stream()
			.map(chat -> new ChatItemResponse(
					chat.getContent(),
					chat.getChattedAt(),
					new ChatWriterProfileResponse(chat.getUser().getId())
				)
			)
			.toList();

		return new MatchChatResponse(match, chats);
	}

	@Transactional
	public void deleteAllByProposals(List<ProposalIdResponse> proposalResponses) {
		List<MatchProposal> proposals = proposalResponses.stream()
			.map((proposal -> MatchProposal.builder()
				.id(proposal.id())
				.build()))
			.toList();

		matchChatRepository.deleteAllByProposalIn(proposals);
	}

	public String createChatRoom(String name) {
		opsHashChatRoom.put("CHAT_ROOMS", name, Long.parseLong(name));

		return name;
	}

}
