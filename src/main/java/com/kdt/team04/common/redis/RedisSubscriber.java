package com.kdt.team04.common.redis;

import org.springframework.messaging.simp.SimpMessageSendingOperations;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kdt.team04.domain.matches.proposal.dto.ChatMessage;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class RedisSubscriber{
	private final ObjectMapper objectMapper;
	private final SimpMessageSendingOperations messagingTemplate;

	public void sendMessage(String publishMessage) {
		try {
			ChatMessage request = objectMapper.readValue(publishMessage, ChatMessage.class);

			messagingTemplate.convertAndSend("/api/sub/chat/room/" + request.roomId(), request);

		} catch (Exception e) {
			log.info(e.getMessage(),e);
			throw new RuntimeException();
		}
	}
}
