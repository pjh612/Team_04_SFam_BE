package com.kdt.team04.domain.matches.match.dto.response;

import java.time.LocalDate;
import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.kdt.team04.domain.matches.match.model.MatchType;
import com.kdt.team04.domain.teams.team.model.SportsCategory;

import io.swagger.v3.oas.annotations.media.Schema;

public record QueryMatchListResponse(
	@Schema(description = "매칭 ID(고유 PK)")
	Long id,

	@Schema(description = "매칭 글 제목")
	String title,

	@Schema(description = "스포츠 종목(값/설명) - BADMINTON/배드민턴, SOCCER/축구, BASEBALL/야구")
	SportsCategory category,

	@Schema(description = "매칭 타입(값/설명) - TEAM_MATCH/팀전 | INDIVIDUAL_MATCH/개인전")
	MatchType matchType,

	@Schema(description = "매칭 글 내용")
	String content,

	@Schema(description = "작성자 ID(고유 PK)")
	Long authorId,

	@Schema(description = "작성자 닉네임")
	String authorNickname,

	@Schema(description = "작성자 위도")
	Double latitude,

	@Schema(description = "작성자 경도")
	Double longitude,

	@Schema(description = "작성자 위치")
	String localName,

	@Schema(description = "나와의 거리")
	Double distance,

	@Schema(description = "원하는 경기 일자")
	LocalDate matchDate,

	@Schema(description = "작성 일자")
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
	LocalDateTime createdAt
) {

}