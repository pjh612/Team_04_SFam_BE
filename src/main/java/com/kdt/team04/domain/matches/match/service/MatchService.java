package com.kdt.team04.domain.matches.match.service;

import java.text.MessageFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kdt.team04.common.PageDto;
import com.kdt.team04.common.exception.BusinessException;
import com.kdt.team04.common.exception.EntityNotFoundException;
import com.kdt.team04.common.exception.ErrorCode;
import com.kdt.team04.domain.matches.match.dto.MatchConverter;
import com.kdt.team04.domain.matches.match.dto.MatchPagingCursor;
import com.kdt.team04.domain.matches.match.dto.request.CreateMatchRequest;
import com.kdt.team04.domain.matches.match.dto.response.MatchListViewResponse;
import com.kdt.team04.domain.matches.match.dto.response.MatchResponse;
import com.kdt.team04.domain.matches.match.dto.response.QueryMatchListResponse;
import com.kdt.team04.domain.matches.match.model.MatchStatus;
import com.kdt.team04.domain.matches.match.model.entity.Match;
import com.kdt.team04.domain.matches.match.repository.MatchRepository;
import com.kdt.team04.domain.matches.proposal.dto.response.ProposalSimpleResponse;
import com.kdt.team04.domain.matches.proposal.service.MatchProposalService;
import com.kdt.team04.domain.teams.team.dto.TeamConverter;
import com.kdt.team04.domain.teams.team.dto.response.TeamResponse;
import com.kdt.team04.domain.teams.team.dto.response.TeamSimpleResponse;
import com.kdt.team04.domain.teams.team.model.entity.Team;
import com.kdt.team04.domain.teams.team.service.TeamGiverService;
import com.kdt.team04.domain.teams.teammember.service.TeamMemberGiverService;
import com.kdt.team04.domain.user.UserConverter;
import com.kdt.team04.domain.user.dto.response.AuthorResponse;
import com.kdt.team04.domain.user.dto.response.UserResponse;
import com.kdt.team04.domain.user.entity.Location;
import com.kdt.team04.domain.user.entity.User;
import com.kdt.team04.domain.user.service.UserService;
import com.kdt.team04.feign.kakao.service.KakaoApiService;

@Transactional(readOnly = true)
@Service
public class MatchService {

	private final MatchRepository matchRepository;
	private final UserService userService;
	private final MatchProposalService matchProposalService;
	private final TeamGiverService teamGiver;
	private final TeamMemberGiverService teamMemberGiver;
	private final MatchConverter matchConverter;
	private final TeamConverter teamConverter;
	private final UserConverter userConverter;
	private final KakaoApiService kakaoApiService;

	public MatchService(MatchRepository matchRepository, UserService userService,
		MatchProposalService matchProposalService, TeamGiverService teamGiver,
		TeamMemberGiverService teamMemberGiver, MatchConverter matchConverter, TeamConverter teamConverter,
		UserConverter userConverter, KakaoApiService kakaoApiService) {
		this.matchRepository = matchRepository;
		this.userService = userService;
		this.matchProposalService = matchProposalService;
		this.teamGiver = teamGiver;
		this.teamMemberGiver = teamMemberGiver;
		this.matchConverter = matchConverter;
		this.teamConverter = teamConverter;
		this.userConverter = userConverter;
		this.kakaoApiService = kakaoApiService;
	}

	@Transactional
	public Long create(Long userId, CreateMatchRequest request) {
		Match match = request.matchType().isTeam() ?
			teamMatchCreate(userId, request) : individualMatchCreate(userId, request);
		Match savedMatch = matchRepository.save(match);

		return savedMatch.getId();
	}

	private Match individualMatchCreate(Long userId, CreateMatchRequest request) {
		if (request.participants() != 1) {
			throw new BusinessException(ErrorCode.MATCH_INVALID_PARTICIPANTS,
				MessageFormat.format("userId = {0}, participants = {1}", userId, request.participants()));
		}

		UserResponse userResponse = userService.findById(userId);
		User user = userConverter.toUser(userResponse);

		verifyUserLocation(user);

		return Match.builder()
			.title(request.title())
			.matchDate(request.matchDate())
			.matchType(request.matchType())
			.participants(request.participants())
			.user(user)
			.sportsCategory(request.sportsCategory())
			.content(request.content())
			.location(user.getUserSettings().getLocation())
			.build();
	}

	private Match teamMatchCreate(Long userId, CreateMatchRequest request) {
		if (request.teamId() == null) {
			throw new BusinessException(ErrorCode.METHOD_ARGUMENT_NOT_VALID, "teamId is null");
		}

		TeamResponse teamResponse = teamGiver.findById(request.teamId());
		teamGiver.verifyLeader(userId, request.teamId(), teamResponse.leader().id());
		teamMemberGiver.hasEnoughMemberCount(request.participants(), request.teamId());

		User teamLeader = userConverter.toUser(teamResponse.leader());
		Team team = teamConverter.toTeam(teamResponse, teamLeader);

		verifyUserLocation(teamLeader);

		return Match.builder()
			.title(request.title())
			.matchDate(request.matchDate())
			.matchType(request.matchType())
			.participants(request.participants())
			.user(teamLeader)
			.team(team)
			.sportsCategory(request.sportsCategory())
			.content(request.content())
			.location(teamLeader.getUserSettings().getLocation())
			.build();
	}

	public PageDto.CursorResponse<MatchListViewResponse, MatchPagingCursor> findMatches(Long myId,
		PageDto.MatchCursorPageRequest request) {
		UserResponse foundUser = userService.findById(myId);

		verifyUserLocation(userConverter.toUser(foundUser));

		Location location = foundUser.userSettings().getLocation();
		PageDto.CursorResponse<QueryMatchListResponse, MatchPagingCursor> queryMatchListResponse = matchRepository.findByLocationPaging(
			location.getLatitude(), location.getLongitude(), request);

		List<MatchListViewResponse> matchListViewResponses = queryMatchListResponse.values()
			.stream()
			.map(MatchListViewResponse::new)
			.collect(Collectors.toList());
		return new PageDto.CursorResponse<>(
			matchListViewResponses,
			queryMatchListResponse.hasNext(),
			queryMatchListResponse.cursor());
	}

	public MatchResponse findById(Long id, Long userId) {
		Match foundMatch = matchRepository.findById(id)
			.orElseThrow(() -> new EntityNotFoundException(ErrorCode.MATCH_NOT_FOUND,
				MessageFormat.format("matchId = {0}", id)));

		UserResponse author = userService.findById(foundMatch.getUser().getId());
		AuthorResponse authorResponse = new AuthorResponse(author.id(), author.nickname(), author.profileImageUrl());

		Optional<ProposalSimpleResponse> proposalResponse = matchProposalService.findByMatchIdAndUserId(id, userId);

		if (foundMatch.getMatchType().isTeam()) {
			Team team = foundMatch.getTeam();
			TeamSimpleResponse teamResponse = new TeamSimpleResponse(team.getId(), team.getName(),
				team.getSportsCategory(), team.getLogoImageUrl());

			return matchConverter.toMatchResponse(foundMatch, authorResponse, teamResponse, proposalResponse);
		}

		return matchConverter.toMatchResponse(foundMatch, authorResponse, proposalResponse);
	}

	@Transactional
	public void delete(Long userId, Long id) {
		Match match = matchRepository.findById(id)
			.orElseThrow(() -> new EntityNotFoundException(ErrorCode.MATCH_NOT_FOUND,
				MessageFormat.format("matchId = {0}", id)));

		if (match.getStatus().isMatched()) {
			throw new BusinessException(ErrorCode.MATCH_INVALID_DELETE_REQUEST,
				MessageFormat.format("matchId = {0}", id));
		}

		verifyAuthor(match, userId);

		matchProposalService.deleteByMatches(id);
		matchRepository.delete(match);
	}

	@Transactional
	public void updateStatusExceptEnd(Long id, Long userId, MatchStatus status) {
		if (status.isEnded()) {
			throw new BusinessException(ErrorCode.MATCH_CANNOT_UPDATE_END,
				MessageFormat.format("matchId = {0}, userId = {1}, status = {2}", id, userId, status));
		}

		Match match = matchRepository.findById(id)
			.orElseThrow(() -> new EntityNotFoundException(ErrorCode.MATCH_NOT_FOUND,
				MessageFormat.format("matchId = {0}", id)));

		verifyAuthor(match, userId);

		if (Objects.equals(match.getStatus(), status)) {
			throw new BusinessException(ErrorCode.MATCH_ALREADY_CHANGED_STATUS,
				MessageFormat.format("matchId = {0} , status = {1}", id, status));
		}

		if (match.getStatus().isEnded()) {
			throw new BusinessException(ErrorCode.MATCH_ENDED,
				MessageFormat.format("matchId = {0} , status = {1}", id, status));
		}

		match.updateStatus(status);
	}

	private void verifyUserLocation(User user) {
		if (user.getUserSettings() == null || user.getUserSettings().getLocation() == null) {
			throw new BusinessException(ErrorCode.LOCATION_NOT_FOUND,
				MessageFormat.format("User id = {0} location is null", user.getId()));
		}
	}

	private void verifyAuthor(Match match, Long userId) {
		if (!Objects.equals(match.getUser().getId(), userId)) {
			throw new BusinessException(ErrorCode.MATCH_ACCESS_DENIED,
				MessageFormat.format("userId = {0}, matchId = {1}", userId, match.getId()));
		}
	}
}
