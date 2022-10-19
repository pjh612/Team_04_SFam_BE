package com.kdt.team04.domain.matches.match.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import javax.persistence.EntityManager;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.transaction.annotation.Transactional;

import com.amazonaws.services.s3.AmazonS3;
import com.kdt.team04.common.PageDto;
import com.kdt.team04.common.aws.s3.S3Uploader;
import com.kdt.team04.common.exception.BusinessException;
import com.kdt.team04.common.exception.EntityNotFoundException;
import com.kdt.team04.domain.matches.match.dto.MatchPagingCursor;
import com.kdt.team04.domain.matches.match.dto.request.CreateMatchRequest;
import com.kdt.team04.domain.matches.match.dto.response.MatchListViewResponse;
import com.kdt.team04.domain.matches.match.dto.response.MatchResponse;
import com.kdt.team04.domain.matches.match.model.MatchStatus;
import com.kdt.team04.domain.matches.match.model.MatchType;
import com.kdt.team04.domain.matches.match.model.entity.Match;
import com.kdt.team04.domain.matches.match.repository.MatchRepository;
import com.kdt.team04.domain.teams.team.model.SportsCategory;
import com.kdt.team04.domain.teams.team.model.entity.Team;
import com.kdt.team04.domain.teams.teammember.model.TeamMemberRole;
import com.kdt.team04.domain.teams.teammember.model.entity.TeamMember;
import com.kdt.team04.domain.user.entity.User;
import com.kdt.team04.domain.user.entity.UserSettings;
import com.kdt.team04.feign.kakao.dto.CoordToAddressResponse;
import com.kdt.team04.feign.kakao.service.KakaoApiService;

@Transactional
@SpringBootTest
class MatchServiceIntegrationTest {

	@Autowired
	private EntityManager entityManager;

	@Autowired
	private MatchService matchService;

	@Autowired
	MatchRepository matchRepository;

	@MockBean
	S3Uploader s3Uploader;

	@MockBean
	AmazonS3 amazonS3;

	@MockBean
	KakaoApiService kakaoApiService;

	@Test
	@DisplayName("팀의 리더는 팀 매칭 공고를 생성할 수 있다.")
	void testTeamCreateSuccess() {
		//given
		User leader = new User("leader", "leader", "password");
		User user1 = new User("member1", "member1", "password");
		User user2 = new User("member2", "member2", "password");
		entityManager.persist(leader);
		entityManager.persist(user1);
		entityManager.persist(user2);
		leader.updateSettings(1.1, 1.2, "테스트동",10);
		Team team = Team.builder()
			.name("team1")
			.description("first team")
			.sportsCategory(SportsCategory.BADMINTON)
			.leader(leader)
			.build();
		entityManager.persist(team);
		entityManager.persist(new TeamMember(team, leader, TeamMemberRole.LEADER));
		entityManager.persist(new TeamMember(team, user1, TeamMemberRole.MEMBER));
		entityManager.persist(new TeamMember(team, user2, TeamMemberRole.MEMBER));
		CreateMatchRequest request = new CreateMatchRequest("match1", LocalDate.now(),
			MatchType.TEAM_MATCH,
			team.getId(), 3, SportsCategory.BADMINTON, "content");

		//when
		Long createdMatch = matchService.create(leader.getId(), request);

		//then
		assertThat(createdMatch).isNotNull();
	}

	@Test
	@DisplayName("사용자는 개인전 매칭 공고를 생성할 수 있다.")
	void testIndividualCreateSuccess() {
		//given
		User user = new User("test1234", "nickname", "$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.");
		entityManager.persist(user);
		user.updateSettings(1.1, 1.2, "테스트동",10);
		CreateMatchRequest request = new CreateMatchRequest("match1", LocalDate.now(),
			MatchType.INDIVIDUAL_MATCH,
			null, 1, SportsCategory.BADMINTON, "content");

		//when
		Long createdMatch = matchService.create(user.getId(), request);

		//then
		assertThat(createdMatch).isNotNull();
	}

	@Test
	@DisplayName("개인전 매칭 공고는 참여 인원이 1명이 아닐경우 예외가 발생한다.")
	void testIndividualCreateFail() {
		//given    
		User user = new User("test1234", "nickname", "$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.");

		entityManager.persist(user);
		CreateMatchRequest request = new CreateMatchRequest("match1", LocalDate.now(),
			MatchType.INDIVIDUAL_MATCH,
			null, 2, SportsCategory.BADMINTON, "content");

		//when, then
		assertThatThrownBy(() -> matchService.create(user.getId(), request)).isInstanceOf(BusinessException.class);
	}

	@Test
	@DisplayName("팀 매칭 공고를 생성하는 주체가 팀의 리더가 아닐 경우 예외가 발생한다.")
	void testTeamCreateFail() {
		//given
		User leader = new User("test1234", "nicknameA", "$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.");
		User member = new User("test1235", "nicknameB", "$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.");

		entityManager.persist(leader);
		Team team = Team.builder()
			.name("team1")
			.description("first team")
			.sportsCategory(SportsCategory.BADMINTON)
			.leader(leader)
			.build();
		entityManager.persist(team);
		CreateMatchRequest request = new CreateMatchRequest("match1", LocalDate.now(),
			MatchType.TEAM_MATCH,
			team.getId(), 1, SportsCategory.BADMINTON, "content");

		//when, then
		assertThatThrownBy(() -> matchService.create(member.getId(), request)).isInstanceOf(BusinessException.class);
	}

	@Test
	@DisplayName("팀 매칭 공고 생성 시 request에 팀 id가 null이면 예외가 발생한다.")
	void testTeamCreateFailByRequest() {
		//given
		User user = new User("username", "nickname", "password");
		entityManager.persist(user);
		Team team = Team.builder()
			.name("team1")
			.description("first team")
			.sportsCategory(SportsCategory.BADMINTON)
			.leader(user)
			.build();
		entityManager.persist(team);
		CreateMatchRequest request = new CreateMatchRequest("match1", LocalDate.now(),
			MatchType.TEAM_MATCH,
			null, 3, SportsCategory.BADMINTON, "content");

		//when, then
		assertThatThrownBy(() -> matchService.create(user.getId(), request)).isInstanceOf(BusinessException.class);

	}

	@Test
	@DisplayName("팀 매칭 공고 생성 시 자신이 선택한 팀의 팀원보다 매칭 참여 인원수가 많으면 예외가 발생한다.")
	void testTeamCreateFailByTeamMemberCount() {
		//given
		User user = new User("username", "nickname", "password");
		entityManager.persist(user);
		Team team = Team.builder()
			.name("team1")
			.description("first team")
			.sportsCategory(SportsCategory.BADMINTON)
			.leader(user)
			.build();
		entityManager.persist(team);
		CreateMatchRequest request = new CreateMatchRequest("match1", LocalDate.now(),
			MatchType.TEAM_MATCH,
			null, 3, SportsCategory.BADMINTON, "content");

		//when, then
		assertThatThrownBy(() -> matchService.create(user.getId(), request)).isInstanceOf(BusinessException.class);

	}

	@Test
	@DisplayName("매칭 공고 단건 조회를 할 수 있다.")
	void testFindByIdSuccess() {
		//given
		User user = new User("password", "username", "nickname");
		entityManager.persist(user);

		Match savedMatch = matchRepository.save(Match.builder()
			.title("match")
			.matchDate(LocalDate.now())
			.matchType(MatchType.INDIVIDUAL_MATCH)
			.participants(1)
			.user(user)
			.sportsCategory(SportsCategory.BADMINTON)
			.content("content")
			.build());

		//when
		MatchResponse foundMatch = matchService.findById(savedMatch.getId(), user.getId());

		//then
		assertThat(foundMatch.title()).isEqualTo(savedMatch.getTitle());
		assertThat(foundMatch.matchDate()).isEqualTo(savedMatch.getMatchDate());
		assertThat(foundMatch.content()).isEqualTo(savedMatch.getContent());
		assertThat(foundMatch.participants()).isEqualTo(savedMatch.getParticipants());
		assertThat(foundMatch.author().id()).isEqualTo(user.getId());
		assertThat(foundMatch.team()).isNull();
	}

	@Test
	@DisplayName("존재하지 않은 매칭 공고 id의 경우 EntityNotFound 예외가 발생한다.")
	void testFindByIdFail() {
		//given
		Long invalidId = 1234L;
		//when, then
		assertThatThrownBy(() -> matchService.findById(invalidId, 1L))
			.isInstanceOf(EntityNotFoundException.class);
	}

	@Test
	@DisplayName("작성자와 공고글 사이의 거리가 1.51km이고 검색범위가 1.50면 검색이 안된다.")
	void testFindMatchesCursorPagingTooFar() {
		UserSettings mySettings = new UserSettings(37.3947122, 127.111253, 10);
		UserSettings authorSettings = new UserSettings(37.3956683, 127.128228, 10);
		LocalDateTime cursorCreatedAt = LocalDateTime.now().plusWeeks(1);
		User leader = User.builder()
			.username("test1234")
			.nickname("nicknameA")
			.password("$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.")
			.userSettings(authorSettings)
			.build();
		User member = User.builder()
			.username("test1235")
			.nickname("nicknameB")
			.password("$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.")
			.userSettings(mySettings)
			.build();
		entityManager.persist(leader);
		entityManager.persist(member);

		Team team = Team.builder()
			.name("team1")
			.description("first team")
			.sportsCategory(SportsCategory.BADMINTON)
			.leader(leader)
			.build();
		entityManager.persist(team);

		Match match = Match.builder()
			.title("title")
			.content("content")
			.team(team)
			.sportsCategory(SportsCategory.BADMINTON)
			.matchDate(LocalDate.now())
			.matchType(MatchType.INDIVIDUAL_MATCH)
			.location(authorSettings.getLocation())
			.status(MatchStatus.WAITING)
			.user(leader)
			.participants(1)
			.build();
		entityManager.persist(match);
		entityManager.flush();

		PageDto.MatchCursorPageRequest request = PageDto.MatchCursorPageRequest.builder()
			.id(match.getId())
			.createdAt(cursorCreatedAt)
			.size(5)
			.category(SportsCategory.BADMINTON)
			.distance(1.5)
			.build();
		PageDto.CursorResponse<MatchListViewResponse, MatchPagingCursor> foundMatches = matchService.findMatches(
			member.getId(), request);

		assertThat(foundMatches.values().size()).isZero();
		assertThat(foundMatches.hasNext()).isFalse();
	}

	@Test
	@DisplayName("두 지점 간 거리 1.51km 5개 매치 불러오기")
	void testFindMatchesCursorPaging() {
		//given
		UserSettings mySettings = new UserSettings(37.3947122, 127.111253, 10);
		UserSettings authorSettings = new UserSettings(37.3956683, 127.128228, 10);
		LocalDateTime cursorCreatedAt = LocalDateTime.now().plusWeeks(1);
		User leader = User.builder()
			.username("test1234")
			.nickname("nicknameA")
			.password("$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.")
			.userSettings(authorSettings)
			.build();
		User member = User.builder()
			.username("test1235")
			.nickname("nicknameB")
			.password("$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.")
			.userSettings(mySettings)
			.build();
		entityManager.persist(leader);
		entityManager.persist(member);

		Team team = Team.builder()
			.name("team1")
			.description("first team")
			.sportsCategory(SportsCategory.BADMINTON)
			.leader(leader)
			.build();
		entityManager.persist(team);

		List<Match> matches = Stream.iterate(0, i -> i + 1)
			.limit(10)
			.map(i ->
				Match.builder()
					.title("title" + i)
					.content("content" + i)
					.team(team)
					.sportsCategory(SportsCategory.BADMINTON)
					.matchDate(LocalDate.now())
					.matchType(MatchType.INDIVIDUAL_MATCH)
					.location(authorSettings.getLocation())
					.status(MatchStatus.WAITING)
					.user(leader)
					.participants(1)
					.build()
			).peek(entityManager::persist)
			.toList();

		entityManager.flush();

		PageDto.MatchCursorPageRequest request = PageDto.MatchCursorPageRequest.builder()
			.id(matches.get(matches.size() - 1).getId())
			.createdAt(cursorCreatedAt)
			.size(5)
			.category(SportsCategory.BADMINTON)
			.distance(1.51)
			.build();

		given(kakaoApiService.coordToAddressResponse(
			authorSettings.getLocation().getLongitude(),
			authorSettings.getLocation().getLatitude())).willReturn(getDummyAddressResponse());

		//when
		PageDto.CursorResponse<MatchListViewResponse, MatchPagingCursor> foundMatches = matchService.findMatches(
			member.getId(), request);


		//then
		assertThat(foundMatches.values()).hasSize(request.getSize());
		assertThat(foundMatches.hasNext()).isTrue();
		assertThat(foundMatches.values().get(0).id()).isEqualTo(matches.get(matches.size() - 1).getId());
		assertThat(foundMatches.values().get(4).id()).isEqualTo(matches.get(matches.size() - 5).getId());
	}

	@Test
	@DisplayName("축구매치 3개, 배트민턴 2개일때 매치 불러오기")
	void testFindMatchesCursorPagingDifferentCategory() {
		//given
		UserSettings mySettings = new UserSettings(37.3947122, 127.111253, 10);
		UserSettings authorSettings = new UserSettings(37.3956683, 127.128228, 10);
		LocalDateTime cursorCreatedAt = LocalDateTime.now().plusWeeks(1);
		User leader = User.builder()
			.username("test1234")
			.nickname("nicknameA")
			.password("$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.")
			.userSettings(authorSettings)
			.build();
		User member = User.builder()
			.username("test1235")
			.nickname("nicknameB")
			.password("$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.")
			.userSettings(mySettings)
			.build();
		entityManager.persist(leader);
		entityManager.persist(member);

		Team team = Team.builder()
			.name("team1")
			.description("first team")
			.sportsCategory(SportsCategory.BADMINTON)
			.leader(leader)
			.build();
		entityManager.persist(team);

		Stream.iterate(0, i -> i + 1)
			.limit(3)
			.map(i ->
				Match.builder()
					.title("title" + i)
					.content("content" + i)
					.team(team)
					.sportsCategory(SportsCategory.SOCCER)
					.matchDate(LocalDate.now())
					.matchType(MatchType.INDIVIDUAL_MATCH)
					.location(authorSettings.getLocation())
					.status(MatchStatus.WAITING)
					.user(leader)
					.participants(1)
					.build()
			).forEach(entityManager::persist);

		List<Match> badmintonMatches = Stream.iterate(0, i -> i + 1)
			.limit(2)
			.map(i ->
				Match.builder()
					.title("title" + i)
					.content("content" + i)
					.team(team)
					.sportsCategory(SportsCategory.BADMINTON)
					.matchDate(LocalDate.now())
					.matchType(MatchType.INDIVIDUAL_MATCH)
					.location(authorSettings.getLocation())
					.status(MatchStatus.WAITING)
					.user(leader)
					.participants(1)
					.build()
			).peek(entityManager::persist)
			.toList();

		entityManager.flush();

		PageDto.MatchCursorPageRequest request = PageDto.MatchCursorPageRequest.builder()
			.id(badmintonMatches.get(badmintonMatches.size() - 1).getId())
			.createdAt(cursorCreatedAt)
			.size(5)
			.category(SportsCategory.BADMINTON)
			.distance(1.51)
			.build();

		given(kakaoApiService.coordToAddressResponse(
			authorSettings.getLocation().getLongitude(),
			authorSettings.getLocation().getLatitude())).willReturn(getDummyAddressResponse());

		//when
		PageDto.CursorResponse<MatchListViewResponse, MatchPagingCursor> foundMatches = matchService.findMatches(
			member.getId(), request);

		//then
		assertThat(foundMatches.values()).hasSize(2);
		assertThat(foundMatches.hasNext()).isFalse();
		assertThat(foundMatches.values().get(0).id()).isEqualTo(
			badmintonMatches.get(badmintonMatches.size() - 1).getId());
	}

	@Test
	@DisplayName("두 지점 간 거리 1.51km 5개 매치 불러오기 - 2번째 페이징")
	void testFindMatchesCursorPagingTwice() {
		//given
		UserSettings mySettings = new UserSettings(37.3947122, 127.111253, 10);
		UserSettings authorSettings = new UserSettings(37.3956683, 127.128228, 10);
		LocalDateTime cursorCreatedAt = LocalDateTime.now().plusWeeks(1);
		User leader = User.builder()
			.username("test1234")
			.nickname("nicknameA")
			.password("$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.")
			.userSettings(authorSettings)
			.build();
		User member = User.builder()
			.username("test1235")
			.nickname("nicknameB")
			.password("$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.")
			.userSettings(mySettings)
			.build();
		entityManager.persist(leader);
		entityManager.persist(member);

		Team team = Team.builder()
			.name("team1")
			.description("first team")
			.sportsCategory(SportsCategory.BADMINTON)
			.leader(leader)
			.build();
		entityManager.persist(team);

		List<Match> matches = Stream.iterate(0, i -> i + 1)
			.limit(10)
			.map(i ->
				Match.builder()
					.title("title" + i)
					.content("content" + i)
					.team(team)
					.sportsCategory(SportsCategory.BADMINTON)
					.matchDate(LocalDate.now())
					.matchType(MatchType.INDIVIDUAL_MATCH)
					.location(authorSettings.getLocation())
					.status(MatchStatus.WAITING)
					.user(leader)
					.participants(1)
					.build()
			).peek(entityManager::persist)
			.toList();

		entityManager.flush();

		PageDto.MatchCursorPageRequest request = PageDto.MatchCursorPageRequest.builder()
			.createdAt(cursorCreatedAt)
			.id(matches.get(matches.size() - 1).getId())
			.size(5)
			.category(SportsCategory.BADMINTON)
			.distance(1.51)
			.build();

		given(kakaoApiService.coordToAddressResponse(
			authorSettings.getLocation().getLongitude(),
			authorSettings.getLocation().getLatitude())).willReturn(getDummyAddressResponse());

		//when
		PageDto.CursorResponse<MatchListViewResponse, MatchPagingCursor> foundMatches = matchService.findMatches(
			member.getId(), request);

		LocalDateTime lastCreatedAt = foundMatches.cursor().createdAt();
		Long lastId = foundMatches.cursor().id();

		PageDto.MatchCursorPageRequest secondRequest = PageDto.MatchCursorPageRequest.builder()
			.id(lastId)
			.createdAt(lastCreatedAt)
			.size(5)
			.category(SportsCategory.BADMINTON)
			.distance(1.51)
			.build();

		PageDto.CursorResponse<MatchListViewResponse, MatchPagingCursor> secondFoundMatches = matchService.findMatches(
			member.getId(), secondRequest);

		//then
		assertThat(secondFoundMatches.values()).hasSize(request.getSize());
		assertThat(secondFoundMatches.hasNext()).isFalse();
		assertThat(secondFoundMatches.values().get(0).id()).isEqualTo(matches.get(matches.size() - 6).getId());
		assertThat(secondFoundMatches.values().get(4).id()).isEqualTo(matches.get(matches.size() - 10).getId());
	}

	@Test
	@DisplayName("페이징 커서가 없다면 전체 내림차순으로 조회한다.")
	void testFindAllMatchesIfNullPagingRequest() {
		//given
		UserSettings mySettings = new UserSettings(37.3947122, 127.111253, 10);
		UserSettings authorSettings = new UserSettings(37.3956683, 127.128228, 10);

		User leader = User.builder()
			.username("test1234")
			.nickname("nicknameA")
			.password("$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.")
			.userSettings(authorSettings)
			.build();
		User member = User.builder()
			.username("test1235")
			.nickname("nicknameB")
			.password("$2a$12$JB1zYmj1TfoylCds8Tt5ue//BQTWE2xO5HZn.MjZcpo.z.7LKagZ.")
			.userSettings(mySettings)
			.build();
		entityManager.persist(leader);
		entityManager.persist(member);

		Team team = Team.builder()
			.name("team1")
			.description("first team")
			.sportsCategory(SportsCategory.BADMINTON)
			.leader(leader)
			.build();
		entityManager.persist(team);

		List<Match> matches = Stream.iterate(0, i -> i + 1)
			.limit(10)
			.map(i ->
				Match.builder()
					.title("title" + i)
					.content("content" + i)
					.team(team)
					.sportsCategory(SportsCategory.BADMINTON)
					.matchDate(LocalDate.now())
					.matchType(MatchType.INDIVIDUAL_MATCH)
					.location(authorSettings.getLocation())
					.status(MatchStatus.WAITING)
					.user(leader)
					.participants(1)
					.build()
			).peek(entityManager::persist)
			.toList();

		entityManager.flush();

		PageDto.MatchCursorPageRequest request = PageDto.MatchCursorPageRequest.builder()
			.size(5)
			.category(SportsCategory.BADMINTON)
			.distance(1.51)
			.build();

		given(kakaoApiService.coordToAddressResponse(
			authorSettings.getLocation().getLongitude(),
			authorSettings.getLocation().getLatitude())).willReturn(getDummyAddressResponse());

		//when
		PageDto.CursorResponse<MatchListViewResponse, MatchPagingCursor> foundMatches = matchService.findMatches(
			member.getId(), request);

		//then
		assertThat(foundMatches.values()).hasSize(request.getSize());
		assertThat(foundMatches.values().get(0).id()).isEqualTo(matches.get(matches.size() - 1).getId());
		assertThat(foundMatches.values().get(4).id()).isEqualTo(matches.get(matches.size() - 5).getId());
		assertThat(foundMatches.hasNext()).isTrue();
	}

	@Test
	@DisplayName("매칭을 모집 완료로 상태 변경한다.")
	void test_updateStatusExceptEnd_toInGame() {
		//given
		User author = new User("author", "author", "aA1234!");
		Team authorTeam = Team.builder()
			.name("team1")
			.description("first team")
			.sportsCategory(SportsCategory.BADMINTON)
			.leader(author)
			.build();
		entityManager.persist(author);
		entityManager.persist(authorTeam);

		Match match = Match.builder()
			.title("match")
			.status(MatchStatus.WAITING)
			.matchDate(LocalDate.now())
			.matchType(MatchType.TEAM_MATCH)
			.participants(3)
			.user(author)
			.team(authorTeam)
			.sportsCategory(SportsCategory.BADMINTON)
			.content("content")
			.build();
		entityManager.persist(match);

		//when
		matchService.updateStatusExceptEnd(match.getId(), author.getId(), MatchStatus.IN_GAME);

		//then
		Match foundMatch = entityManager.find(Match.class, match.getId());
		assertThat(foundMatch).isNotNull();
		assertThat(foundMatch.getStatus()).isEqualTo(MatchStatus.IN_GAME);
	}

	@Test
	@DisplayName("매칭을 모집 중으로 상태 변경한다.")
	void test_updateStatusExceptEnd_toWaiting() {
		//given
		User author = new User("author", "author", "aA1234!");
		Team authorTeam = Team.builder()
			.name("team1")
			.description("first team")
			.sportsCategory(SportsCategory.BADMINTON)
			.leader(author)
			.build();
		entityManager.persist(author);
		entityManager.persist(authorTeam);

		Match match = Match.builder()
			.title("match")
			.status(MatchStatus.IN_GAME)
			.matchDate(LocalDate.now())
			.matchType(MatchType.TEAM_MATCH)
			.participants(3)
			.user(author)
			.team(authorTeam)
			.sportsCategory(SportsCategory.BADMINTON)
			.content("content")
			.build();
		entityManager.persist(match);

		//when
		matchService.updateStatusExceptEnd(match.getId(), author.getId(), MatchStatus.WAITING);

		//then
		Match foundMatch = entityManager.find(Match.class, match.getId());
		assertThat(foundMatch).isNotNull();
		assertThat(foundMatch.getStatus()).isEqualTo(MatchStatus.WAITING);
	}

	@Nested
	@DisplayName("매칭을 모집 완료 또는 모집 중으로 상태 변경 시")
	class UserUpdateRequestStatusExceptEnd {

		@Test
		@DisplayName("경기 완료 상태로 변경하는 경우 오류가 발생한다.")
		void testFail_CanNotUpdateEnd_updateStatusExceptEnd() {
			//given
			User author = new User("author", "author", "aA1234!");
			Team authorTeam = Team.builder()
				.name("team1")
				.description("first team")
				.sportsCategory(SportsCategory.BADMINTON)
				.leader(author)
				.build();
			entityManager.persist(author);
			entityManager.persist(authorTeam);

			Match match = Match.builder()
				.title("match")
				.status(MatchStatus.IN_GAME)
				.matchDate(LocalDate.now())
				.matchType(MatchType.TEAM_MATCH)
				.participants(3)
				.user(author)
				.team(authorTeam)
				.sportsCategory(SportsCategory.BADMINTON)
				.content("content")
				.build();
			entityManager.persist(match);

			//when, then
			assertThatThrownBy(() -> {
				matchService.updateStatusExceptEnd(match.getId(), author.getId(), MatchStatus.END);
			}).isInstanceOf(BusinessException.class);
		}

		@Test
		@DisplayName("매칭이 존재하지 않는 경우 오류가 발생한다.")
		void testFail_EmptyExceptionBy_updateStatusExceptEnd() {
			//given
			User author = new User("author", "author", "aA1234!");
			entityManager.persist(author);

			Long invalidMatchId = 999L;

			//when, then
			assertThatThrownBy(() -> {
				matchService.updateStatusExceptEnd(invalidMatchId, author.getId(), MatchStatus.IN_GAME);
			}).isInstanceOf(BusinessException.class);
		}

		@Test
		@DisplayName("매칭 작성자가 아닌 경우 오류가 발생한다.")
		void testFail_Access_DeniedBy_updateStatusExceptEnd() {
			//given
			User author = new User("author", "author", "aA1234!");
			Team authorTeam = Team.builder()
				.name("team1")
				.description("first team")
				.sportsCategory(SportsCategory.BADMINTON)
				.leader(author)
				.build();
			entityManager.persist(author);
			entityManager.persist(authorTeam);

			Match match = Match.builder()
				.title("match")
				.status(MatchStatus.WAITING)
				.matchDate(LocalDate.now())
				.matchType(MatchType.TEAM_MATCH)
				.participants(3)
				.user(author)
				.team(authorTeam)
				.sportsCategory(SportsCategory.BADMINTON)
				.content("content")
				.build();
			entityManager.persist(match);

			User invalidUser = new User("proposer", "proposer", "aA1234!");
			entityManager.persist(invalidUser);

			//when, then
			assertThatThrownBy(() -> {
				matchService.updateStatusExceptEnd(match.getId(), invalidUser.getId(), MatchStatus.IN_GAME);
			}).isInstanceOf(BusinessException.class);
		}

		@Test
		@DisplayName("이미 변경 상태인 경우 오류가 발생한다.")
		void testFail_AlreadyChangedBy_updateStatusExceptEnd() {
			//given
			User author = new User("author", "author", "aA1234!");
			Team authorTeam = Team.builder()
				.name("team1")
				.description("first team")
				.sportsCategory(SportsCategory.BADMINTON)
				.leader(author)
				.build();
			entityManager.persist(author);
			entityManager.persist(authorTeam);

			Match match = Match.builder()
				.title("match")
				.status(MatchStatus.IN_GAME)
				.matchDate(LocalDate.now())
				.matchType(MatchType.TEAM_MATCH)
				.participants(3)
				.user(author)
				.team(authorTeam)
				.sportsCategory(SportsCategory.BADMINTON)
				.content("content")
				.build();
			entityManager.persist(match);

			//when, then
			assertThatThrownBy(() -> {
				matchService.updateStatusExceptEnd(match.getId(), author.getId(), MatchStatus.IN_GAME);
			}).isInstanceOf(BusinessException.class);
		}

		@Test
		@DisplayName("경기 종료 상태인 경우 오류가 발생한다.")
		void testFail_MatchEndedBy_updateStatusExceptEnd() {
			//given
			User author = new User("author", "author", "aA1234!");
			Team authorTeam = Team.builder()
				.name("team1")
				.description("first team")
				.sportsCategory(SportsCategory.BADMINTON)
				.leader(author)
				.build();
			entityManager.persist(author);
			entityManager.persist(authorTeam);

			Match match = Match.builder()
				.title("match")
				.status(MatchStatus.END)
				.matchDate(LocalDate.now())
				.matchType(MatchType.TEAM_MATCH)
				.participants(3)
				.user(author)
				.team(authorTeam)
				.sportsCategory(SportsCategory.BADMINTON)
				.content("content")
				.build();
			entityManager.persist(match);

			//when, then
			assertThatThrownBy(() -> {
				matchService.updateStatusExceptEnd(match.getId(), author.getId(), MatchStatus.IN_GAME);
			}).isInstanceOf(BusinessException.class);
		}
	}

	@Test
	@DisplayName("매칭 공고자는 매칭 공고를 삭제할 수 있다.")
	void testDeleteSuccess() {
		//given
		User user = new User("password", "username", "nickname");
		entityManager.persist(user);

		Match savedMatch = matchRepository.save(Match.builder()
			.title("match")
			.matchDate(LocalDate.now())
			.matchType(MatchType.INDIVIDUAL_MATCH)
			.participants(1)
			.user(user)
			.status(MatchStatus.WAITING)
			.sportsCategory(SportsCategory.BADMINTON)
			.content("content")
			.build());

		//when
		matchService.delete(user.getId(), savedMatch.getId());

		//then
		assertThat(matchRepository.findById(savedMatch.getId())).isEmpty();

	}

	@Test
	@DisplayName("매칭 공고자가 아니면 매칭 공고를 삭제시 예외가 발생한다.")
	void testDeleteFail() {
		//given
		User user = new User("username", "nickname", "password");
		entityManager.persist(user);

		Match savedMatch = matchRepository.save(Match.builder()
			.title("match")
			.matchDate(LocalDate.now())
			.matchType(MatchType.INDIVIDUAL_MATCH)
			.participants(1)
			.user(user)
			.sportsCategory(SportsCategory.BADMINTON)
			.status(MatchStatus.WAITING)
			.content("content")
			.build());

		//when, then
		assertThatThrownBy(() -> matchService.delete(1000L, savedMatch.getId()));
	}

	@Test
	@DisplayName("매칭 공고의 상태가 모집 중이 아닐 경우 예외가 발생한다.")
	void testDeleteFailByStatus() {
		//given
		User user = new User("username", "nickname", "password");
		entityManager.persist(user);

		Match savedMatch = matchRepository.save(Match.builder()
			.title("match")
			.matchDate(LocalDate.now())
			.matchType(MatchType.INDIVIDUAL_MATCH)
			.participants(1)
			.user(user)
			.status(MatchStatus.IN_GAME)
			.sportsCategory(SportsCategory.BADMINTON)
			.content("content")
			.build());

		//when, then
		assertThatThrownBy(() -> matchService.delete(user.getId(), savedMatch.getId()));
	}

	CoordToAddressResponse getDummyAddressResponse() {
		CoordToAddressResponse.Address address = CoordToAddressResponse.Address.builder()
			.region3DepthName("구서동")
			.build();
		CoordToAddressResponse.Documents documents = new CoordToAddressResponse.Documents(null, address);

		return new CoordToAddressResponse(null, Collections.singletonList(documents));
	}
}