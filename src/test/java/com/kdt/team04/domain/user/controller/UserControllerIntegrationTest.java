package com.kdt.team04.domain.user.controller;

import static com.kdt.team04.domain.matches.match.model.MatchStatus.END;
import static com.kdt.team04.domain.teams.team.model.SportsCategory.BASEBALL;
import static com.kdt.team04.domain.teams.team.model.SportsCategory.SOCCER;
import static com.kdt.team04.domain.teams.teammember.model.TeamMemberRole.LEADER;
import static java.time.LocalDate.now;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.handler;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.LongStream;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.Cookie;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

import com.amazonaws.services.s3.AmazonS3;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kdt.team04.common.ApiResponse;
import com.kdt.team04.common.aws.s3.S3Uploader;
import com.kdt.team04.common.security.jwt.Jwt;
import com.kdt.team04.domain.auth.dto.JwtToken;
import com.kdt.team04.domain.matches.match.model.MatchType;
import com.kdt.team04.domain.matches.match.model.entity.Match;
import com.kdt.team04.domain.matches.review.dto.response.MatchReviewTotalResponse;
import com.kdt.team04.domain.matches.review.model.MatchReviewValue;
import com.kdt.team04.domain.matches.review.model.entity.MatchReview;
import com.kdt.team04.domain.security.WithMockJwtAuthentication;
import com.kdt.team04.domain.teams.team.dto.response.TeamSimpleResponse;
import com.kdt.team04.domain.teams.team.model.entity.Team;
import com.kdt.team04.domain.teams.teammember.model.entity.TeamMember;
import com.kdt.team04.domain.user.Role;
import com.kdt.team04.domain.user.dto.response.FindProfileResponse;
import com.kdt.team04.domain.user.dto.response.UserFindResponse;
import com.kdt.team04.domain.user.entity.User;

@SpringBootTest
@AutoConfigureMockMvc
class UserControllerIntegrationTest {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	ObjectMapper objectMapper;

	@PersistenceContext
	EntityManager entityManager;

	@Autowired
	Jwt jwt;

	@Autowired
	PasswordEncoder passwordEncoder;

	@MockBean
	S3Uploader s3Uploader;

	@MockBean
	AmazonS3 amazonS3;

	@Test
	@Transactional
	@DisplayName("회원 프로필을 조회한다.")
	void testFindProfile() throws Exception {
		// given
		User findUser = new User("test00", "nk_test00",
			passwordEncoder.encode("1234"));
		User user = new User("test01", "nk_test01",
			passwordEncoder.encode("1234"));

		Team findUserTeam1 = Team.builder()
			.name("team00")
			.description("desc-team00")
			.sportsCategory(SOCCER)
			.leader(findUser)
			.build();
		TeamMember findUserTeamMember1 = new TeamMember(findUserTeam1, findUser, LEADER);
		Team findUserTeam2 = Team.builder()
			.name("team01")
			.description("desc-team01")
			.sportsCategory(BASEBALL)
			.leader(findUser)
			.build();
		TeamMember findUserTeamMember2 = new TeamMember(findUserTeam2, findUser, LEADER);

		Team userTeam = Team.builder()
			.name("team02")
			.description("desc-team02")
			.sportsCategory(SOCCER)
			.leader(user)
			.build();
		TeamMember userTeamMember = new TeamMember(userTeam, user, LEADER);

		Match match = Match.builder()
			.title("축구 덤벼!")
			.sportsCategory(SOCCER)
			.matchType(MatchType.TEAM_MATCH)
			.matchDate(now())
			.content("축구 하실분?")
			.status(END)
			.user(findUser)
			.team(findUserTeam1)
			.build();
		MatchReview review = MatchReview.builder()
			.match(match)
			.review(MatchReviewValue.BEST)
			.user(user)
			.team(userTeam)
			.targetUser(findUser)
			.targetTeam(findUserTeam1)
			.build();

		entityManager.persist(findUser);
		entityManager.persist(user);
		entityManager.persist(findUserTeam1);
		entityManager.persist(findUserTeam2);
		entityManager.persist(userTeam);
		entityManager.persist(findUserTeamMember1);
		entityManager.persist(findUserTeamMember2);
		entityManager.persist(userTeamMember);
		entityManager.persist(match);
		entityManager.persist(review);

		MatchReviewTotalResponse reviewResponse = new MatchReviewTotalResponse(1, 0, 0);
		List<TeamSimpleResponse> teamResponses = Arrays.asList(
			new TeamSimpleResponse(findUserTeam1.getId(), findUserTeam1.getName(),
				findUserTeam1.getSportsCategory(), findUserTeam1.getLogoImageUrl()),
			new TeamSimpleResponse(findUserTeam2.getId(), findUserTeam2.getName(),
				findUserTeam2.getSportsCategory(), findUserTeam2.getLogoImageUrl())
		);
		FindProfileResponse profileResponse = new FindProfileResponse(findUser.getNickname(),
			findUser.getProfileImageUrl(), findUser.getEmail(), null, reviewResponse,
			teamResponses);

		String response = objectMapper.writeValueAsString(new ApiResponse<>(profileResponse));

		// when
		ResultActions result = mockMvc.perform(
			get("/api/users/" + findUser.getId())
				.accept(MediaType.APPLICATION_JSON)
				.cookie(getAccessTokenCookie(user))
		);

		// then
		result.andDo(print())
			.andExpect(status().isOk())
			.andExpect(handler().handlerType(UserController.class))
			.andExpect(handler().methodName("findProfile"))
			.andExpect(content().string(response));
	}

	@Test
	@Transactional
	@DisplayName("회원 프로필 닉네임이 포함된 유저들을 조회한다.")
	@WithMockJwtAuthentication
	void testFindAllByNickname() throws Exception {
		// given
		String nickname = "test";
		LongStream.range(1, 6)
			.mapToObj(id ->
				User.builder()
					.username("test00" + id)
					.nickname("test00" + id)
					.password(passwordEncoder.encode("12345"))
					.profileImageUrl("test00" + id)
					.build()
			)
			.forEach(user -> entityManager.persist(user));

		List<UserFindResponse> responses = LongStream.range(1, 6)
			.mapToObj(id ->
				new UserFindResponse(id, "test00" + id, "test00" + id, "test00" + id))
			.toList();

		String response = objectMapper.writeValueAsString(new ApiResponse<>(responses));

		// when
		ResultActions result = mockMvc.perform(
			get("/api/users")
				.param("nickname", nickname)
				.accept(MediaType.APPLICATION_JSON)
				.cookie(getAccessTokenCookie(createUser(entityManager)))
		);

		// then
		result.andDo(print())
			.andExpect(status().isOk())
			.andExpect(handler().handlerType(UserController.class))
			.andExpect(handler().methodName("findUsers"))
			.andExpect(content().string(response));
	}

	@Test
	@Transactional
	@DisplayName("닉네임이 포함된 사용자가 없다면 비어있는 리스트를 반환한다.")
	void testFindAllByNicknameEmpty() throws Exception {
		// given
		String nickname = "notfound";
		LongStream.range(1, 6)
			.mapToObj(id ->
				new User("test00" + id, "test00" + id, passwordEncoder.encode("12345"))
			)
			.forEach(user -> entityManager.persist(user));

		List<UserFindResponse> responses = Collections.emptyList();

		String response = objectMapper.writeValueAsString(new ApiResponse<>(responses));

		// when
		ResultActions result = mockMvc.perform(
			get("/api/users")
				.param("nickname", nickname)
				.accept(MediaType.APPLICATION_JSON)
				.cookie(getAccessTokenCookie(createUser(entityManager)))
		);

		// then
		result.andDo(print())
			.andExpect(status().isOk())
			.andExpect(handler().handlerType(UserController.class))
			.andExpect(handler().methodName("findUsers"))
			.andExpect(content().string(response));
	}

	@Test
	@Transactional
	@DisplayName("닉네임이 null 혹은 빈값으로 요청된다면 예외를 반환한다.")
	void testFindAllByNicknameException() throws Exception {
		// given
		LongStream.range(1, 6)
			.mapToObj(id ->
				new User("test00" + id, "test00" + id, passwordEncoder.encode("12345"))
			)
			.forEach(user -> entityManager.persist(user));

		// when
		ResultActions result = mockMvc
			.perform(get("/api/users")
				.cookie(getAccessTokenCookie(createUser(entityManager))));

		// then
		result.andDo(print())
			.andExpect(status().isBadRequest());
	}

	User createUser(EntityManager entityManager) {
		String encodedPassword = passwordEncoder.encode("@Test1234!");
		User newUser = new User("dummyuser1234", "dummyNickname1",
			encodedPassword);

		entityManager.persist(newUser);

		return newUser;
	}

	Cookie getAccessTokenCookie(User user) {
		Jwt.Claims claims = Jwt.Claims.builder(
			user.getId(),
			user.getUsername(),
			new String[] {String.valueOf(Role.USER)}).build();
		JwtToken accessToken = jwt.generateAccessToken(claims);

		return new Cookie(accessToken.header(), accessToken.token());
	}
}