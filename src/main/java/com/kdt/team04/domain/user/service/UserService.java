package com.kdt.team04.domain.user.service;

import java.text.MessageFormat;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import com.kdt.team04.common.aws.s3.S3Uploader;
import com.kdt.team04.common.exception.BusinessException;
import com.kdt.team04.common.exception.EntityNotFoundException;
import com.kdt.team04.common.exception.ErrorCode;
import com.kdt.team04.common.file.ImagePath;
import com.kdt.team04.domain.matches.review.dto.response.MatchReviewTotalResponse;
import com.kdt.team04.domain.matches.review.service.MatchReviewGiverService;
import com.kdt.team04.domain.teams.team.dto.response.TeamSimpleResponse;
import com.kdt.team04.domain.teams.team.service.TeamGiverService;
import com.kdt.team04.domain.user.UserConverter;
import com.kdt.team04.domain.user.dto.UpdateUserRequest;
import com.kdt.team04.domain.user.dto.request.CreateUserRequest;
import com.kdt.team04.domain.user.dto.request.UpdateUserByOAuthRequest;
import com.kdt.team04.domain.user.dto.request.UpdateUserSettingsRequest;
import com.kdt.team04.domain.user.dto.response.FindProfileResponse;
import com.kdt.team04.domain.user.dto.response.UpdateUserSettingsResponse;
import com.kdt.team04.domain.user.dto.response.UserFindResponse;
import com.kdt.team04.domain.user.dto.response.UserResponse;
import com.kdt.team04.domain.user.entity.User;
import com.kdt.team04.domain.user.repository.UserRepository;
import com.kdt.team04.feign.kakao.dto.CoordToAddressResponse;
import com.kdt.team04.feign.kakao.service.KakaoApiService;

@Service
@Transactional(readOnly = true)
public class UserService {

	private final UserRepository userRepository;
	private final MatchReviewGiverService matchReviewGiver;
	private final TeamGiverService teamGiver;
	private final UserConverter userConverter;
	private final S3Uploader s3Uploader;
	private final KakaoApiService kakaoApiService;

	public UserService(UserRepository userRepository, MatchReviewGiverService matchReviewGiver,
		TeamGiverService teamGiver, S3Uploader s3Uploader, UserConverter userConverter,
		KakaoApiService kakaoApiService) {
		this.userRepository = userRepository;
		this.matchReviewGiver = matchReviewGiver;
		this.teamGiver = teamGiver;
		this.userConverter = userConverter;
		this.s3Uploader = s3Uploader;
		this.kakaoApiService = kakaoApiService;
	}

	public UserResponse findByUsername(String username) {
		User foundUser = this.userRepository.findByUsername(username)
			.orElseThrow(() -> new EntityNotFoundException(ErrorCode.USER_NOT_FOUND,
				MessageFormat.format("Username = {0}", username)));

		return userConverter.toUserResponse(foundUser);
	}

	public UserResponse findByEmail(String email) {
		User foundUser = this.userRepository.findByEmail(email)
			.orElseThrow(() -> new EntityNotFoundException(ErrorCode.USER_NOT_FOUND,
				MessageFormat.format("email = {0}", email)));

		return userConverter.toUserResponse(foundUser);
	}

	public UserResponse findById(Long id) {
		User foundUser = this.userRepository.findById(id)
			.orElseThrow(() -> new EntityNotFoundException(ErrorCode.USER_NOT_FOUND,
				MessageFormat.format("UserId = {0}", id)));

		return userConverter.toUserResponse(foundUser);
	}

	public FindProfileResponse findProfileById(Long id) {
		User foundUser = userRepository.findById(id)
			.orElseThrow(() -> new EntityNotFoundException(ErrorCode.USER_NOT_FOUND,
				MessageFormat.format("UserId = {0}", id)));

		String userLocalName = getUserLocalName(foundUser);

		MatchReviewTotalResponse review = matchReviewGiver.findTotalReviewByUserId(id);
		List<TeamSimpleResponse> teams = teamGiver.findAllByTeamMemberUserId(id);

		return FindProfileResponse.builder()
			.nickname(foundUser.getNickname())
			.profileImageUrl(foundUser.getProfileImageUrl())
			.email(foundUser.getEmail())
			.localName(userLocalName)
			.review(review)
			.teams(teams)
			.build();
	}

	private String getUserLocalName(User user) {
		if (user.getUserSettings() == null) {
			return null;
		}

		Double longitude = user.getUserSettings().getLocation().getLongitude();
		Double latitude = user.getUserSettings().getLocation().getLatitude();

		return kakaoApiService.coordToAddressResponse(longitude, latitude)
			.documents()
			.get(0)
			.address()
			.region3DepthName();
	}

	@Transactional
	public Long create(CreateUserRequest request) {
		User user = userConverter.toUser(request);

		return userRepository.save(user).getId();
	}

	public List<UserFindResponse> findAllByNickname(String nickname) {
		return userRepository.findByNicknameContaining(nickname).stream()
			.map(
				user -> new UserFindResponse(
					user.getId(),
					user.getUsername(),
					user.getNickname(),
					user.getProfileImageUrl()
				)
			)
			.toList();
	}

	@Transactional
	public UpdateUserSettingsResponse updateSettings(Long targetId,
		UpdateUserSettingsRequest request) {
		User foundUser = this.userRepository.findById(targetId)
			.orElseThrow(() -> new EntityNotFoundException(ErrorCode.USER_NOT_FOUND,
				MessageFormat.format("UserId = {0}", targetId)));
		CoordToAddressResponse coordToAddressResponse = kakaoApiService.coordToAddressResponse(request.longitude(),
			request.latitude());
		String localName = coordToAddressResponse.documents().get(0).address().region3DepthName();
		foundUser.updateSettings(request.latitude(), request.longitude(), localName, request.searchDistance());

		return new UpdateUserSettingsResponse(request.latitude(), request.longitude(), request.searchDistance());
	}

	public Boolean usernameDuplicationCheck(String username) {
		return userRepository.existsByUsername(username);
	}

	public Boolean nicknameDuplicationCheck(String nickname) {
		return userRepository.existsByNickname(nickname);
	}

	@Transactional
	public void update(Long targetId, UpdateUserByOAuthRequest request) {
		User foundUser = this.userRepository.findById(targetId)
			.orElseThrow(() -> new EntityNotFoundException(ErrorCode.USER_NOT_FOUND,
				MessageFormat.format("UserId = {0}", targetId)));
		foundUser.update(request.nickname(), request.email(), request.profileImageUrl());
	}

	@Transactional
	public void update(Long targetId, UpdateUserRequest request) {
		if (request.nickname() != null && nicknameDuplicationCheck(request.nickname())) {
			throw new BusinessException(ErrorCode.USER_DUPLICATED_NICKNAME,
				MessageFormat.format("already exists nickname : {0}", request.nickname()));
		}

		User foundUser = this.userRepository.findById(targetId)
			.orElseThrow(() -> new EntityNotFoundException(ErrorCode.USER_NOT_FOUND,
				MessageFormat.format("UserId = {0}", targetId)));

		foundUser.update(request.nickname(), null, null);
	}

	@Transactional
	public String uploadProfile(Long id, MultipartFile file) {
		User foundUser = this.userRepository.findById(id)
			.orElseThrow(() -> new EntityNotFoundException(ErrorCode.USER_NOT_FOUND,
				MessageFormat.format("UserId = {0}", id)));

		return Optional.ofNullable(foundUser.getProfileImageUrl())
			.map(
				key -> {
					s3Uploader.uploadByKey(file.getResource(), key);
					return key;
				}
			).orElseGet(() -> {
				String url = s3Uploader.uploadByPath(file.getResource(), ImagePath.USERS_PROFILES);
				foundUser.updateImageUrl(url);
				return url;
			});
	}

}
