package com.kdt.team04.domain.user.entity;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.kdt.team04.domain.user.Role;

class UserTest {

	@Test
	@DisplayName("유저 세팅 정보 업데이트 성공")
	void updateUserSettingsSuccess() {
		//given
		User user = User.builder()
			.id(1L)
			.username("test1234")
			.nickname("nickname1234")
			.userSettings(null)
			.email("test1234@gmail.com")
			.profileImageUrl(null)
			.role(Role.USER)
			.build();

		Double latitude = 33.0;
		Double longitude = 120.0;
		Integer searchDistance = 25;

		//when
		user.updateSettings(latitude, longitude, "테스트동",searchDistance);

		//then
		Assertions.assertThat(user.getUserSettings().getLocation().getLatitude()).isEqualTo(latitude);
		Assertions.assertThat(user.getUserSettings().getLocation().getLongitude()).isEqualTo(longitude);
		Assertions.assertThat(user.getUserSettings().getSearchDistance()).isEqualTo(searchDistance);
	}

	@Test
	@DisplayName("위치 정보가 NULL이면 업데이트할 수 없다.")
	void updateUserSettingsNullLocationFail() {
		//given
		User user = User.builder()
			.id(1L)
			.username("test1234")
			.nickname("nickname1234")
			.userSettings(null)
			.email("test1234@gmail.com")
			.profileImageUrl(null)
			.role(Role.USER)
			.build();

		Integer searchDistance = 25;

		//when, then
		Assertions.assertThatThrownBy(() -> user.updateSettings(null, null,"테스트동", searchDistance))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	@DisplayName("조회 거리 정보가 NULL이면 업데이트할 수 없다.")
	void updateUserSettingsNullSearchDistanceFail() {
		//given
		User user = User.builder()
			.id(1L)
			.username("test1234")
			.nickname("nickname1234")
			.userSettings(null)
			.email("test1234@gmail.com")
			.profileImageUrl(null)
			.role(Role.USER)
			.build();

		Double latitude = 33.0;
		Double longitude = 120.0;

		//when, then
		Assertions.assertThatThrownBy(() -> user.updateSettings(latitude, longitude, "테스트동",null))
			.isInstanceOf(IllegalArgumentException.class);
	}
}