package com.kdt.team04.domain.user.entity;

import static com.google.common.base.Preconditions.checkArgument;

import javax.persistence.Column;
import javax.persistence.Embedded;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import com.kdt.team04.domain.BaseEntity;
import com.kdt.team04.domain.user.Role;

import lombok.Builder;

@Table(name = "users")
@Entity
public class User extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotBlank
	private String password;

	@NotBlank
	@Column(unique = true)
	@Pattern(regexp = "^[a-z0-9_]*$")
	@Size(min = 6, max = 64)
	private String username;

	@NotBlank
	@Pattern(regexp = "^[가-힣|a-z|A-Z|0-9|_.#]+$")
	@Size(min = 2, max = 40)
	@Column(unique = true)
	private String nickname;

	@Embedded
	private UserSettings userSettings;

	@Email
	private String email;

	private String profileImageUrl;

	@Enumerated(EnumType.STRING)
	private Role role;

	protected User() {
	}

	public User(String username, String nickname, String password) {
		this(null, password, username, nickname, null, null, null, Role.USER);
	}

	@Builder
	public User(Long id, String password, String username, String nickname, UserSettings userSettings, String email,
		String profileImageUrl, Role role) {
		this.id = id;
		this.password = password;
		this.username = username;
		this.nickname = nickname;
		this.userSettings = userSettings;
		this.email = email;
		this.profileImageUrl = profileImageUrl;
		this.role = role;
	}

	public Long getId() {
		return id;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public String getNickname() {
		return nickname;
	}

	public String getEmail() {
		return email;
	}

	public String getProfileImageUrl() {
		return profileImageUrl;
	}

	public Role getRole() {
		return role;
	}

	public UserSettings getUserSettings() {
		return userSettings;
	}

	public void updateSettings(Double latitude, Double longitude, String localName, Integer searchDistance) {
		checkArgument(latitude != null, "latitude must be provided");
		checkArgument(longitude != null, "longitude must be provided");
		checkArgument(localName != null, "localName must be provided");
		checkArgument(searchDistance != null, "search distance must be provided");
		this.userSettings = new UserSettings(latitude, longitude, localName, searchDistance);
	}

	public User update(String nickname, String email, String profileImageUrl) {
		this.nickname = nickname != null ? nickname : this.nickname;
		this.email = email != null ? email : this.email;
		this.profileImageUrl = profileImageUrl != null ? profileImageUrl : this.profileImageUrl;

		return this;
	}

	public void updateImageUrl(String profileImageUrl) {
		this.profileImageUrl = profileImageUrl;
	}

	@Override
	public String toString() {
		return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
			.append("id", id)
			.append("username", username)
			.append("nickname", nickname)
			.append("userSettings", userSettings)
			.toString();
	}
}
