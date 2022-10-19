package com.kdt.team04.domain.user.entity;

import javax.persistence.Access;
import javax.persistence.AccessType;
import javax.persistence.Embeddable;
import javax.persistence.Embedded;

@Embeddable
@Access(AccessType.FIELD)
public class UserSettings {

	@Embedded
	private Location location;
	private Integer searchDistance;

	protected UserSettings() {
	}

	public UserSettings(Double latitude, Double longitude, Integer searchDistance) {
		this.location = new Location(latitude, longitude);
		this.searchDistance = searchDistance;
	}

	public UserSettings(Double latitude, Double longitude, String localName, Integer searchDistance) {
		this.location = new Location(latitude, longitude, localName);
		this.searchDistance = searchDistance;
	}

	public Location getLocation() {
		return this.location;
	}

	public Integer getSearchDistance() {
		return this.searchDistance;
	}

}
