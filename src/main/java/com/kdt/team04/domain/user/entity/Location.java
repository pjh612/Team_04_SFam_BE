package com.kdt.team04.domain.user.entity;

import javax.persistence.Access;
import javax.persistence.AccessType;
import javax.persistence.Embeddable;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

@Embeddable
@Access(AccessType.FIELD)
public class Location {

	private Double latitude;
	private Double longitude;
	private String localName;

	protected Location() {
	}

	public Location(Double latitude, Double longitude) {
		this.latitude = latitude;
		this.longitude = longitude;
	}

	public Location(Double latitude, Double longitude, String localName) {
		this.latitude = latitude;
		this.longitude = longitude;
		this.localName = localName;
	}

	public Double getLatitude() {
		return this.latitude;
	}

	public Double getLongitude() {
		return this.longitude;
	}

	public String getLocalName() {
		return localName;
	}

	@Override
	public String toString() {
		return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
			.append("latitude", latitude)
			.append("longitude", longitude)
			.toString();
	}
}
