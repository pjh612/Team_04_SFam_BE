package com.kdt.team04.domain.teammember.dto;

import org.springframework.stereotype.Component;

import com.kdt.team04.domain.team.dto.TeamResponse;
import com.kdt.team04.domain.team.entity.Team;
import com.kdt.team04.domain.teammember.entity.TeamMember;
import com.kdt.team04.domain.user.dto.UserResponse;
import com.kdt.team04.domain.user.entity.User;

@Component
public class TeamMemberConverter {

	public User toUser(Long userId) {
		return User.builder()
			.id(userId)
			.build();
	}

	public Team toTeam(Long teamId) {
		return Team.builder()
			.id(teamId)
			.build();
	}

	public TeamMemberResponse toTeamMemberResponse(TeamMember teamMember) {
		return new TeamMemberResponse(teamMember.getUser().getId(), teamMember.getUser().getNickname(),
			teamMember.getRole());
	}
}
