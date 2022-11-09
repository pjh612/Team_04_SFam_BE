package com.kdt.team04.domain.matches.proposal.entity;

import static com.kdt.team04.domain.matches.proposal.entity.MatchProposalStatus.WAITING;
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

import java.text.MessageFormat;

import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import com.kdt.team04.common.exception.BusinessException;
import com.kdt.team04.common.exception.ErrorCode;
import com.kdt.team04.domain.BaseEntity;
import com.kdt.team04.domain.matches.match.model.entity.Match;
import com.kdt.team04.domain.teams.team.model.entity.Team;
import com.kdt.team04.domain.user.entity.User;

import lombok.Builder;

@Entity
public class MatchProposal extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "match_id")
	private Match match;

	private String content;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "user_id")
	private User user;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "team_id")
	private Team team;

	@Enumerated(value = EnumType.STRING)
	private MatchProposalStatus status;

	protected MatchProposal() {/*no-op*/}

	@Builder
	public MatchProposal(Long id, Match match, String content, User user, Team team, MatchProposalStatus status) {
		this.id = id;
		this.match = match;
		this.content = content;
		this.user = user;
		this.team = team;
		this.status = defaultIfNull(status, WAITING);
	}

	public void updateStatus(MatchProposalStatus status) {
		if(!this.status.isWaiting() || status.isFixed()) {
			throw new BusinessException(ErrorCode.PROPOSAL_INVALID_REACT,
				MessageFormat.format("proposal {1} status can't be {2} from {3}", this.id, status, this.status));
		}

		this.status = status;
	}

	public Long getId() {
		return id;
	}

	public Match getMatch() {
		return match;
	}

	public String getContent() {
		return content;
	}

	public User getUser() {
		return user;
	}

	public Team getTeam() {
		return team;
	}

	public MatchProposalStatus getStatus() {
		return status;
	}

	@Override
	public String toString() {
		return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
			.append("id", id)
			.append("match", match)
			.append("content", content)
			.append("user", user)
			.append("team", team)
			.append("status", status)
			.toString();
	}
}
