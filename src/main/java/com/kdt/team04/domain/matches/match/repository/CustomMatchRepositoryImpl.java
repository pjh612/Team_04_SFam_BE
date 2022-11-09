package com.kdt.team04.domain.matches.match.repository;

import static com.kdt.team04.domain.matches.match.model.entity.QMatch.match;
import static com.kdt.team04.domain.user.entity.QUser.user;
import static com.querydsl.core.types.dsl.Expressions.asNumber;
import static com.querydsl.core.types.dsl.MathExpressions.acos;
import static com.querydsl.core.types.dsl.MathExpressions.cos;
import static com.querydsl.core.types.dsl.MathExpressions.radians;
import static com.querydsl.core.types.dsl.MathExpressions.sin;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import com.kdt.team04.common.PageDto;
import com.kdt.team04.domain.matches.match.dto.MatchPagingCursor;
import com.kdt.team04.domain.matches.match.dto.response.QueryMatchListResponse;
import com.kdt.team04.domain.matches.match.model.MatchStatus;
import com.kdt.team04.domain.teams.team.model.SportsCategory;
import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.Projections;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.core.types.dsl.NumberExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;

public class CustomMatchRepositoryImpl implements CustomMatchRepository {

	private final JPAQueryFactory jpaQueryFactory;

	public CustomMatchRepositoryImpl(JPAQueryFactory jpaQueryFactory) {
		this.jpaQueryFactory = jpaQueryFactory;
	}

	public PageDto.CursorResponse<QueryMatchListResponse, MatchPagingCursor> findByLocationPaging(
		Double latitude, Double longitude, PageDto.MatchCursorPageRequest pageRequest) {
		Double distance = pageRequest.getDistance();
		Integer size = pageRequest.getSize();
		SportsCategory category = pageRequest.getCategory();
		Long id = pageRequest.getId();
		LocalDateTime createdAt = pageRequest.getCreatedAt();
		MatchStatus status = pageRequest.getStatus();
		Long userId = pageRequest.getUserId();

		NumberExpression<Double> distanceExpression = asNumber(6371.0)
			.multiply(acos(cos(radians(asNumber(latitude))).multiply(cos(radians(match.location.latitude)))
				.multiply(cos(radians(match.location.longitude).subtract(radians(asNumber(longitude)))))
				.add(sin(radians(asNumber(latitude))).multiply(sin(radians(match.location.latitude))))));

		BooleanBuilder where = new BooleanBuilder();

		BooleanExpression categoryCondition = Optional.ofNullable(category)
			.map(match.sportsCategory::eq)
			.orElse(null);

		BooleanExpression distanceCondition = Optional.ofNullable(distance)
			.map(distanceExpression::lt)
			.orElse(distanceExpression.lt(40.0));

		BooleanExpression distanceOrUserIdCondition = Optional.ofNullable(userId)
			.map(match.user.id::eq)
			.orElse(distanceCondition);

		BooleanExpression statusCondition = Optional.ofNullable(status)
			.map(match.status::eq)
			.orElse(null);

		BooleanExpression cursorCondition = null;

		if (createdAt != null && id != null) {
			cursorCondition = match.createdAt.lt(createdAt)
				.or(match.createdAt.eq(createdAt).and(match.id.lt(id)));
		}
		List<QueryMatchListResponse> matches = jpaQueryFactory.select(
				Projections.constructor(QueryMatchListResponse.class,
					match.id,
					match.title,
					match.sportsCategory,
					match.matchType,
					match.content,
					match.user.id,
					match.user.nickname,
					match.location.latitude,
					match.location.longitude,
					match.location.localName,
					distanceExpression.as("distance"),
					match.matchDate,
					match.createdAt
				)
			)
			.from(match)
			.leftJoin(match.user, user)
			.where(where.and(distanceOrUserIdCondition)
				.and(categoryCondition)
				.and(statusCondition)
				.and(cursorCondition))
			.orderBy(match.createdAt.desc(), match.id.desc())
			.limit(size)
			.fetch();

		LocalDateTime nextCreatedAtCursor = matches.isEmpty() ? null : matches.get(matches.size() - 1).createdAt();
		Long nextIdCursor = matches.isEmpty() ? null : matches.get(matches.size() - 1).id();
		Boolean hasNext = hasNext(nextCreatedAtCursor, nextIdCursor, category, status);

		return new PageDto.CursorResponse<>(matches, hasNext, new MatchPagingCursor(nextCreatedAtCursor, nextIdCursor));
	}

	private Boolean hasNext(LocalDateTime createdAtCursor, Long idCursor, SportsCategory sportsCategory,
		MatchStatus status) {
		if (createdAtCursor == null || idCursor == null) {
			return false;
		}
		BooleanBuilder where = new BooleanBuilder();

		BooleanExpression categoryCondition = Optional.ofNullable(sportsCategory)
			.map(match.sportsCategory::eq)
			.orElse(null);

		BooleanExpression statusCondition = Optional.ofNullable(status)
			.map(match.status::eq)
			.orElse(null);

		return jpaQueryFactory.selectFrom(match)
			.where(where.and(categoryCondition).and(statusCondition)
				.and(match.createdAt.loe(createdAtCursor)
					.and(match.id.lt(idCursor))
				))
			.fetchFirst() != null;
	}

	@Override
	public Double getDistance(Double latitude, Double longitude, Long matchId) {
		NumberExpression<Double> distanceExpression = asNumber(6371.0)
			.multiply(acos(cos(radians(asNumber(latitude))).multiply(cos(radians(match.location.latitude)))
				.multiply(cos(radians(match.location.longitude).subtract(radians(asNumber(longitude)))))
				.add(sin(radians(asNumber(latitude))).multiply(sin(radians(match.location.latitude))))));

		return jpaQueryFactory.select(distanceExpression)
			.from(match)
			.where(match.id.eq(matchId))
			.fetchOne();
	}
}