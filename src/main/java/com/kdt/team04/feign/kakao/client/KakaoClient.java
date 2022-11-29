package com.kdt.team04.feign.kakao.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

import com.kdt.team04.common.config.FeignConfig;
import com.kdt.team04.feign.kakao.dto.CoordToAddressResponse;

@FeignClient(name = "kakao", url = "https://dapi.kakao.com/v2", configuration = FeignConfig.class)
public interface KakaoClient {

	@GetMapping("/local/geo/coord2address.json?input_coord=WGS84")
	CoordToAddressResponse coordToAddress(
		@RequestHeader("Authorization") String kakaoAk,
		@RequestParam(name = "x") Double longitude,
		@RequestParam(name = "y") Double latitude);
}
