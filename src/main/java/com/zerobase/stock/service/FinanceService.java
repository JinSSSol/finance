package com.zerobase.stock.service;

import com.zerobase.stock.model.Company;
import com.zerobase.stock.model.Dividend;
import com.zerobase.stock.model.ScrapedResult;
import com.zerobase.stock.model.constants.CacheKey;
import com.zerobase.stock.persist.CompanyRepository;
import com.zerobase.stock.persist.DividendRepository;
import com.zerobase.stock.persist.entity.CompanyEntity;
import com.zerobase.stock.persist.entity.DividendEntity;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class FinanceService {

	private final CompanyRepository companyRepository;
	private final DividendRepository dividendRepository;

	@Cacheable(key = "#companyName", value = CacheKey.KEY_FINANCE)
	public ScrapedResult getDividendByCompanyName(String companyName) {
		// 1. 회사명을 기준으로 회사 정보를 조회
		CompanyEntity company = this.companyRepository.findByName(companyName)
			.orElseThrow(() -> new RuntimeException("존재하지 않는 회사입니다."));

		// 2. 조회한 회사 Id로 배당금 정보 조회
		List<DividendEntity> dividendEntities = this.dividendRepository.findAllByCompanyId(
			company.getId());

		// 3. 결과 조합 후 반환
		List<Dividend> dividends = dividendEntities.stream()
													.map(e -> new Dividend(e.getDate(), e.getDividend()))
													.collect(Collectors.toList());

		return new ScrapedResult(new Company(company.getTicker(), company.getName()), dividends);

	}

}
