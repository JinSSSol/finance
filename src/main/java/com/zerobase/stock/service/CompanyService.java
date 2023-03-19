package com.zerobase.stock.service;

import com.zerobase.stock.exception.impl.NoCompanyException;
import com.zerobase.stock.model.Company;
import com.zerobase.stock.model.ScrapedResult;
import com.zerobase.stock.persist.CompanyRepository;
import com.zerobase.stock.persist.DividendRepository;
import com.zerobase.stock.persist.entity.CompanyEntity;
import com.zerobase.stock.persist.entity.DividendEntity;
import com.zerobase.stock.scraper.Scraper;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import org.apache.commons.collections4.Trie;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

@Service
@AllArgsConstructor
public class CompanyService {

	private final Trie trie;
	private final Scraper yahooFinanceScrapper;
	private final CompanyRepository companyRepository;
	private final DividendRepository dividendRepository;

	public Company save(String ticker) {
		boolean exists = this.companyRepository.existsByTicker(ticker);
		if (exists) {
			throw new RuntimeException("already exists ticker -> " + ticker);
		}
		return this.storeCompanyAndDividend(ticker);
	}

	public Page<CompanyEntity> getAllCompany(Pageable pageable) {
		return this.companyRepository.findAll(pageable);
	}

	private Company storeCompanyAndDividend(String ticker) {
		// ticker 기준 회사 스크래핑
		Company company = this.yahooFinanceScrapper.scrapCompanyByTicker(ticker);
		if (ObjectUtils.isEmpty(company)) {
			throw new RuntimeException("failed to scrap ticker -> " + ticker);
		}

		// 해당 회사 존재할 경우, 회사의 배당금 정보를 스크래핑
		ScrapedResult scrapedResult = this.yahooFinanceScrapper.scrap(company);

		// 스크래핑 결과
		CompanyEntity companyEntity = this.companyRepository.save(new CompanyEntity(company));
		List<DividendEntity> dividendEntities = scrapedResult.getDividends().stream()
			.map(e -> new DividendEntity(companyEntity.getId(), e))
			.collect(Collectors.toList());

		this.dividendRepository.saveAll(dividendEntities);
		return company;
	}

	public void addAutocompleteKeyword(String keyword) {
		this.trie.put(keyword, null);
	}

	public List<String> autocomplete(String keyword) {
		return (List<String>) this.trie.prefixMap(keyword).keySet()
			.stream()
			.limit(10)
			.collect(Collectors.toList());
	}

	public void deleteAutocompleteKeyword(String keyword) {
		this.trie.remove(keyword);
	}

	public String deleteCompany(String ticker) {
		var company = this.companyRepository.findByTicker(ticker)
			.orElseThrow(() -> new NoCompanyException());

		this.dividendRepository.deleteAllByCompanyId(company.getId());
		this.companyRepository.delete(company);

		this.deleteAutocompleteKeyword(company.getName());
		return company.getName();
	}
}
