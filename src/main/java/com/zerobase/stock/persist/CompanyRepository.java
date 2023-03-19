package com.zerobase.stock.persist;

import com.zerobase.stock.persist.entity.CompanyEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CompanyRepository extends JpaRepository<CompanyEntity, Long> {
	boolean existsByTicker(String ticker);

	Optional<CompanyEntity> findByName(String name);

	Optional<CompanyEntity> findByTicker(String ticker);
}
