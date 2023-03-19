package com.zerobase.stock.persist;

import com.zerobase.stock.model.MemberEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MemberRepository extends JpaRepository<MemberEntity, Long> {

	Optional<MemberEntity> findByUsername(String username);

	boolean existsByUsername(String username);

}
