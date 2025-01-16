package com.sample.cms.domain.repository;

import com.sample.cms.domain.entity.CmsUser;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CmsUserRepository extends
    JpaRepository<CmsUser, Long> {

  Optional<CmsUser> findByUserId(String userId);

  Optional<CmsUser> findByUserIdAndPassword(String userId, String password);
}
