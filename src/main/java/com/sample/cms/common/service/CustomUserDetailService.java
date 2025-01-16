package com.sample.cms.common.service;

import com.sample.cms.common.dto.CustomUser;
import com.sample.cms.common.exception.ApiException;
import com.sample.cms.common.type.ApiStatus;
import com.sample.cms.domain.entity.CmsUser;
import com.sample.cms.domain.repository.CmsUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomUserDetailService implements UserDetailsService {

  private final CmsUserRepository cmsUserRepository;

  @Override
  public UserDetails loadUserByUsername(String userId) {
    CmsUser cmsUser = cmsUserRepository.findByUserId(userId)
        .orElseThrow(() -> new ApiException(ApiStatus.INVALID_REQUEST));
    log.debug("cmsUser : {}", cmsUser);
    return new CustomUser(cmsUser);
  }
}
