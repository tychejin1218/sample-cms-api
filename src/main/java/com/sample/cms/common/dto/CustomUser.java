package com.sample.cms.common.dto;

import com.sample.cms.domain.entity.CmsUser;
import java.io.Serial;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

@Getter
@Setter
@ToString
public class CustomUser extends User {

  @Serial
  private static final long serialVersionUID = -6746075231392948543L;

  private transient CmsUser cmsUser;

  public CustomUser(CmsUser cmsUser) {
    super(cmsUser.getUsername(), cmsUser.getPassword(), getAuthorities(cmsUser.getRoles()));
    this.cmsUser = cmsUser;
  }

  public static Collection<GrantedAuthority> getAuthorities(String roles) {
    return Arrays.stream(roles.split(",")).toList()
        .stream()
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toList());
  }
}
