package com.itheima.pinda.authority.biz.service.auth.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.itheima.pinda.auth.server.utils.JwtTokenServerUtils;
import com.itheima.pinda.auth.utils.JwtUserInfo;
import com.itheima.pinda.auth.utils.Token;
import com.itheima.pinda.authority.biz.service.auth.ResourceService;
import com.itheima.pinda.authority.biz.service.auth.UserService;
import com.itheima.pinda.authority.dto.auth.LoginDTO;
import com.itheima.pinda.authority.dto.auth.ResourceQueryDTO;
import com.itheima.pinda.authority.dto.auth.UserDTO;
import com.itheima.pinda.authority.entity.auth.Resource;
import com.itheima.pinda.authority.entity.auth.User;
import com.itheima.pinda.base.R;
import com.itheima.pinda.common.constant.CacheKey;
import com.itheima.pinda.dozer.DozerUtils;
import com.itheima.pinda.exception.code.ExceptionCode;
import net.oschina.j2cache.CacheChannel;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * @author 安逸i
 * @version 1.0
 */
@Service
public class AuthManager {

    @Autowired
    private UserService userService;

    @Autowired
    private DozerUtils dozer;

    @Autowired
    private ResourceService resourceService;

    @Autowired
    private JwtTokenServerUtils jwtTokenServerUtils;

    @Autowired
    private CacheChannel cacheChannel;

    /**
     * 登录验证
     * @param account
     * @param password
     * @return
     */
    public R<LoginDTO> login(String account, String password) {

        R<User> userR = check(account,password);
        // 生成token，写入到返回对象
        User user = userR.getData();
        Token token = getToken(user);
        // 封装前端使用的限权列表写入到返回对象
        List<Resource> resourceList = resourceService.findVisibleResource(ResourceQueryDTO.builder().
                userId(user.getId()).build());
        List<String> permissionsList = null;

        if (resourceList != null || resourceList.size() > 0){
            // 封装返回给前端的限权列表
            permissionsList = resourceList.stream().map(Resource::getCode)
                    .collect(Collectors.toList());

            // 封装给网关使用的限权列表
            List<String> visibleResource = resourceList.stream().map(item -> {
                return item.getMethod() + item.getUrl();
            }).collect(Collectors.toList());
            cacheChannel.set(CacheKey.USER_RESOURCE, user.getId().toString(), visibleResource);
        }


        LoginDTO loginDTO = LoginDTO.builder()
                .user(this.dozer.map(user, UserDTO.class))
                .token(token)
                .permissionsList(permissionsList)
                .build();

        // 将限权列表存入到缓存中
        return R.success(loginDTO);
    }

    /**
     * 获取token
     * @param user
     * @return
     */
    private Token getToken(User user) {

        // 生成token有效部分
        JwtUserInfo jwtUserInfo = new JwtUserInfo(
                user.getId(),
                user.getAccount(),
                user.getName(),
                user.getOrgId(),
                user.getStationId()
        );
        Token token = jwtTokenServerUtils.generateUserToken(jwtUserInfo, null);
        return token;
    }

    /**
     * 校验账号密码
     * @param account
     * @param password
     * @return
     */
    private R<User> check(String account, String password) {

        // 查询用户信息
        User user = userService.getOne(new LambdaQueryWrapper<User>()
                .eq(User::getAccount, account));

        // 密码加密
        String passwordMd5 = DigestUtils.md5Hex(password);

        if (user == null || !user.getPassword().equals(passwordMd5)) {
            return R.fail(ExceptionCode.JWT_USER_INVALID);
        }

        return R.success(user);
    }
}
