package edu.adelaide.mapper;

import edu.adelaide.entity.Groups;

public interface GroupsMapper {
    int deleteByPrimaryKey(String groupId);

    int insert(Groups row);

    int insertSelective(Groups row);

    Groups selectByPrimaryKey(String groupId);

    int updateByPrimaryKeySelective(Groups row);

    int updateByPrimaryKeyWithBLOBs(Groups row);

    int updateByPrimaryKey(Groups row);
}