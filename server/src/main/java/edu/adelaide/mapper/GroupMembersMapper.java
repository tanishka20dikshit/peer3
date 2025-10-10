package edu.adelaide.mapper;

import edu.adelaide.entity.GroupMembers;
import edu.adelaide.entity.GroupMembersKey;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * Mapper for table `group_members` with composite PK.
 */
public interface GroupMembersMapper {

    int deleteByPrimaryKey(GroupMembersKey key);

    int insert(GroupMembers row);              // requires both PK fields set
    int insertSelective(GroupMembers row);     // requires both PK fields set

    GroupMembers selectByPrimaryKey(GroupMembersKey key);

    List<GroupMembers> queryAllActive();

    int updateByPrimaryKeySelective(GroupMembers row); // row must contain both PK fields
    int updateByPrimaryKey(GroupMembers row);          // row must contain both PK fields

    // edu.adelaide.mapper.GroupMembersMapper
    int upsertActive(
        @org.apache.ibatis.annotations.Param("groupId") String groupId,
        @org.apache.ibatis.annotations.Param("userId")  String userId,
        @org.apache.ibatis.annotations.Param("role")    String role,
        @org.apache.ibatis.annotations.Param("wrappedKey") String wrappedKey
    );


    /** Mark membership as LEFT (no delete, for audit). */
    int markLeft(@Param("groupId") String groupId,
                 @Param("userId") String userId);
}
