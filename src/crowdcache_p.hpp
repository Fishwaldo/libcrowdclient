/* crowd-c++ - crowdcache.hpp
** Copyright (c) 2014 Justin Hammond
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
**  USA
**
** crowd-c++ SVN Identification:
** $Rev$
*/

/** @file crowdcache.hpp
 *  @brief
 */



#ifndef CROWDCACHE_HPP_
#define CROWDCACHE_HPP_

#include "crowdclient.hpp"


struct PrincipleCache_t {
		time_t added;
		bool fullresults;
		PrincipleDetails principle;
};

struct GroupCache_t {
		time_t added;
		bool fullresults;
		GroupDetails group;
};

struct IsGroupMemberCache_t {
		time_t added;
		bool result;
};

struct PrincipleGroups_t {
		time_t added;
		std::vector<std::string> groups;
};


struct Statistics_t {
		int PrincipleCacheHits;
		int PrincipleCacheMisses;
		int TokenMapHits;
		int TokenMapMisses;
		int IsGroupMemberHits;
		int IsGroupMemberMisses;
		int PrincipleGroupsHits;
		int PrincipleGroupsMisses;
		int AllGroupsHits;
		int AllGroupsMisses;
		int ApplicationGroupsHits;
		int ApplicationGroupsMisses;
		int GroupHits;
		int GroupMisses;
		int AllUsersHits;
		int AllUsersMisses;
};

class CrowdCache {
public:
		CrowdCache();
		~CrowdCache();

		void setTimeout(int timeout);
		int getTimeout();

		void checkAllCaches();
		void invalidateGroupCaches();

		void setPrincipleCache(std::string username, PrincipleDetails pd, bool full);
		CrowdClientReturnCodes getPrincipleCache(std::string username, PrincipleDetails attributes, bool full);
		void invalidatePrincipleCache(std::string username);

		CrowdClientReturnCodes getPrincipleTokenCache(std::string token, PrincipleDetails attributes, bool full);
		void setPrincipleTokenCache(std::string token, PrincipleDetails pd, bool full);
		void invalidatePrincipleTokenCache(std::string token);

		void setIsGroupMemberCache(std::string group, std::string member, bool result);
		CrowdClientReturnCodes getIsGroupMemberCache(std::string group, std::string member, bool *result);
		void invalidateIsGroupMemberCache(std::string group, std::string member);

		void setPrincipleGroupsCache(std::string username, std::vector<std::string> groups);
		CrowdClientReturnCodes getPrincipleGroupsCache(std::string group, std::vector<std::string> *groups);
		void invalidatePrincipleGroupCache(std::string username);

		void setAllGroupsCache(std::vector<std::string> groups);
		CrowdClientReturnCodes getAllGroupsCache(std::vector<std::string> *groups);
		void invalidateAllGroupCache();

		void setApplicationGroupsCache(std::vector<std::string> groups);
		CrowdClientReturnCodes getApplicationGroupsCache(std::vector<std::string> *groups);
		void invalidateApplicationGroupCache();

		void setGroupCache(std::string group, GroupDetails gd, bool full);
		CrowdClientReturnCodes getGroupCache(std::string group, GroupDetails gd, bool full);
		void invalidateGroupCache(std::string group);

		void setAllUsersCache(std::vector<std::string> groups);
		CrowdClientReturnCodes getAllUsersCache(std::vector<std::string> *users);
		void invalidateAllUsersCache();

private:
		std::map<std::string, PrincipleCache_t *> PrincipleCache;
		std::map<std::string, std::string> TokenMap;
		std::map<std::string, IsGroupMemberCache_t *> IsGroupMemberCache;
		std::map<std::string, PrincipleGroups_t *> PrincipleGroupsCache;
		PrincipleGroups_t AllGroupsCache;
		PrincipleGroups_t ApplicationGroupsCache;
		std::map<std::string, GroupCache_t *> GroupCache;
		PrincipleGroups_t AllUsersCache;
		int timeout;
		Statistics_t stats;

};




#endif /* CROWDCACHE_HPP_ */
