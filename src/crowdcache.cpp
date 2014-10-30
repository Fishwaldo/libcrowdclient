/* crowd-c++ - crowdcache.cpp
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

/** @file crowdcache.cpp
 *  @brief
 */

#include "crowdcache_p.hpp"

#include <iostream>


CrowdCache::CrowdCache() :
timeout(0)
{

}
CrowdCache::~CrowdCache() {

}

void CrowdCache::setTimeout(int timeout) {
	this->timeout = timeout;
	this->checkAllCaches();
}

int CrowdCache::getTimeout() {
	return this->timeout;
}

void CrowdCache::checkAllCaches() {
	time_t now = time(NULL);
	for (std::map<std::string, PrincipleCache_t *>::iterator it = this->PrincipleCache.begin(); it != this->PrincipleCache.end(); it++) {
		if (difftime((long)now, (long)it->second->added) > this->timeout) {
			delete it->second;
			this->PrincipleCache.erase(it);
		}
	}
	for (std::map<std::string, PrincipleGroups_t *>::iterator it = this->PrincipleGroupsCache.begin(); it != this->PrincipleGroupsCache.end(); it++) {
		if (difftime((long)now, (long)it->second->added) > this->timeout) {
			delete it->second;
			this->PrincipleGroupsCache.erase(it);
		}
	}
	for (std::map<std::string, IsGroupMemberCache_t *>::iterator it = this->IsGroupMemberCache.begin(); it != this->IsGroupMemberCache.end(); it++) {
		if (difftime((long)now, (long)it->second->added) > this->timeout) {
			delete it->second;
			this->IsGroupMemberCache.erase(it);
		}
	}
	for (std::map<std::string, GroupCache_t *>::iterator it = this->GroupCache.begin(); it != this->GroupCache.end(); it++) {
		if (difftime((long)now, (long)it->second->added) > this->timeout) {
			delete it->second;
			this->GroupCache.erase(it);
		}
	}
	if (difftime((long)time(NULL), this->AllGroupsCache.added) > this->timeout) {
		this->AllGroupsCache.added = 0;
		this->AllGroupsCache.groups.clear();
	}
	if (difftime((long)time(NULL), this->AllGroupsCache.added) > this->timeout) {
		this->ApplicationGroupsCache.added = 0;
		this->ApplicationGroupsCache.groups.clear();
	}
	if (difftime((long)time(NULL), this->AllUsersCache.added) > this->timeout) {
		this->AllUsersCache.added = 0;
		this->AllUsersCache.groups.clear();
	}
}
void CrowdCache::invalidateGroupCaches() {
	for (std::map<std::string, IsGroupMemberCache_t *>::iterator it = this->IsGroupMemberCache.begin(); it != this->IsGroupMemberCache.end(); it++) {
		delete it->second;
		this->IsGroupMemberCache.erase(it);
	}
	for (std::map<std::string, GroupCache_t *>::iterator it = this->GroupCache.begin(); it != this->GroupCache.end(); it++) {
		delete it->second;
		this->GroupCache.erase(it);
	}
	for (std::map<std::string, PrincipleGroups_t *>::iterator it = this->PrincipleGroupsCache.begin(); it != this->PrincipleGroupsCache.end(); it++) {
		delete it->second;
		this->PrincipleGroupsCache.erase(it);
	}
	if (difftime((long)time(NULL), this->AllGroupsCache.added) > this->timeout) {
		this->AllGroupsCache.added = 0;
		this->AllGroupsCache.groups.clear();
	}
	if (difftime((long)time(NULL), this->AllGroupsCache.added) > this->timeout) {
		this->ApplicationGroupsCache.added = 0;
		this->ApplicationGroupsCache.groups.clear();
	}
}


void CrowdCache::setPrincipleCache(std::string username, PrincipleDetails pd, bool full) {
	if (timeout == 0)
		return;
	PrincipleCache_t *pc = new PrincipleCache_t;
	pc->added = time(0);
	pc->principle = pd;
	pc->fullresults = full;
	this->PrincipleCache[username] = pc;
}

void CrowdCache::setPrincipleTokenCache(std::string token, PrincipleDetails pd, bool full) {
	if (timeout == 0)
		return;
	this->setPrincipleCache(pd->name, pd, full);
	this->TokenMap[token] = pd->name;
}
CrowdClientReturnCodes CrowdCache::getPrincipleCache(std::string username, PrincipleDetails attributes, bool full) {
	if (timeout == 0)
		return CROWD_NAK;
	if (this->PrincipleCache.find(username) == this->PrincipleCache.end()) {
		this->stats.PrincipleCacheMisses++;
		return CROWD_NAK;
	}
	PrincipleCache_t *pc;
	pc = this->PrincipleCache[username];
	if (difftime((long)time(NULL), pc->added) > this->timeout) {
		/* Timeout */
		this->PrincipleCache.erase(username);
		delete pc;
		this->stats.PrincipleCacheMisses++;
		return CROWD_NAK;
	}
	if ((full) & (pc->fullresults != true)) {
		this->stats.PrincipleCacheMisses++;
		return CROWD_NAK;
	}
	attributes->active = pc->principle->active;
	attributes->attributes = pc->principle->attributes;
	attributes->conception = pc->principle->conception;
	attributes->description = pc->principle->description;
	attributes->directoryId = pc->principle->directoryId;
	attributes->id = pc->principle->id;
	attributes->lastModified = pc->principle->lastModified;
	attributes->name = pc->principle->name;
	this->stats.PrincipleCacheHits++;
	return CROWD_OK;
}

CrowdClientReturnCodes CrowdCache::getPrincipleTokenCache(std::string token, PrincipleDetails attributes, bool full) {
	if (this->TokenMap.find(token) == this->TokenMap.end()) {
		this->stats.TokenMapMisses++;
		return CROWD_NAK;
	}
	if (this->getPrincipleCache(this->TokenMap[token], attributes, full) == CROWD_NAK) {
		this->TokenMap.erase(token);
		this->stats.TokenMapMisses++;
		return CROWD_NAK;
	}
	this->stats.TokenMapHits++;
	return CROWD_OK;
}
void CrowdCache::invalidatePrincipleTokenCache(std::string token) {
	if (this->TokenMap.find(token) == this->TokenMap.end()) {
		return;
	}
	this->TokenMap.erase(token);
}


void CrowdCache::invalidatePrincipleCache(std::string username) {
	if (this->PrincipleCache.find(username) == this->PrincipleCache.end()) {
		return;
	}
	delete this->PrincipleCache[username];
	this->PrincipleCache.erase(username);
	return;
}


void CrowdCache::setIsGroupMemberCache(std::string group, std::string member, bool result) {
	if (this->timeout == 0)
		return;
	IsGroupMemberCache_t *igm = new IsGroupMemberCache_t;
	igm->added = time(0);
	igm->result = result;
	if (this->IsGroupMemberCache.count(group+"-"+member) > 0)
		delete this->IsGroupMemberCache[group+"-"+member];
	this->IsGroupMemberCache[group+"-"+member] = igm;
}
CrowdClientReturnCodes CrowdCache::getIsGroupMemberCache(std::string group, std::string member, bool *result) {
	if (timeout == 0)
		return CROWD_NAK;
	if (this->IsGroupMemberCache.find(group+"-"+member) == this->IsGroupMemberCache.end()) {
		this->stats.IsGroupMemberMisses++;
		return CROWD_NAK;
	}
	IsGroupMemberCache_t *igm;
	igm = this->IsGroupMemberCache[group+"-"+member];
	if (difftime((long)time(NULL), igm->added) > this->timeout) {
		/* Timeout */
		this->IsGroupMemberCache.erase(group+"-"+member);
		delete igm;
		this->stats.IsGroupMemberMisses++;
		return CROWD_NAK;
	}
	*result = igm->result;
	this->stats.IsGroupMemberHits++;
	return CROWD_OK;
}

void CrowdCache::invalidateIsGroupMemberCache(std::string group, std::string member) {
	if (this->timeout == 0)
		return;
	if (this->IsGroupMemberCache.find(group+"-"+member) == this->IsGroupMemberCache.end()) {
		return;
	}
	delete this->IsGroupMemberCache[group+"-"+member];
	this->IsGroupMemberCache.erase(group+"-"+member);
	return;
}


void CrowdCache::setPrincipleGroupsCache(std::string username, std::vector<std::string> groups) {
	if (this->timeout == 0)
		return;
	PrincipleGroups_t *pg = new PrincipleGroups_t;
	pg->added = time(0);
	pg->groups = groups;
	if (this->PrincipleGroupsCache.count(username) > 0)
		delete this->PrincipleGroupsCache[username];
	this->PrincipleGroupsCache[username] = pg;
}
CrowdClientReturnCodes CrowdCache::getPrincipleGroupsCache(std::string username, std::vector<std::string> *groups) {
	if (timeout == 0)
		return CROWD_NAK;
	if (this->PrincipleGroupsCache.find(username) == this->PrincipleGroupsCache.end()) {
		this->stats.PrincipleGroupsMisses++;
		return CROWD_NAK;
	}
	PrincipleGroups_t *pg;
	pg = this->PrincipleGroupsCache[username];
	if (difftime((long)time(NULL), pg->added) > this->timeout) {
		/* Timeout */
		this->PrincipleGroupsCache.erase(username);
		delete pg;
		this->stats.PrincipleGroupsMisses++;
		return CROWD_NAK;
	}
	*groups = pg->groups;
	this->stats.PrincipleGroupsHits++;
	return CROWD_OK;

}
void CrowdCache::invalidatePrincipleGroupCache(std::string username) {
	if (this->timeout == 0)
		return;
	if (this->PrincipleGroupsCache.find(username) == this->PrincipleGroupsCache.end()) {
		return;
	}
	delete this->PrincipleGroupsCache[username];
	this->PrincipleGroupsCache.erase(username);
	return;
}

void CrowdCache::setAllGroupsCache(std::vector<std::string> groups) {
	if (this->timeout == 0)
		return;
	this->AllGroupsCache.added = time(0);
	this->AllGroupsCache.groups = groups;
}
CrowdClientReturnCodes CrowdCache::getAllGroupsCache(std::vector<std::string> *groups) {
	if (this->timeout == 0)
		return CROWD_NAK;
	if (difftime((long)time(NULL), this->AllGroupsCache.added) > this->timeout) {
		this->AllGroupsCache.added = 0;
		this->AllGroupsCache.groups.clear();
		this->stats.AllGroupsMisses++;
		return CROWD_NAK;
	}
	*groups = this->AllGroupsCache.groups;
	this->stats.AllGroupsHits++;
	return CROWD_OK;
}
void CrowdCache::invalidateAllGroupCache() {
	if (this->timeout == 0)
		return;
	this->AllGroupsCache.added = 0;
	this->AllGroupsCache.groups.clear();
}

void CrowdCache::setGroupCache(std::string group, GroupDetails igd, bool full) {
	if (this->timeout == 0)
		return;
	GroupCache_t *gc = new GroupCache_t;
	gc->added = time(0);
	gc->group = igd;
	gc->fullresults = full;
	this->GroupCache[group] = gc;
}
CrowdClientReturnCodes CrowdCache::getGroupCache(std::string group, GroupDetails igd, bool full) {
	if (this->timeout == 0)
		return CROWD_NAK;
	if (this->GroupCache.find(group) == this->GroupCache.end()) {
		this->stats.GroupMisses++;
		return CROWD_NAK;
	}
	GroupCache_t *gd;
	gd = this->GroupCache[group];
	if (difftime((long)time(NULL), gd->added) > this->timeout) {
		/* Timeout */
		this->GroupCache.erase(group);
		delete gd;
		this->stats.GroupMisses++;
		return CROWD_NAK;
	}
	if ((full) & (gd->fullresults != true)) {
		this->stats.GroupMisses++;
		return CROWD_NAK;
	}
	igd->active = gd->group->active;
	igd->attributes = gd->group->attributes;
	igd->conception = gd->group->conception;
	igd->description = gd->group->description;
	igd->directoryId = gd->group->directoryId;
	igd->id = gd->group->id;
	igd->lastModified = gd->group->lastModified;
	igd->members = gd->group->members;
	igd->name = gd->group->name;
	this->stats.GroupHits++;
	return CROWD_OK;
}
void CrowdCache::invalidateGroupCache(std::string group) {
	if (this->GroupCache.find(group) == this->GroupCache.end()) {
		return;
	}
	delete this->GroupCache[group];
	this->GroupCache.erase(group);
	return;
}


void CrowdCache::setApplicationGroupsCache(std::vector<std::string> groups) {
	if (this->timeout == 0)
		return;
	this->ApplicationGroupsCache.added = time(0);
	this->ApplicationGroupsCache.groups = groups;
}
CrowdClientReturnCodes CrowdCache::getApplicationGroupsCache(std::vector<std::string> *groups) {
	if (this->timeout == 0)
		return CROWD_NAK;
	if (difftime((long)time(NULL), this->ApplicationGroupsCache.added) > this->timeout) {
		this->ApplicationGroupsCache.added = 0;
		this->ApplicationGroupsCache.groups.clear();
		this->stats.ApplicationGroupsMisses++;
		return CROWD_NAK;
	}
	*groups = this->ApplicationGroupsCache.groups;
	this->stats.ApplicationGroupsHits;
	return CROWD_OK;
}
void CrowdCache::invalidateApplicationGroupCache() {
	if (this->timeout == 0)
		return;
	this->ApplicationGroupsCache.added = 0;
	this->ApplicationGroupsCache.groups.clear();
}

void CrowdCache::setAllUsersCache(std::vector<std::string> users) {
	if (this->timeout == 0)
		return;
	this->AllUsersCache.added = time(0);
	this->AllUsersCache.groups = users;
}
CrowdClientReturnCodes CrowdCache::getAllUsersCache(std::vector<std::string> *users) {
	if (this->timeout == 0)
		return CROWD_NAK;
	if (difftime((long)time(NULL), this->AllUsersCache.added) > this->timeout) {
		this->AllUsersCache.added = 0;
		this->AllUsersCache.groups.clear();
		this->stats.AllUsersMisses++;
		return CROWD_NAK;
	}
	*users = this->AllUsersCache.groups;
	this->stats.AllUsersHits++;
	return CROWD_OK;
}
void CrowdCache::invalidateAllUsersCache() {
	if (this->timeout == 0)
		return;
	this->AllUsersCache.added = 0;
	this->AllUsersCache.groups.clear();
}


