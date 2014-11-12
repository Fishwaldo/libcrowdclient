/* crowd-c++ - crowdclient.cpp
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

/** @file crowdclient.cpp
 *  @brief
 */

#include <map>
#include <sstream>

#include "crowdclient.hpp"
#include "crowdcache_p.hpp"
#include "soapSecurityServerHttpBindingProxy.h"
#include "SecurityServerHttpBinding.nsmap"


template <typename T>
std::string tostring(const T& t)
{
	std::ostringstream ss;
	ss << t;
	return ss.str();
}



CrowdClient *CrowdClient::instance = NULL;
bool CrowdClient::ready = false;
bool CrowdClient::throwenabled = true;
CrowdClientReturnCodes CrowdClient::errorcode = CROWD_OK;


CrowdClient *CrowdClient::Get() {
	if (!CrowdClient::instance) {
		CrowdClient::instance = new CrowdClient();
	}
	return CrowdClient::instance;

}
bool CrowdClient::isReady() {
	if (!CrowdClient::ready)
		CrowdClient::errorcode = CROWD_ERR_NOT_READY;
	else
		CrowdClient::errorcode = CROWD_OK;
	return CrowdClient::ready;
}

CrowdClient::CrowdClient() : authToken(NULL), url(""), appname(""), password(""), authattempts(3)
{
	this->cache = new CrowdCache();
	this->cache->setTimeout(600);
	this->service = new SecurityServerHttpBindingProxy(SOAP_IO_KEEPALIVE);
}
CrowdClient::~CrowdClient() {
	//delete this->authToken;
	this->service->destroy();
	delete this->service;
	this->instance = NULL;
	delete this->cache;
}


CrowdClientReturnCodes CrowdClient::setup(std::string url, std::string appname, std::string password) {
	/* construct a new instance */
	CrowdClient *clnt = CrowdClient::Get();
	clnt->url = url;
	clnt->appname = appname;
	clnt->password = password;
	return clnt->authApplication();
}
void CrowdClient::setExceptions(bool enabled) {
	CrowdClient::throwenabled = enabled;
}

CrowdClientReturnCodes CrowdClient::getErrorCode() {
	return this->errorcode;
}
std::string CrowdClient::getErrorMsg() {
	if (this->errorcode == CROWD_OK) {
		return "";
	} else {
		return this->service->soap_fault()->faultstring;
	}
}


CrowdClientReturnCodes CrowdClient::processFault() {
	CrowdException *exception;
	if (!this->service->soap_fault()) {
		return CROWD_ERR_UNKNOWN;
	}
	std::cout << this->service->soap_fault()->faultcode << std::endl;
	if (this->service->soap_fault()->detail->ns1__ApplicationAccessDeniedException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_APPLICATION_ACCESS_DENIED, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_APPLICATION_ACCESS_DENIED;
	} else if (this->service->soap_fault()->detail->ns1__ApplicationPermissionException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_APPLICATION_PERMISSION, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_APPLICATION_PERMISSION;
	} else if (this->service->soap_fault()->detail->ns1__BulkAddFailedException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_BULK_ADD_FAILED, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_BULK_ADD_FAILED;
	} else if (this->service->soap_fault()->detail->ns1__ExpiredCredentialException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_EXPIRED_CREDENTIAL, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_EXPIRED_CREDENTIAL;
	} else if (this->service->soap_fault()->detail->ns1__InactiveAccountException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_INACTIVE_ACCOUNT, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_INACTIVE_ACCOUNT;
	} else if (this->service->soap_fault()->detail->ns1__InvalidAuthenticationException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_INVALID_AUTHENTICATION, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_INVALID_AUTHENTICATION;
	} else if (this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_INVALID_AUTHORIZATION, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_INVALID_AUTHORIZATION;
	} else if (this->service->soap_fault()->detail->ns1__InvalidCredentialException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_INVALID_CREDENTIAL, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_INVALID_CREDENTIAL;
	} else if (this->service->soap_fault()->detail->ns1__InvalidEmailAddressException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_INVALID_EMAIL, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_INVALID_EMAIL;
	} else if (this->service->soap_fault()->detail->ns1__InvalidGroupException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_INVALID_GROUP, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_INVALID_GROUP;
	} else if (this->service->soap_fault()->detail->ns1__InvalidRoleException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_INVALID_ROLE, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_INVALID_ROLE;
	} else if (this->service->soap_fault()->detail->ns1__InvalidTokenException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_INVALID_TOKEN, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_INVALID_TOKEN;
	} else if (this->service->soap_fault()->detail->ns1__InvalidUserException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_INVALID_USER, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_INVALID_USER;
	} else if (this->service->soap_fault()->detail->ns1__ObjectNotFoundException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_OBJECT_NOT_FOUND, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_OBJECT_NOT_FOUND;
	} else if (this->service->soap_fault()->detail->ns1__RemoteException) {
		if (this->throwenabled) throw CrowdException(CROWD_ERR_REMOTE_EXCEPTION, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_REMOTE_EXCEPTION;
	} else {
		/* Unknown/Unhandled Exception */
		if (this->throwenabled) throw CrowdException(CROWD_ERR_UNKNOWN, this->service->soap_fault_string());
		this->errorcode = CROWD_ERR_UNKNOWN;
	}
	return this->errorcode;

}

CrowdClientReturnCodes CrowdClient::authApplication() {
	bool ret = false;
	_ns1__authenticateApplication auth;
	ns2__ApplicationAuthenticationContext *authcontext = new ns2__ApplicationAuthenticationContext();
	ns2__PasswordCredential *authpass = new ns2__PasswordCredential();

	authpass->credential = &this->password;

	authcontext->name = &this->appname;


	authcontext->credential = authpass;
	auth.in0 = authcontext;
	_ns1__authenticateApplicationResponse authResponse;

	if (this->service->authenticateApplication(this->url.c_str(), NULL, &auth, &authResponse) == SOAP_OK) {
		this->authToken = authResponse.out;
		ret = true;
		CrowdClient::ready = true;
	} else {
		ret = false;
		CrowdClient::ready = false;
	}
	delete authcontext;
	delete authpass;
	if (ret == false)
		return this->processFault();
	return CROWD_OK;
}

CrowdClientReturnCodes CrowdClient::authPrinciple(std::string username, std::string password, std::string *token) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	/* what ever happens, we invalidate the cache */
	this->cache->invalidatePrincipleCache(username);

	_ns1__authenticatePrincipalSimple auth;
	_ns1__authenticatePrincipalSimpleResponse authResponse;

	auth.in0 = this->authToken;
	auth.in1 = &username;
	auth.in2 = &password;
	int attempts = 0;
	while (true) {
		int ret = this->service->authenticatePrincipalSimple(this->url.c_str(), NULL, &auth, &authResponse);
		if ( ret == SOAP_OK) {
			token->assign(authResponse.out->c_str());
			this->cache->invalidatePrincipleTokenCache(authResponse.out->c_str());
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			auth.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}

CrowdClientReturnCodes CrowdClient::deauthPrinciple(std::string token) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;


	_ns1__invalidatePrincipalToken Token;
	_ns1__invalidatePrincipalTokenResponse TokenResponse;
	Token.in0 = this->authToken;
	Token.in1 = &token;
	int attempts = 0;
	while (true) {
		int ret = this->service->invalidatePrincipalToken(this->url.c_str(), NULL, &Token, &TokenResponse);
		if ( ret == SOAP_OK) {
			this->cache->invalidatePrincipleTokenCache(token);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			Token.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}
CrowdClientReturnCodes CrowdClient::checkPrincipleToken(std::string token) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__isValidPrincipalToken Token;
	_ns1__isValidPrincipalTokenResponse TokenResponse;
	Token.in0 = this->authToken;
	Token.in1 = &token;
	int attempts = 0;
	while (true) {
		int ret = this->service->isValidPrincipalToken(this->url.c_str(), NULL, &Token, &TokenResponse);
		if (ret == SOAP_OK) {
			if (TokenResponse.out == false) this->cache->invalidatePrincipleTokenCache(token);
			return TokenResponse.out ? CROWD_OK : CROWD_NAK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			Token.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}
CrowdClientReturnCodes CrowdClient::isGroupMember(std::string group, std::string user) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool result;
	if (this->cache->getIsGroupMemberCache(group, user, &result) == CROWD_OK) {
		return result ? CROWD_OK : CROWD_NAK;
	}

	_ns1__isGroupMember GroupMember;
	_ns1__isGroupMemberResponse GroupMemberResponse;
	GroupMember.in0 = this->authToken;
	GroupMember.in1 = &group;
	GroupMember.in2 = &user;
	int attempts = 0;
	while (true) {
		int ret = this->service->isGroupMember(this->url.c_str(), NULL, &GroupMember, &GroupMemberResponse);
		if (ret == SOAP_OK) {
			this->cache->setIsGroupMemberCache(group, user, GroupMemberResponse.out);
			return GroupMemberResponse.out ? CROWD_OK : CROWD_NAK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			GroupMember.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}

CrowdClientReturnCodes CrowdClient::resetPrinciplePassword(std::string user) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__resetPrincipalCredential reset;
	_ns1__resetPrincipalCredentialResponse resetResponse;
	reset.in0 = this->authToken;
	reset.in1 = &user;
	int attempts = 0;
	while (true) {
		int ret = this->service->resetPrincipalCredential(this->url.c_str(), NULL, &reset, &resetResponse);
		if (ret == SOAP_OK) {
			this->cache->invalidatePrincipleCache(user);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			reset.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}
CrowdClientReturnCodes CrowdClient::getPrincipleByToken(std::string token, PrincipleDetails attributes) {
	if (attributes.use_count() <= 0) {
		return CROWD_ERR_INVALID_PARAM;
	}

	if(this->cache->getPrincipleTokenCache(token, attributes, false) == CROWD_OK) {
		return CROWD_OK;
	}


	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__findPrincipalByToken principle;
	_ns1__findPrincipalByTokenResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = &token;
	int attempts = 0;
	while (true) {
		int ret = this->service->findPrincipalByToken(this->url.c_str(), NULL, &principle, &principleResponse);
		if (ret== SOAP_OK) {
			if (principleResponse.out->ID)
				attributes->id = *principleResponse.out->ID;
			attributes->active = *principleResponse.out->active;
			if (principleResponse.out->conception)
				attributes->conception = *principleResponse.out->conception;
			if (principleResponse.out->description)
				attributes->description = *principleResponse.out->description;
			if (principleResponse.out->directoryId)
				attributes->directoryId = *principleResponse.out->directoryId;
			if (principleResponse.out->lastModified)
				attributes->lastModified = *principleResponse.out->lastModified;
			if (principleResponse.out->name)
				attributes->name = *principleResponse.out->name;
			for (int i = 0; i < principleResponse.out->attributes->SOAPAttribute.size(); i++) {
				ns3__SOAPAttribute *attribs = principleResponse.out->attributes->SOAPAttribute.at(i);
				for (int k = 0; k < attribs->values->string.size(); k++) {
					attributes->attributes[*attribs->name].push_back(attribs->values->string.at(k));
				}
			}
			this->cache->setPrincipleTokenCache(token, attributes, false);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			principle.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}

CrowdClientReturnCodes CrowdClient::getPrincipleAttributes(std::string username, PrincipleDetails attributes) {
	if (attributes.use_count() <= 0) {
		return CROWD_ERR_INVALID_PARAM;
	}
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;

	if(this->cache->getPrincipleCache(username, attributes, false) == CROWD_OK) {
		return CROWD_OK;
	}

	_ns1__findPrincipalWithAttributesByName principle;
	_ns1__findPrincipalWithAttributesByNameResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = &username;
	int attempts = 0;
	int ret = this->service->findPrincipalWithAttributesByName(this->url.c_str(), NULL, &principle, &principleResponse);
	if ( ret == SOAP_OK) {
		if (principleResponse.out->ID)
			attributes->id = *principleResponse.out->ID;
		attributes->active = *principleResponse.out->active;
		if (principleResponse.out->conception)
			attributes->conception = *principleResponse.out->conception;
		if (principleResponse.out->description)
			attributes->description = *principleResponse.out->description;
		if (principleResponse.out->directoryId)
			attributes->directoryId = *principleResponse.out->directoryId;
		if (principleResponse.out->lastModified)
			attributes->lastModified = *principleResponse.out->lastModified;
		if (principleResponse.out->name)
			attributes->name = *principleResponse.out->name;
		for (int i = 0; i < principleResponse.out->attributes->SOAPAttribute.size(); i++) {
			ns3__SOAPAttribute *attribs = principleResponse.out->attributes->SOAPAttribute.at(i);
			for (int k = 0; k < attribs->values->string.size(); k++) {
				attributes->attributes[*attribs->name].push_back(attribs->values->string.at(k));
			}
		}
		this->cache->setPrincipleCache(username, attributes, true);
		return CROWD_OK;
	} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
		attempts++;
		if (this->authApplication() != CROWD_OK) {
			return this->processFault();
		}
		principle.in0 = this->authToken;
	} else {
		return this->processFault();
	}
}

CrowdClientReturnCodes CrowdClient::getPrincipleByName(std::string username, PrincipleDetails attributes) {
	if (attributes.use_count() <= 0) {
		return CROWD_ERR_INVALID_PARAM;
	}
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;

	if(this->cache->getPrincipleCache(username, attributes, false) == CROWD_OK) {
		return CROWD_OK;
	}

	_ns1__findPrincipalByName principle;
	_ns1__findPrincipalByNameResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = &username;
	int attempts = 0;
	while (true) {
		int ret = this->service->findPrincipalByName(this->url.c_str(), NULL, &principle, &principleResponse);
		if ( ret == SOAP_OK) {
			if (principleResponse.out->ID)
				attributes->id = *principleResponse.out->ID;
			attributes->active = *principleResponse.out->active;
			if (principleResponse.out->conception)
				attributes->conception = *principleResponse.out->conception;
			if (principleResponse.out->description)
				attributes->description = *principleResponse.out->description;
			if (principleResponse.out->directoryId)
				attributes->directoryId = *principleResponse.out->directoryId;
			if (principleResponse.out->lastModified)
				attributes->lastModified = *principleResponse.out->lastModified;
			if (principleResponse.out->name)
				attributes->name = *principleResponse.out->name;
			for (int i = 0; i < principleResponse.out->attributes->SOAPAttribute.size(); i++) {
				ns3__SOAPAttribute *attribs = principleResponse.out->attributes->SOAPAttribute.at(i);
				for (int k = 0; k < attribs->values->string.size(); k++) {
					attributes->attributes[*attribs->name].push_back(attribs->values->string.at(k));
				}
			}
			this->cache->setPrincipleCache(username, attributes, true);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			principle.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}

CrowdClientReturnCodes CrowdClient::getAllGroups(std::vector<std::string> *groups) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;

	if(this->cache->getAllGroupsCache(groups) == CROWD_OK) {
		return CROWD_OK;
	}

	_ns1__findAllGroupNames findgroups;
	_ns1__findAllGroupNamesResponse findgroupsResponse;
	findgroups.in0 = this->authToken;
	int attempts = 0;
	while (true) {
		int ret = this->service->findAllGroupNames(this->url.c_str(), NULL, &findgroups, &findgroupsResponse);
		if (ret== SOAP_OK) {
			groups->clear();
			groups->swap(findgroupsResponse.out->string);
			this->cache->setAllGroupsCache(*groups);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			findgroups.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}

CrowdClientReturnCodes CrowdClient::getGroup(std::string groupname, GroupDetails groupdetails) {
	if (groupdetails.use_count() <= 0) {
		return CROWD_ERR_INVALID_PARAM;
	}
	if (this->cache->getGroupCache(groupname, groupdetails, false) == CROWD_OK) {
		return CROWD_OK;
	}

	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__findGroupByName group;
	_ns1__findGroupByNameResponse groupResponse;
	group.in0 = this->authToken;
	group.in1 = &groupname;
	int attempts = 0;
	while (true) {
		int ret = this->service->findGroupByName(this->url.c_str(), NULL, &group, &groupResponse);
		if (ret== SOAP_OK) {
			if (groupResponse.out->ID)
				groupdetails->id = *groupResponse.out->ID;
			groupdetails->active = *groupResponse.out->active;
			if (groupResponse.out->conception)
				groupdetails->conception = *groupResponse.out->conception;
			if (groupResponse.out->description)
				groupdetails->description = *groupResponse.out->description;
			if (groupResponse.out->directoryId)
				groupdetails->directoryId = *groupResponse.out->directoryId;
			if (groupResponse.out->lastModified)
				groupdetails->lastModified = *groupResponse.out->lastModified;
			if (groupResponse.out->name)
				groupdetails->name = *groupResponse.out->name;
			for (int i = 0; i < groupResponse.out->attributes->SOAPAttribute.size(); i++) {
				ns3__SOAPAttribute *attribs = groupResponse.out->attributes->SOAPAttribute.at(i);
				for (int k = 0; k < attribs->values->string.size(); k++) {
					groupdetails->attributes[*attribs->name].push_back(attribs->values->string.at(k));
				}
			}
			for (int i = 0; i < groupResponse.out->members->string.size(); i++) {
				groupdetails->members.push_back(groupResponse.out->members->string.at(i));
			}
			this->cache->setGroupCache(groupdetails->name, groupdetails, false);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			group.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}

CrowdClientReturnCodes CrowdClient::getGroupAttributes(std::string groupname, GroupDetails attributes) {
	if (attributes.use_count() <= 0) {
		return CROWD_ERR_INVALID_PARAM;
	}
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;

	if (this->cache->getGroupCache(groupname, attributes, true) == CROWD_OK) {
		return CROWD_OK;
	}

	_ns1__findGroupWithAttributesByName group;
	_ns1__findGroupWithAttributesByNameResponse groupResponse;
	group.in0 = this->authToken;
	group.in1 = &groupname;
	int attempts = 0;
	while (true) {
		int ret = this->service->findGroupWithAttributesByName(this->url.c_str(), NULL, &group, &groupResponse);
		if (ret == SOAP_OK) {
			if (groupResponse.out->ID)
				attributes->id = *groupResponse.out->ID;
			attributes->active = *groupResponse.out->active;
			if (groupResponse.out->conception)
				attributes->conception = *groupResponse.out->conception;
			if (groupResponse.out->description)
				attributes->description = *groupResponse.out->description;
			if (groupResponse.out->directoryId)
				attributes->directoryId = *groupResponse.out->directoryId;
			if (groupResponse.out->lastModified)
				attributes->lastModified = *groupResponse.out->lastModified;
			if (groupResponse.out->name)
				attributes->name = *groupResponse.out->name;
			for (int i = 0; i < groupResponse.out->attributes->SOAPAttribute.size(); i++) {
				ns3__SOAPAttribute *attribs = groupResponse.out->attributes->SOAPAttribute.at(i);
				for (int k = 0; k < attribs->values->string.size(); k++) {
					attributes->attributes[*attribs->name].push_back(attribs->values->string.at(k));
				}
			}
			for (int i = 0; i < groupResponse.out->members->string.size(); i++) {
				attributes->members.push_back(groupResponse.out->members->string.at(i));
			}
			this->cache->setGroupCache(attributes->name, attributes, true);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			group.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}
CrowdClientReturnCodes CrowdClient::getPrincipleGroups(std::string username, std::vector<std::string> *groups) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;

	if(this->cache->getPrincipleGroupsCache(username, groups) == CROWD_OK) {
		return CROWD_OK;
	}


	_ns1__findGroupMemberships groupmembership;
	_ns1__findGroupMembershipsResponse groupmembershipResponse;
	groupmembership.in0 = this->authToken;
	groupmembership.in1 = &username;
	int attempts = 0;
	while (true) {
		int ret = this->service->findGroupMemberships(this->url.c_str(), NULL, &groupmembership, &groupmembershipResponse);
		if (ret == SOAP_OK) {
			groups->clear();
			groups->swap(groupmembershipResponse.out->string);
			this->cache->setPrincipleGroupsCache(username, *groups);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			groupmembership.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}


CrowdClientReturnCodes CrowdClient::getApplicationGroups(std::vector<std::string> *groups) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	if (this->cache->getApplicationGroupsCache(groups) == CROWD_OK) {
		return CROWD_OK;
	}
	_ns1__getGrantedAuthorities appgroups;
	_ns1__getGrantedAuthoritiesResponse appgroupsResponse;
	appgroups.in0 = this->authToken;
	int attempts = 0;
	while (true) {
		int ret = this->service->getGrantedAuthorities(this->url.c_str(), NULL, &appgroups, &appgroupsResponse);
		if (ret== SOAP_OK) {
			groups->clear();
			groups->swap(appgroupsResponse.out->string);
			this->cache->setApplicationGroupsCache(*groups);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			appgroups.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}
CrowdClientReturnCodes CrowdClient::getAllPrinciples(std::vector<std::string> *users) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	if (this->cache->getAllUsersCache(users) == CROWD_OK) {
		return CROWD_OK;
	}
	_ns1__findAllPrincipalNames principles;
	_ns1__findAllPrincipalNamesResponse principlesResponse;
	principles.in0 = this->authToken;
	int attempts = 0;
	while (true) {
		int ret = this->service->findAllPrincipalNames(this->url.c_str(), NULL, &principles, &principlesResponse);
		if (ret == SOAP_OK) {
			users->clear();
			users->swap(principlesResponse.out->string);
			this->cache->setAllUsersCache(*users);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			principles.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}

CrowdClientReturnCodes CrowdClient::addPrinciple(std::string username, std::string firstname, std::string lastname, std::string email, std::string password, PrincipleDetails attributes) {
	if (attributes.use_count() <= 0) {
		return CROWD_ERR_INVALID_PARAM;
	}
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool success = false;
	_ns1__addPrincipal principle;
	_ns1__addPrincipalResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = new ns3__SOAPPrincipal();
	principle.in1->name = &username;
	principle.in1->active = new bool(true);

	principle.in1->attributes = new ns3__ArrayOfSOAPAttribute();

	ns3__SOAPAttribute givenName;
	givenName.name = new std::string("givenName");
	givenName.values = new ns1__ArrayOfString();
	givenName.values->string.push_back(firstname);
	principle.in1->attributes->SOAPAttribute.push_back(&givenName);

	ns3__SOAPAttribute sn;
	sn.name = new std::string("sn");
	sn.values = new ns1__ArrayOfString();
	sn.values->string.push_back(lastname);
	principle.in1->attributes->SOAPAttribute.push_back(&sn);

	ns3__SOAPAttribute displayName;
	displayName.name = new std::string("displayName");
	displayName.values = new ns1__ArrayOfString();
	displayName.values->string.push_back(std::string(firstname + " " + lastname));
	principle.in1->attributes->SOAPAttribute.push_back(&displayName);

	ns3__SOAPAttribute mail;
	mail.name = new std::string("mail");
	mail.values = new ns1__ArrayOfString();
	mail.values->string.push_back(email);
	principle.in1->attributes->SOAPAttribute.push_back(&mail);

	principle.in2 = new ns2__PasswordCredential();
	principle.in2->credential = &password;
	//principle.in2->encryptedCredential = false;
	int attempts = 0;
	while (true) {
		int ret = this->service->addPrincipal(this->url.c_str(), NULL, &principle, &principleResponse);
		if (ret== SOAP_OK) {
			if (principleResponse.out->ID)
				attributes->id = *principleResponse.out->ID;
			attributes->active = *principleResponse.out->active;
			if (principleResponse.out->conception)
				attributes->conception = *principleResponse.out->conception;
			if (principleResponse.out->description)
				attributes->description = *principleResponse.out->description;
			if (principleResponse.out->directoryId)
				attributes->directoryId = *principleResponse.out->directoryId;
			if (principleResponse.out->lastModified)
				attributes->lastModified = *principleResponse.out->lastModified;
			if (principleResponse.out->name)
				attributes->name = *principleResponse.out->name;
			for (int i = 0; i < principleResponse.out->attributes->SOAPAttribute.size(); i++) {
				ns3__SOAPAttribute *attribs = principleResponse.out->attributes->SOAPAttribute.at(i);
				for (int k = 0; k < attribs->values->string.size(); k++) {
					attributes->attributes[*attribs->name].push_back(attribs->values->string.at(k));
				}
			}
			this->cache->setPrincipleCache(attributes->name, attributes, false);
			this->cache->invalidateAllUsersCache();
			success = true;
			break;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				success = false;
				break;
			}
			principle.in0 = this->authToken;
		} else {
			success = false;
			break;
		}
	}


	delete principle.in1->attributes;
	delete principle.in1->active;
	delete principle.in1;
	delete givenName.name;
	delete givenName.values;
	delete sn.name;
	delete sn.values;
	delete displayName.name;
	delete displayName.values;
	delete mail.name;
	delete mail.values;
	delete principle.in2;
	if (success == false)
		return this->processFault();
	return CROWD_OK;
}

CrowdClientReturnCodes CrowdClient::removePrinciple(std::string username) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__removePrincipal principle;
	_ns1__removePrincipalResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = &username;
	int attempts = 0;
	while (true) {
		int ret = this->service->removePrincipal(this->url.c_str(), NULL, &principle, &principleResponse);
		if (ret	== SOAP_OK) {
			this->cache->invalidatePrincipleCache(username);
			this->cache->invalidatePrincipleGroupCache(username);
			this->cache->invalidateAllUsersCache();

			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			principle.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}

CrowdClientReturnCodes CrowdClient::addPrincipleAttributes(std::string username, std::string attributename, std::vector<std::string> attributevals) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool success = false;
	_ns1__addAttributeToPrincipal principle;
	_ns1__addAttributeToPrincipalResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = &username;
	principle.in2 = new ns3__SOAPAttribute();
	principle.in2->name = &attributename;
	principle.in2->values = new ns1__ArrayOfString();
	for (int i = 0; i < attributevals.size(); i++) {
		principle.in2->values->string.push_back(attributevals.at(i));
	}
	int attempts = 0;
	while (true) {
		int ret = this->service->addAttributeToPrincipal(this->url.c_str(), NULL, &principle, &principleResponse);
		if (ret == SOAP_OK) {
			success = true;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				success = false;
				break;
			}
			principle.in0 = this->authToken;
		} else {
			success = false;
			break;
		}

	}
	delete principle.in2->values;
	delete principle.in2;
	if (success == false)
		return this->processFault();
	this->cache->invalidatePrincipleCache(username);
	return CROWD_OK;
}
CrowdClientReturnCodes CrowdClient::removePrincipleAttributes(std::string username, std::string attribute) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__removeAttributeFromPrincipal attrib;
	_ns1__removeAttributeFromPrincipalResponse attribResponse;
	attrib.in0 = this->authToken;
	attrib.in1 = &username;
	attrib.in2 = &attribute;
	int attempts = 0;
	while (true) {
		int ret = this->service->removeAttributeFromPrincipal(this->url.c_str(), NULL, &attrib, &attribResponse);
		if (ret == SOAP_OK) {
			this->cache->invalidatePrincipleCache(username);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			attrib.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}

CrowdClientReturnCodes CrowdClient::updatePrincipleAttributes(std::string username, std::string attributename, std::vector<std::string> attributevals) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool success = false;
	_ns1__updatePrincipalAttribute principle;
	_ns1__updatePrincipalAttributeResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = &username;
	principle.in2 = new ns3__SOAPAttribute();
	principle.in2->name = &attributename;
	principle.in2->values = new ns1__ArrayOfString();
	for (int i = 0; i < attributevals.size(); i++) {
		principle.in2->values->string.push_back(attributevals.at(i));
	}
	int attempts = 0;
	while (true) {
		int ret = this->service->updatePrincipalAttribute(this->url.c_str(), NULL, &principle, &principleResponse);
		if (ret== SOAP_OK) {
			success = true;
			break;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				success = false;
				break;
			}
			principle.in0 = this->authToken;
		} else {
			success = false;
			break;
		}
	}
	delete principle.in2->values;
	delete principle.in2;
	if (success == false)
		return this->processFault();

	this->cache->invalidatePrincipleCache(username);
	return CROWD_OK;
}

CrowdClientReturnCodes CrowdClient::addGroup(std::string groupname, std::string description, GroupDetails attributes) {
	if (attributes.use_count() <= 0) {
		return CROWD_ERR_INVALID_PARAM;
	}
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool success = false;
	_ns1__addGroup group;
	_ns1__addGroupResponse groupResponse;
	group.in0 = this->authToken;
	group.in1 = new ns3__SOAPGroup();
	group.in1->active = new bool(true);
	group.in1->name = &groupname;
	group.in1->description = &description;
	int attempts = 0;
	while (true) {
		int ret = this->service->addGroup(this->url.c_str(), NULL, &group, &groupResponse);
		if (ret== SOAP_OK) {
			if (groupResponse.out->ID)
				attributes->id = *groupResponse.out->ID;
			attributes->active = *groupResponse.out->active;
			if (groupResponse.out->conception)
				attributes->conception = *groupResponse.out->conception;
			if (groupResponse.out->description)
				attributes->description = *groupResponse.out->description;
			if (groupResponse.out->directoryId)
				attributes->directoryId = *groupResponse.out->directoryId;
			if (groupResponse.out->lastModified)
				attributes->lastModified = *groupResponse.out->lastModified;
			if (groupResponse.out->name)
				attributes->name = *groupResponse.out->name;
			for (int i = 0; i < groupResponse.out->attributes->SOAPAttribute.size(); i++) {
				ns3__SOAPAttribute *attribs = groupResponse.out->attributes->SOAPAttribute.at(i);
				for (int k = 0; k < attribs->values->string.size(); k++) {
					attributes->attributes[*attribs->name].push_back(attribs->values->string.at(k));
				}
			}
			for (int i = 0; i < groupResponse.out->members->string.size(); i++) {
				attributes->members.push_back(groupResponse.out->members->string.at(i));
			}
			success = true;
			break;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				success = false;
				break;
			}
			group.in0 = this->authToken;
		} else {
			success = false;
			break;
		}
	}
	delete group.in1->active;
	delete group.in1;
	if (success == false)
		return this->processFault();
	this->cache->invalidateAllGroupCache();
	this->cache->invalidateApplicationGroupCache();
	this->cache->setGroupCache(attributes->name, attributes, false);
	return CROWD_OK;
}
CrowdClientReturnCodes CrowdClient::updateGroup(std::string name, std::string description, bool active) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__updateGroup group;
	_ns1__updateGroupResponse groupResponse;
	group.in0 = this->authToken;
	group.in1 = &name;
	group.in2 = &description;
	group.in3 = active;
	int attempts = 0;
	while (true) {
		int ret = this->service->updateGroup(this->url.c_str(), NULL, &group, &groupResponse);
		if (ret == SOAP_OK) {
			this->cache->invalidateGroupCache(name);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			group.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}

}
CrowdClientReturnCodes CrowdClient::removeGroup(std::string name) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__removeGroup group;
	_ns1__removeGroupResponse groupResponse;
	group.in0 = this->authToken;
	group.in1 = &name;
	int attempts = 0;
	while (true) {
		int ret = this->service->removeGroup(this->url.c_str(), NULL, &group, &groupResponse);
		if (ret== SOAP_OK) {
			this->cache->invalidateGroupCaches();
			this->cache->invalidateAllGroupCache();
			this->cache->invalidateGroupCache(name);
			this->cache->invalidateApplicationGroupCache();
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			group.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}
CrowdClientReturnCodes CrowdClient::addGroupMember(std::string groupname, std::string principle) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__addPrincipalToGroup group;
	_ns1__addPrincipalToGroupResponse groupResponse;
	group.in0 = this->authToken;
	group.in2 = &groupname;
	group.in1 = &principle;
	int attempts = 0;
	while (true) {
		int ret = this->service->addPrincipalToGroup(this->url.c_str(), NULL, &group, &groupResponse);
		if (ret== SOAP_OK) {
			this->cache->invalidateIsGroupMemberCache(groupname, principle);
			this->cache->invalidatePrincipleGroupCache(principle);
			this->cache->invalidateGroupCache(groupname);
			this->cache->invalidateAllUsersCache();

			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			group.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}
CrowdClientReturnCodes CrowdClient::removeGroupMember(std::string groupname, std::string principle) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__removePrincipalFromGroup group;
	_ns1__removePrincipalFromGroupResponse groupResponse;
	group.in0 = this->authToken;
	group.in2 = &groupname;
	group.in1 = &principle;
	int attempts = 0;
	while (true) {
		int ret = this->service->removePrincipalFromGroup(this->url.c_str(), NULL, &group, &groupResponse);
		if (ret== SOAP_OK) {
			this->cache->invalidateIsGroupMemberCache(groupname, principle);
			this->cache->invalidatePrincipleGroupCache(principle);
			this->cache->invalidateGroupCache(groupname);
			this->cache->invalidateAllUsersCache();

			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			group.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}

CrowdClientReturnCodes CrowdClient::addGroupAttributes(std::string groupname, std::string attributename, std::vector<std::string> attributevals) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool success = false;
	_ns1__addAttributeToGroup group;
	_ns1__addAttributeToGroupResponse groupResponse;
	group.in0 = this->authToken;
	group.in1 = &groupname;
	group.in2 = new ns3__SOAPAttribute();
	group.in2->name = &attributename;
	group.in2->values = new ns1__ArrayOfString();
	for (int i = 0; i < attributevals.size(); i++) {
		group.in2->values->string.push_back(attributevals.at(i));
	}
	int attempts = 0;
	while (true) {
		int ret = this->service->addAttributeToGroup(this->url.c_str(), NULL, &group, &groupResponse);
		if (ret == SOAP_OK) {
			success = true;
			break;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				success = false;
				break;
			}
			group.in0 = this->authToken;
		} else {
			success = false;
			break;
		}
	}
	delete group.in2->values;
	delete group.in2;
	if (success == false)
		return this->processFault();
	this->cache->invalidateGroupCache(groupname);
	return CROWD_OK;
}

CrowdClientReturnCodes CrowdClient::updateGroupAttributes(std::string groupname, std::string attributename, std::vector<std::string> attributevals) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool success = false;
	_ns1__updateGroupAttribute group;
	_ns1__updateGroupAttributeResponse groupResponse;
	group.in0 = this->authToken;
	group.in1 = &groupname;
	group.in2 = new ns3__SOAPAttribute();
	group.in2->name = &attributename;
	group.in2->values = new ns1__ArrayOfString();
	for (int i = 0; i < attributevals.size(); i++) {
		group.in2->values->string.push_back(attributevals.at(i));
	}
	int attempts = 0;
	while (true) {
		int ret = this->service->updateGroupAttribute(this->url.c_str(), NULL, &group, &groupResponse);
		if (ret== SOAP_OK) {
			ret = true;
			break;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				success = false;
				break;
			}
			group.in0 = this->authToken;
		} else {
			success = false;
			break;
		}

	}
	delete group.in2->values;

	delete group.in2;
	if (success == false)
		return this->processFault();
	this->cache->invalidateGroupCache(groupname);
	return CROWD_OK;
}
CrowdClientReturnCodes CrowdClient::removeGroupAttributes(std::string groupname, std::string attribute) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__removeAttributeFromGroup attrib;
	_ns1__removeAttributeFromGroupResponse attribResponse;
	attrib.in0 = this->authToken;
	attrib.in1 = &groupname;
	attrib.in2 = &attribute;
	int attempts = 0;
	while (true) {
		int ret = this->service->removeAttributeFromGroup(this->url.c_str(), NULL, &attrib, &attribResponse);
		if (ret == SOAP_OK) {
			this->cache->invalidateGroupCache(groupname);
			return CROWD_OK;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				return this->processFault();
			}
			attrib.in0 = this->authToken;
		} else {
			return this->processFault();
		}
	}
}

CrowdClientReturnCodes CrowdClient::resetPrinciplePassword(std::string user, std::string password) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool success = false;
	_ns1__updatePrincipalCredential principle;
	_ns1__updatePrincipalCredentialResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = &user;
	principle.in2 = new ns2__PasswordCredential();
	principle.in2->credential = &password;
	principle.in2->encryptedCredential = new bool(false);
	int attempts = 0;
	while (true) {
		int ret = this->service->updatePrincipalCredential(this->url.c_str(), NULL, &principle, &principleResponse);
		if (ret == SOAP_OK) {
			ret = true;
			break;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				success = false;
				break;
			}
			principle.in0 = this->authToken;
		} else {
			success = false;
			break;
		}

	}

	delete principle.in2->encryptedCredential;
	delete principle.in2;
	if (success == false)
		return this->processFault();

	this->cache->invalidatePrincipleCache(user);
	return CROWD_OK;
}

CrowdClientReturnCodes CrowdClient::searchPrinciples(std::vector< searchParams * > search, std::vector<PrincipleDetails > *results) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool success = false;
	_ns1__searchPrincipals searchPrinciple;
	_ns1__searchPrincipalsResponse searchPrincipleResponse;
	searchPrinciple.in0 = this->authToken;
	searchPrinciple.in1 = new ns3__ArrayOfSearchRestriction();
	for (int i = 0; i < search.size(); i++) {
		ns3__SearchRestriction *param = new ns3__SearchRestriction();
		param->name = &(search.at(i))->name;
		param->value = &(search.at(i))->value;
		searchPrinciple.in1->SearchRestriction.push_back(param);
	}
	int attempts = 0;
	while (true) {
		int ret = this->service->searchPrincipals(this->url.c_str(), NULL, &searchPrinciple, &searchPrincipleResponse);
		if (ret == SOAP_OK) {
			success = true;
			break;
		} else if ((this->service->soap_fault()->detail->ns1__InvalidAuthorizationTokenException) && (attempts < this->authattempts)) {
			attempts++;
			if (this->authApplication() != CROWD_OK) {
				success = false;
				break;
			}
			searchPrinciple.in0 = this->authToken;
		} else {
			success = false;
			break;
		}

	}
	while (searchPrinciple.in1->SearchRestriction.size() > 0) {
		delete searchPrinciple.in1->SearchRestriction.back();
		searchPrinciple.in1->SearchRestriction.pop_back();
	}
	delete searchPrinciple.in1;
	if (searchPrincipleResponse.out->SOAPPrincipal.size() == 0)
		return CROWD_NAK;
	for (int i = 0; i < searchPrincipleResponse.out->SOAPPrincipal.size(); i++) {
		PrincipleDetails attributes = boost::make_shared<PrincipleDetails_t>();
		if (searchPrincipleResponse.out->SOAPPrincipal.at(i)->ID)
			attributes->id = *searchPrincipleResponse.out->SOAPPrincipal.at(i)->ID;
		attributes->active = *searchPrincipleResponse.out->SOAPPrincipal.at(i)->active;
		if (searchPrincipleResponse.out->SOAPPrincipal.at(i)->conception)
			attributes->conception = *searchPrincipleResponse.out->SOAPPrincipal.at(i)->conception;
		if (searchPrincipleResponse.out->SOAPPrincipal.at(i)->description)
			attributes->description = *searchPrincipleResponse.out->SOAPPrincipal.at(i)->description;
		if (searchPrincipleResponse.out->SOAPPrincipal.at(i)->directoryId)
			attributes->directoryId = *searchPrincipleResponse.out->SOAPPrincipal.at(i)->directoryId;
		if (searchPrincipleResponse.out->SOAPPrincipal.at(i)->lastModified)
			attributes->lastModified = *searchPrincipleResponse.out->SOAPPrincipal.at(i)->lastModified;
		if (searchPrincipleResponse.out->SOAPPrincipal.at(i)->name)
			attributes->name = *searchPrincipleResponse.out->SOAPPrincipal.at(i)->name;
		for (int j = 0; j < searchPrincipleResponse.out->SOAPPrincipal.at(i)->attributes->SOAPAttribute.size(); j++) {
			ns3__SOAPAttribute *attribs = searchPrincipleResponse.out->SOAPPrincipal.at(i)->attributes->SOAPAttribute.at(j);
			for (int k = 0; k < attribs->values->string.size(); k++) {
				attributes->attributes[*attribs->name].push_back(attribs->values->string.at(k));
			}
		}
		this->cache->setPrincipleCache(attributes->name, attributes, false);
		results->push_back(attributes);
	}

	if (success == false)
		return this->processFault();
	else
		return CROWD_OK;
}

const CrowdCacheStatistics_t CrowdClient::getCacheStats() {
	return this->cache->getStats();
}

