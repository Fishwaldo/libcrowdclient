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

CrowdClient::CrowdClient() : authToken(NULL), url(""), appname(""), password("")
{
	this->service = new SecurityServerHttpBindingProxy(SOAP_IO_KEEPALIVE);
}
CrowdClient::~CrowdClient() {
	//delete this->authToken;
	this->service->destroy();
	delete this->service;
	this->instance = NULL;
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
	_ns1__authenticatePrincipalSimple auth;
	_ns1__authenticatePrincipalSimpleResponse authResponse;

	auth.in0 = this->authToken;
	auth.in1 = &username;
	auth.in2 = &password;
	if (this->service->authenticatePrincipalSimple(this->url.c_str(), NULL, &auth, &authResponse) == SOAP_OK) {
		token->assign(authResponse.out->c_str());
		return CROWD_OK;
	} else {
		return this->processFault();
	}
}

CrowdClientReturnCodes CrowdClient::deauthPrinciple(std::string token) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;

	_ns1__invalidatePrincipalToken Token;
	_ns1__invalidatePrincipalTokenResponse TokenResponse;
	Token.in0 = this->authToken;
	Token.in1 = &token;
	if (this->service->invalidatePrincipalToken(this->url.c_str(), NULL, &Token, &TokenResponse) == SOAP_OK) {
		return CROWD_OK;
	} else {
		return this->processFault();
	}
}
CrowdClientReturnCodes CrowdClient::checkPrincipleToken(std::string token) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__isValidPrincipalToken Token;
	_ns1__isValidPrincipalTokenResponse TokenResponse;
	Token.in0 = this->authToken;
	Token.in1 = &token;
	if (this->service->isValidPrincipalToken(this->url.c_str(), NULL, &Token, &TokenResponse) == SOAP_OK) {
		return TokenResponse.out ? CROWD_OK : CROWD_NAK;
	}
	return this->processFault();
}
CrowdClientReturnCodes CrowdClient::isGroupMember(std::string group, std::string user) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__isGroupMember GroupMember;
	_ns1__isGroupMemberResponse GroupMemberResponse;
	GroupMember.in0 = this->authToken;
	GroupMember.in1 = &group;
	GroupMember.in2 = &user;
	if (this->service->isGroupMember(this->url.c_str(), NULL, &GroupMember, &GroupMemberResponse) == SOAP_OK) {
		return GroupMemberResponse.out ? CROWD_OK : CROWD_NAK;
	}
	return this->processFault();
}

CrowdClientReturnCodes CrowdClient::resetPrinciplePassword(std::string user) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__resetPrincipalCredential reset;
	_ns1__resetPrincipalCredentialResponse resetResponse;
	reset.in0 = this->authToken;
	reset.in1 = &user;
	if (this->service->resetPrincipalCredential(this->url.c_str(), NULL, &reset, &resetResponse) == SOAP_OK) {
		return CROWD_OK;
	} else {
		return this->processFault();
	}
}
CrowdClientReturnCodes CrowdClient::getPrincipleByToken(std::string token, PrincipleDetails *attributes) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__findPrincipalByToken principle;
	_ns1__findPrincipalByTokenResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = &token;
	if (this->service->findPrincipalByToken(this->url.c_str(), NULL, &principle, &principleResponse) == SOAP_OK) {
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
		return CROWD_OK;
	}
	return this->processFault();
}

CrowdClientReturnCodes CrowdClient::getPrincipleAttributes(std::string username, PrincipleDetails *attributes) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__findPrincipalWithAttributesByName principle;
	_ns1__findPrincipalWithAttributesByNameResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = &username;
	if (this->service->findPrincipalWithAttributesByName(this->url.c_str(), NULL, &principle, &principleResponse) == SOAP_OK) {
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
		return CROWD_OK;
	}
	return this->processFault();
}

CrowdClientReturnCodes CrowdClient::getPrincipleByName(std::string username, PrincipleDetails *attributes) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__findPrincipalByName principle;
	_ns1__findPrincipalByNameResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = &username;
	if (this->service->findPrincipalByName(this->url.c_str(), NULL, &principle, &principleResponse) == SOAP_OK) {
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
		return CROWD_OK;
	}
	return this->processFault();

}

CrowdClientReturnCodes CrowdClient::getAllGroups(std::vector<std::string> *groups) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__findAllGroupNames findgroups;
	_ns1__findAllGroupNamesResponse findgroupsResponse;
	findgroups.in0 = this->authToken;
	if (this->service->findAllGroupNames(this->url.c_str(), NULL, &findgroups, &findgroupsResponse) == SOAP_OK) {
		groups->clear();
		groups->swap(findgroupsResponse.out->string);
		return CROWD_OK;
	}
	return this->processFault();
}

CrowdClientReturnCodes CrowdClient::getGroup(std::string groupname, GroupDetails *groupdetails) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__findGroupByName group;
	_ns1__findGroupByNameResponse groupResponse;
	group.in0 = this->authToken;
	group.in1 = &groupname;
	if (this->service->findGroupByName(this->url.c_str(), NULL, &group, &groupResponse) == SOAP_OK) {
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
		return CROWD_OK;
	}
	return this->processFault();
}

CrowdClientReturnCodes CrowdClient::getGroupAttributes(std::string groupname, GroupDetails *attributes) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__findGroupWithAttributesByName group;
	_ns1__findGroupWithAttributesByNameResponse groupResponse;
	group.in0 = this->authToken;
	group.in1 = &groupname;
	if (this->service->findGroupWithAttributesByName(this->url.c_str(), NULL, &group, &groupResponse) == SOAP_OK) {
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
		return CROWD_OK;
	}
	return this->processFault();
}
CrowdClientReturnCodes CrowdClient::getPrincipleGroups(std::string username, std::vector<std::string> *groups) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__findGroupMemberships groupmembership;
	_ns1__findGroupMembershipsResponse groupmembershipResponse;
	groupmembership.in0 = this->authToken;
	groupmembership.in1 = &username;
	if (this->service->findGroupMemberships(this->url.c_str(), NULL, &groupmembership, &groupmembershipResponse) == SOAP_OK) {
		groups->clear();
		groups->swap(groupmembershipResponse.out->string);
		return CROWD_OK;
	}
	return this->processFault();
}

CrowdClientReturnCodes CrowdClient::getApplicationGroups(std::vector<std::string> *groups) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__getGrantedAuthorities appgroups;
	_ns1__getGrantedAuthoritiesResponse appgroupsResponse;
	appgroups.in0 = this->authToken;
	if (this->service->getGrantedAuthorities(this->url.c_str(), NULL, &appgroups, &appgroupsResponse) == SOAP_OK) {
		groups->clear();
		groups->swap(appgroupsResponse.out->string);
		return CROWD_OK;
	}
	return this->processFault();
}
CrowdClientReturnCodes CrowdClient::getAllPrinciples(std::vector<std::string> *users) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__findAllPrincipalNames principles;
	_ns1__findAllPrincipalNamesResponse principlesResponse;
	principles.in0 = this->authToken;
	if (this->service->findAllPrincipalNames(this->url.c_str(), NULL, &principles, &principlesResponse) == SOAP_OK) {
		users->clear();
		users->swap(principlesResponse.out->string);
		return CROWD_OK;
	}
	return this->processFault();
}

CrowdClientReturnCodes CrowdClient::addPrinciple(std::string username, std::string firstname, std::string lastname, std::string email, std::string password, PrincipleDetails *attributes) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool ret = false;
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

	if (this->service->addPrincipal(this->url.c_str(), NULL, &principle, &principleResponse) == SOAP_OK) {
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
		ret = true;
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
	if (ret == false)
		return this->processFault();
	else
		return CROWD_OK;
}

CrowdClientReturnCodes CrowdClient::removePrinciple(std::string username) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__removePrincipal principle;
	_ns1__removePrincipalResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = &username;
	if (this->service->removePrincipal(this->url.c_str(), NULL, &principle, &principleResponse) == SOAP_OK) {
		return CROWD_OK;
	}
	return this->processFault();
}

CrowdClientReturnCodes CrowdClient::addPrincipleAttributes(std::string username, std::string attributename, std::vector<std::string> attributevals) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool ret = false;
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
	if (this->service->addAttributeToPrincipal(this->url.c_str(), NULL, &principle, &principleResponse) == SOAP_OK) {
		ret = true;
	}
	delete principle.in2->values;
	delete principle.in2;
	if (ret == false)
		return this->processFault();
	else
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
	if (this->service->removeAttributeFromPrincipal(this->url.c_str(), NULL, &attrib, &attribResponse) == SOAP_OK) {
		return CROWD_OK;
	}
	return this->processFault();
}

CrowdClientReturnCodes CrowdClient::updatePrincipleAttributes(std::string username, std::string attributename, std::vector<std::string> attributevals) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool ret = false;
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
	if (this->service->updatePrincipalAttribute(this->url.c_str(), NULL, &principle, &principleResponse) == SOAP_OK) {
		ret = true;
	}
	delete principle.in2->values;
	delete principle.in2;
	if (ret == false)
		return this->processFault();
	else
		return CROWD_OK;
}

CrowdClientReturnCodes CrowdClient::addGroup(std::string groupname, std::string description, GroupDetails *attributes) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool ret = false;
	_ns1__addGroup group;
	_ns1__addGroupResponse groupResponse;
	group.in0 = this->authToken;
	group.in1 = new ns3__SOAPGroup();
	group.in1->active = new bool(true);
	group.in1->name = &groupname;
	group.in1->description = &description;
	if (this->service->addGroup(this->url.c_str(), NULL, &group, &groupResponse) == SOAP_OK) {
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
		ret = true;
	}
	delete group.in1->active;
	delete group.in1;
	if (ret == false)
		return this->processFault();
	else
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
	if (this->service->updateGroup(this->url.c_str(), NULL, &group, &groupResponse) == SOAP_OK) {
		return CROWD_OK;
	}
	return this->processFault();

}
CrowdClientReturnCodes CrowdClient::removeGroup(std::string name) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__removeGroup group;
	_ns1__removeGroupResponse groupResponse;
	group.in0 = this->authToken;
	group.in1 = &name;
	if (this->service->removeGroup(this->url.c_str(), NULL, &group, &groupResponse) == SOAP_OK) {
		return CROWD_OK;
	}
	return this->processFault();
}
CrowdClientReturnCodes CrowdClient::addGroupMember(std::string groupname, std::string principle) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__addPrincipalToGroup group;
	_ns1__addPrincipalToGroupResponse groupResponse;
	group.in0 = this->authToken;
	group.in2 = &groupname;
	group.in1 = &principle;
	if (this->service->addPrincipalToGroup(this->url.c_str(), NULL, &group, &groupResponse) == SOAP_OK) {
		return CROWD_OK;
	}
	return this->processFault();

}
CrowdClientReturnCodes CrowdClient::removeGroupMember(std::string groupname, std::string principle) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	_ns1__removePrincipalFromGroup group;
	_ns1__removePrincipalFromGroupResponse groupResponse;
	group.in0 = this->authToken;
	group.in2 = &groupname;
	group.in1 = &principle;
	if (this->service->removePrincipalFromGroup(this->url.c_str(), NULL, &group, &groupResponse) == SOAP_OK) {
		return CROWD_OK;
	}
	return this->processFault();
}

CrowdClientReturnCodes CrowdClient::addGroupAttributes(std::string groupname, std::string attributename, std::vector<std::string> attributevals) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool ret = false;
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
	if (this->service->addAttributeToGroup(this->url.c_str(), NULL, &group, &groupResponse) == SOAP_OK) {
		ret = true;
	}
	delete group.in2->values;
	delete group.in2;
	if (ret == false)
		return this->processFault();
	else
		return CROWD_OK;
}

CrowdClientReturnCodes CrowdClient::updateGroupAttributes(std::string groupname, std::string attributename, std::vector<std::string> attributevals) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool ret = false;
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
	if (this->service->updateGroupAttribute(this->url.c_str(), NULL, &group, &groupResponse) == SOAP_OK) {
		ret = true;
	}
	delete group.in2->values;

	delete group.in2;
	if (ret == false)
		return this->processFault();
	else
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
	if (this->service->removeAttributeFromGroup(this->url.c_str(), NULL, &attrib, &attribResponse) == SOAP_OK) {
		return CROWD_OK;
	}
	return this->processFault();
}

CrowdClientReturnCodes CrowdClient::resetPrinciplePassword(std::string user, std::string password) {
	if (!this->isReady())
		return CROWD_ERR_NOT_READY;
	bool ret = false;
	_ns1__updatePrincipalCredential principle;
	_ns1__updatePrincipalCredentialResponse principleResponse;
	principle.in0 = this->authToken;
	principle.in1 = &user;
	principle.in2 = new ns2__PasswordCredential();
	principle.in2->credential = &password;
	principle.in2->encryptedCredential = new bool(false);
	if (this->service->updatePrincipalCredential(this->url.c_str(), NULL, &principle, &principleResponse) == SOAP_OK) {
		ret = true;
	}
	delete principle.in2->encryptedCredential;
	delete principle.in2;
	if (ret == false)
		return this->processFault();
	else
		return CROWD_OK;
}
