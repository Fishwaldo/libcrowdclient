/* crowd-c++ - crowdclient.hpp
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

/** @file crowdclient.hpp
 *  @brief
 */



#ifndef CROWDCLIENT_HPP_
#define CROWDCLIENT_HPP_

#include <string>
#include <map>
#include <vector>
#include <stdint.h>

class ns2__AuthenticatedToken;
class SecurityServerHttpBindingProxy;

struct PrincipleDetails {
		int64_t id;
		bool active;
		time_t conception;	/* optional element of type xsd:dateTime */
		std::string description;	/* optional element of type xsd:string */
		int64_t directoryId;	/* optional element of type xsd:long */
		time_t lastModified;	/* optional element of type xsd:dateTime */
		std::string name;	/* optional element of type xsd:string */
		std::map<std::string, std::vector<std::string> > attributes;
};
struct GroupDetails {
		int64_t id;
		bool active;
		time_t conception;	/* optional element of type xsd:dateTime */
		std::string description;	/* optional element of type xsd:string */
		int64_t directoryId;	/* optional element of type xsd:long */
		time_t lastModified;	/* optional element of type xsd:dateTime */
		std::string name;	/* optional element of type xsd:string */
		std::map<std::string, std::vector<std::string> > attributes;
		std::vector<std::string> members;
};

enum CrowdClientReturnCodes {
	CROWD_OK = 1,
	CROWD_NAK = 0,
	CROWD_ERR_APPLICATION_ACCESS_DENIED = -1,
	CROWD_ERR_APPLICATION_PERMISSION = -2,
	CROWD_ERR_BULK_ADD_FAILED = -3,
	CROWD_ERR_EXPIRED_CREDENTIAL = -4,
	CROWD_ERR_INACTIVE_ACCOUNT = -5,
	CROWD_ERR_INVALID_AUTHENTICATION = -6,
	CROWD_ERR_INVALID_AUTHORIZATION = -7,
	CROWD_ERR_INVALID_CREDENTIAL = -8,
	CROWD_ERR_INVALID_EMAIL = -9,
	CROWD_ERR_INVALID_GROUP = -10,
	CROWD_ERR_INVALID_ROLE = -11,
	CROWD_ERR_INVALID_TOKEN = -12,
	CROWD_ERR_INVALID_USER = -13,
	CROWD_ERR_OBJECT_NOT_FOUND = -14,
	CROWD_ERR_REMOTE_EXCEPTION = -15,
	CROWD_ERR_NOT_READY = -16,
	CROWD_ERR_UNKNOWN = -254
};

class CrowdException: public std::exception
{
public:
    /** Constructor (C strings).
     *  @param message C-style string error message.
     *                 The string contents are copied upon construction.
     *                 Hence, responsibility for deleting the \c char* lies
     *                 with the caller.
     */
    explicit CrowdException(const CrowdClientReturnCodes code, const char* message):
    code_(code),
    msg_(message)
      {
      }

    /** Constructor (C++ STL strings).
     *  @param message The error message.
     */
    explicit CrowdException(const CrowdClientReturnCodes code, const std::string& message):
		code_(code),
		msg_(message)
      {}

    /** Destructor.
     * Virtual to allow for subclassing.
     */
    virtual ~CrowdException() throw (){}

    /** Returns a pointer to the (constant) error description.
     *  @return A pointer to a \c const \c char*. The underlying memory
     *          is in posession of the \c Exception object. Callers \a must
     *          not attempt to free the memory.
     */
    virtual const char* what() const throw (){
       return msg_.c_str();
    }
    /** Return a CrowdClientReturnCodes (constant) to identify the error.
     *
     */
    virtual const CrowdClientReturnCodes type() const throw() {
    	return code_;
    }

protected:
    /** Error message.
     */
    std::string msg_;
    CrowdClientReturnCodes code_;
};


class CrowdClient {
public:
		static CrowdClient *Get();
		~CrowdClient();
		static bool isReady();
		static CrowdClientReturnCodes setup(std::string url, std::string appname, std::string password);
		static void setExceptions(bool enabled);

		CrowdClientReturnCodes getErrorCode();
		std::string getErrorMsg();



		CrowdClientReturnCodes authApplication();
		CrowdClientReturnCodes getApplicationGroups(std::vector<std::string> *groups);
		CrowdClientReturnCodes authPrinciple(std::string username, std::string password, std::string *token);
		CrowdClientReturnCodes deauthPrinciple(std::string token);
		CrowdClientReturnCodes checkPrincipleToken(std::string token);
		CrowdClientReturnCodes resetPrinciplePassword(std::string user);
		CrowdClientReturnCodes resetPrinciplePassword(std::string user, std::string password);
		CrowdClientReturnCodes getPrincipleByToken(std::string token, PrincipleDetails *attributes);
		CrowdClientReturnCodes getPrincipleAttributes(std::string username, PrincipleDetails *attributes);
		CrowdClientReturnCodes addPrincipleAttributes(std::string username, std::string attributename, std::vector<std::string> attributevals);
		CrowdClientReturnCodes removePrincipleAttributes(std::string username, std::string attribute);
		CrowdClientReturnCodes updatePrincipleAttributes(std::string username, std::string attributename, std::vector<std::string> attributevals);
		CrowdClientReturnCodes getPrincipleByName(std::string username, PrincipleDetails *attributes);
		CrowdClientReturnCodes getPrincipleGroups(std::string username, std::vector<std::string> *groups);
		CrowdClientReturnCodes addPrinciple(std::string username, std::string firstname, std::string lastname, std::string email, std::string password, PrincipleDetails *attributes);
		CrowdClientReturnCodes removePrinciple(std::string username);

		CrowdClientReturnCodes getAllPrinciples(std::vector<std::string> *users);

		CrowdClientReturnCodes getAllGroups(std::vector<std::string> *groups);
		CrowdClientReturnCodes getGroup(std::string group, GroupDetails *attributes);
		CrowdClientReturnCodes getGroupAttributes(std::string group, GroupDetails *attributes);
		CrowdClientReturnCodes addGroup(std::string name, std::string description, GroupDetails *attributes);
		CrowdClientReturnCodes updateGroup(std::string name, std::string description, bool active);
		CrowdClientReturnCodes removeGroup(std::string name);
		CrowdClientReturnCodes addGroupMember(std::string groupname, std::string principle);
		CrowdClientReturnCodes removeGroupMember(std::string groupname, std::string principle);
		CrowdClientReturnCodes isGroupMember(std::string group, std::string user);
		CrowdClientReturnCodes addGroupAttributes(std::string groupname, std::string attributename, std::vector<std::string> attributevals);
		CrowdClientReturnCodes updateGroupAttributes(std::string groupname, std::string attributename, std::vector<std::string> attributevals);
		CrowdClientReturnCodes removeGroupAttributes(std::string groupname, std::string attribute);


private:
		CrowdClient();
		CrowdClientReturnCodes processFault();

		static CrowdClient *instance;
		static bool ready;

		SecurityServerHttpBindingProxy *service;


		ns2__AuthenticatedToken *authToken;
		std::string url;
		std::string appname;
		std::string password;
		static CrowdClientReturnCodes errorcode;
		static bool throwenabled;
};






#endif /* CROWDCLIENT_HPP_ */
