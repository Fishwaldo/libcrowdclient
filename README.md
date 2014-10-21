# LibCrowdClient - A C++ Library to interface with Atlassian Crowd 

This is a pure C++ library that interfaces with Atlassian Crowd for 
Authentication and Authorization. You can use this library to 
interface your applications with the Crowd Identity Management 
server at http://www.atlassian.com/software/crowd/overview

It implments most of the SOAP API calls exposed by Crowd for
authentication, and managing users and groups. Some of the
features missing currently are:

* Roles (depreciated in Crowd)
* Searching for Users/Groups (Planned)
* Cacheing (Planned)
* SSO based on Cookies/Headers (Planned)

You can view the details of the Crowd SOAP API here:
https://docs.atlassian.com/atlassian-crowd/latest/com/atlassian/crowd/service/soap/server/SecurityServer.html

The API is a simple Single Static (optional) class and it
handles all the remote calls automatically. It works synchronous manor,
so all calls complete, and can be configured to either throw
exceptions of failures (like Authentication Failures, or communication
failures) to returning status codes. 

The API allows you to authenticate users, create/delete/modify users
and groups and authenticate your application. No Server Side code is 
necessary to support this.

Installation
------------

Installation is straight forward on the crowd side, just create a new
"generic application" in crowd, with a appname, password and the IP address
filled in. Assign your directories (the first directory will be where new
users/groups are created) and then in the CrowdClient api, call 
CrowdClient::Setup(<url of crowd server>, <appname>, <apppassword>);

A Sample Application is included, called crowdclient, that will exercise all
the SOAP API, so you can refer to that for further information on
how to operate the API. 

Contact
-------
Please file Bug Reports, enhancements etc at http://jira.my-ho.st/jira/browse/LCC


