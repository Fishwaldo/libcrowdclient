#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include "crowdclient.hpp"

int main(int argc, char **argv) {
	std::string host;
	std::string app;
	std::string pw;
	opterr = 0;
	int c;

	static struct option long_options[] = {
			{"help", no_argument, 0, 0},
			{"host", required_argument, 0, 'h'},
			{"app", required_argument, 0, 'a'},
			{"apppw", required_argument, 0, 'p'},
			{ 0, 0, 0, 0 }
	};
	int option_index = 0;
	while (( c = getopt_long(argc, argv, "h:a:p:", long_options, &option_index)) != -1) {
		switch (c) {
			case 0:
				std::cout << "Crowd Client Example Application" << std::endl;
				std::cout << "Usage: crowdclient --host <host> --app <app> --apppw <apppw>" << std::endl;
				exit(1);
				break;
			case 'a':
				app = optarg;
				break;
			case 'h':
				host = optarg;
				break;
			case 'p':
				pw = optarg;
				break;
			default:
				abort();
		}
	}
	if ((host.length() == 0)
			|| (app.length() == 0)
			|| (pw.length() == 0))
	{
		std::cerr << "Missing Required Arguements" << std::endl;
		exit(-1);
	}

	std::cout << "Host: " << host.append("/services/SecurityServer") << std::endl;
	std::cout << "App Name: " << app << std::endl;
	std::cout << "Password: " << pw << std::endl;


	try {
		CrowdClient::setExceptions(false);
		//		if (CrowdClient::setup("http://crowd.my-ho.st/crowd/services/SecurityServer", "crowdtest", "crowdtest") != CROWD_OK) {
		if (CrowdClient::setup(host, app, pw) != CROWD_OK) {
			std::cerr << "Setup Error" << std::endl;
			exit(-1);
		}

		CrowdClient *clnt = CrowdClient::Get();

		std::vector<std::string> allusers;
		std::string token;

		{
			if (clnt->getAllPrinciples(&allusers) == CROWD_OK) {
				std::cout << "Listing All Users: " << std::endl;
				for (int i = 0; i < allusers.size(); i++) {
					std::cout << "\t" << allusers.at(i) << std::endl;
				}
			} else {
				std::cout << "getAllPrinciples Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			PrincipleDetails attributes;
			if (clnt->getPrincipleAttributes(allusers.at(0), &attributes)) {
				std::cout << "getPrincipleAttributes for: " << allusers.at(0) << std::endl;
				std::cout << "\tID: " << attributes.id << std::endl;
				std::cout << "\tActive: " << (attributes.active ? "true" : "false") << std::endl;
				std::cout << "\tName: " << attributes.name << std::endl;
				std::cout << "\tConception: " << attributes.conception << std::endl;
				std::cout << "\tLast Modified: " << attributes.lastModified << std::endl;
				std::cout << "\tDescription: " << attributes.description << std::endl;
				std::cout << "\tDirectoryID: " << attributes.directoryId << std::endl;
				for (std::map<std::string, std::vector<std::string> >::iterator it = attributes.attributes.begin(); it != attributes.attributes.end(); it++) {
					std::cout << "\t" << it->first <<":"<< std::endl;
					for (int i = 0; i < it->second.size(); i++) {
						std::cout << "\t\t" << it->second.at(i) << std::endl;
					}
				}
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			PrincipleDetails attributes;
			if (clnt->getPrincipleByName(allusers.at(0), &attributes)) {
				std::cout << "getPrincipleByName for: " << allusers.at(0) << std::endl;
				std::cout << "\tID: " << attributes.id << std::endl;
				std::cout << "\tActive: " << (attributes.active ? "true" : "false") << std::endl;
				std::cout << "\tName: " << attributes.name << std::endl;
				std::cout << "\tConception: " << attributes.conception << std::endl;
				std::cout << "\tLast Modified: " << attributes.lastModified << std::endl;
				std::cout << "\tDescription: " << attributes.description << std::endl;
				std::cout << "\tDirectoryID: " << attributes.directoryId << std::endl;
				for (std::map<std::string, std::vector<std::string> >::iterator it = attributes.attributes.begin(); it != attributes.attributes.end(); it++) {
					std::cout << "\t" << it->first <<":"<< std::endl;
					for (int i = 0; i < it->second.size(); i++) {
						std::cout << "\t\t" << it->second.at(i) << std::endl;
					}
				}
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{

			std::vector<std::string> groupmembership;
			if (clnt->getPrincipleGroups(allusers.at(0), &groupmembership)) {
				std::cout << "getPrincipleGroups for: " << allusers.at(0) << std::endl;
				for (int i = 0; i < groupmembership.size(); i++) {
					std::cout << "\t" << groupmembership.at(i) << std::endl;
				}
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			PrincipleDetails attributes;
			std::cout << "addPrinciple for blah" << std::endl;
			if (clnt->addPrinciple("blah", "John", "Smith", "john@smith.com", "blah", &attributes)) {
				std::cout << "Attributes:" << std::endl;
				std::cout << "\tID: " << attributes.id << std::endl;
				std::cout << "\tActive: " << (attributes.active ? "true" : "false") << std::endl;
				std::cout << "\tName: " << attributes.name << std::endl;
				std::cout << "\tConception: " << attributes.conception << std::endl;
				std::cout << "\tLast Modified: " << attributes.lastModified << std::endl;
				std::cout << "\tDescription: " << attributes.description << std::endl;
				std::cout << "\tDirectoryID: " << attributes.directoryId << std::endl;
				for (std::map<std::string, std::vector<std::string> >::iterator it = attributes.attributes.begin(); it != attributes.attributes.end(); it++) {
					std::cout << "\t" << it->first <<":"<< std::endl;
					for (int i = 0; i < it->second.size(); i++) {
						std::cout << "\t\t" << it->second.at(i) << std::endl;
					}
				}
			}  else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			std::vector<std::string> vals;
			vals.push_back("test1");
			vals.push_back("test2");
			if (clnt->addPrincipleAttributes("blah", "blah", vals)) {
				std::cout << "addPrincipleAttributes for blah" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			std::vector<std::string> vals;
			vals.push_back("test3");
			vals.push_back("test4");
			if (clnt->updatePrincipleAttributes("blah", "blah", vals)) {
				std::cout << "updatePrincipleAttributes for blah" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->removePrincipleAttributes("blah", "blah")) {
				std::cout << "removePrincipleAttributes Deleted" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->resetPrinciplePassword("blah", "haha")) {
				std::cout << "resetPrinciplePassword for blah" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->authPrinciple("blah", "haha", &token)) {
				std::cout << "authPrinciple for blah: " << token << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->checkPrincipleToken(token)) {
				std::cout << "checkPrincipleToken for blah" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			PrincipleDetails attributes;
			if (clnt->getPrincipleByToken(token, &attributes)) {
				std::cout << "getPrincipleByToken for blah" << std::endl;
				std::cout << "\tID: " << attributes.id << std::endl;
				std::cout << "\tActive: " << (attributes.active ? "true" : "false") << std::endl;
				std::cout << "\tName: " << attributes.name << std::endl;
				std::cout << "\tConception: " << attributes.conception << std::endl;
				std::cout << "\tLast Modified: " << attributes.lastModified << std::endl;
				std::cout << "\tDescription: " << attributes.description << std::endl;
				std::cout << "\tDirectoryID: " << attributes.directoryId << std::endl;
				for (std::map<std::string, std::vector<std::string> >::iterator it = attributes.attributes.begin(); it != attributes.attributes.end(); it++) {
					std::cout << "\t" << it->first <<":"<< std::endl;
					for (int i = 0; i < it->second.size(); i++) {
						std::cout << "\t\t" << it->second.at(i) << std::endl;
					}
				}
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->deauthPrinciple(token)) {
				std::cout << "deauthPrinciple for blah" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->checkPrincipleToken(token)) {
				std::cout << "checkPrincipleToken for blah: Valid" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			GroupDetails attributes;
			if (clnt->addGroup("Group", "TestGroup", &attributes)) {
				std::cout << "Attributes:" << std::endl;
				std::cout << "\tID: " << attributes.id << std::endl;
				std::cout << "\tActive: " << (attributes.active ? "true" : "false") << std::endl;
				std::cout << "\tName: " << attributes.name << std::endl;
				std::cout << "\tConception: " << attributes.conception << std::endl;
				std::cout << "\tLast Modified: " << attributes.lastModified << std::endl;
				std::cout << "\tDescription: " << attributes.description << std::endl;
				std::cout << "\tDirectoryID: " << attributes.directoryId << std::endl;
				for (std::map<std::string, std::vector<std::string> >::iterator it = attributes.attributes.begin(); it != attributes.attributes.end(); it++) {
					std::cout << "\t" << it->first <<":"<< std::endl;
					for (int i = 0; i < it->second.size(); i++) {
						std::cout << "\t\t" << it->second.at(i) << std::endl;
					}
				}
				std::cout << "\tMembers:" << std::endl;
				for (int i = 0; i < attributes.members.size(); i++) {
					std::cout << "\t\t" << attributes.members.at(i) << std::endl;
				}
			}  else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->isGroupMember("Group", "blah")) {
				std::cout << "isGroupMember true" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->addGroupMember("Group", "blah")) {
				std::cout << "addGroupMember Blah to Group" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->isGroupMember("Group", "blah")) {
				std::cout << "isGroupMember true" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			GroupDetails attributes;
			if (clnt->getGroup("Group", &attributes)) {
				std::cout << "getGroup:" << std::endl;
				std::cout << "\tID: " << attributes.id << std::endl;
				std::cout << "\tActive: " << (attributes.active ? "true" : "false") << std::endl;
				std::cout << "\tName: " << attributes.name << std::endl;
				std::cout << "\tConception: " << attributes.conception << std::endl;
				std::cout << "\tLast Modified: " << attributes.lastModified << std::endl;
				std::cout << "\tDescription: " << attributes.description << std::endl;
				std::cout << "\tDirectoryID: " << attributes.directoryId << std::endl;
				for (std::map<std::string, std::vector<std::string> >::iterator it = attributes.attributes.begin(); it != attributes.attributes.end(); it++) {
					std::cout << "\t" << it->first <<":"<< std::endl;
					for (int i = 0; i < it->second.size(); i++) {
						std::cout << "\t\t" << it->second.at(i) << std::endl;
					}
				}
				std::cout << "\tMembers:" << std::endl;
				for (int i = 0; i < attributes.members.size(); i++) {
					std::cout << "\t\t" << attributes.members.at(i) << std::endl;
				}
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->updateGroup("Group", "TestNewGroup", false)) {
				std::cout << "Update Group" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			GroupDetails attributes;
			if (clnt->getGroupAttributes("Group", &attributes)) {
				std::cout << "getGroupAttributes:" << std::endl;
				std::cout << "\tID: " << attributes.id << std::endl;
				std::cout << "\tActive: " << (attributes.active ? "true" : "false") << std::endl;
				std::cout << "\tName: " << attributes.name << std::endl;
				std::cout << "\tConception: " << attributes.conception << std::endl;
				std::cout << "\tLast Modified: " << attributes.lastModified << std::endl;
				std::cout << "\tDescription: " << attributes.description << std::endl;
				std::cout << "\tDirectoryID: " << attributes.directoryId << std::endl;
				for (std::map<std::string, std::vector<std::string> >::iterator it = attributes.attributes.begin(); it != attributes.attributes.end(); it++) {
					std::cout << "\t" << it->first <<":"<< std::endl;
					for (int i = 0; i < it->second.size(); i++) {
						std::cout << "\t\t" << it->second.at(i) << std::endl;
					}
				}
				std::cout << "\tMembers:" << std::endl;
				for (int i = 0; i < attributes.members.size(); i++) {
					std::cout << "\t\t" << attributes.members.at(i) << std::endl;
				}
			}  else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}

		}
		{
			std::vector<std::string> vals;
			vals.push_back("test1");
			vals.push_back("test2");
			if (clnt->addGroupAttributes("Group", "blah", vals)) {
				std::cout << "addGroupAttributes" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			std::vector<std::string> vals;
			vals.push_back("test3");
			vals.push_back("test4");
			if (clnt->updateGroupAttributes("Group", "blah", vals)) {
				std::cout << "updateGroupAttributes" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			GroupDetails attributes;
			if (clnt->getGroupAttributes("Group", &attributes)) {
				std::cout << "getGroupAttributes for Group" << std::endl;
				std::cout << "\tID: " << attributes.id << std::endl;
				std::cout << "\tActive: " << (attributes.active ? "true" : "false") << std::endl;
				std::cout << "\tName: " << attributes.name << std::endl;
				std::cout << "\tConception: " << attributes.conception << std::endl;
				std::cout << "\tLast Modified: " << attributes.lastModified << std::endl;
				std::cout << "\tDescription: " << attributes.description << std::endl;
				std::cout << "\tDirectoryID: " << attributes.directoryId << std::endl;
				for (std::map<std::string, std::vector<std::string> >::iterator it = attributes.attributes.begin(); it != attributes.attributes.end(); it++) {
					std::cout << "\t" << it->first <<":"<< std::endl;
					for (int i = 0; i < it->second.size(); i++) {
						std::cout << "\t\t" << it->second.at(i) << std::endl;
					}
				}
				std::cout << "\tMembers:" << std::endl;
				for (int i = 0; i < attributes.members.size(); i++) {
					std::cout << "\t\t" << attributes.members.at(i) << std::endl;
				}
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->removeGroupMember("Group", "blah")) {
				std::cout << "removeGroupMember: blah from Group" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->removeGroupAttributes("Group", "blah")) {
				std::cout << "removeGroupAttributes: blah from Group" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			std::vector<std::string> groups;
			if (clnt->getAllGroups(&groups)) {
				std::cout << "getAllGroups: " << std::endl;
				for (int i = 0; i < groups.size(); i++) {
					std::cout << "\t" << groups.at(i) << std::endl;
				}
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			std::vector<std::string> appgroups;
			if (clnt->getApplicationGroups(&appgroups)) {
				std::cout << "getApplicationGroups: " << std::endl;
				for (int i = 0 ; i < appgroups.size(); i++) {
					std::cout << "\t" << appgroups.at(i) << std::endl;
				}
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->removeGroup("Group")) {
				std::cout << "Group Removed" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}
		{
			if (clnt->removePrinciple("blah")) {
				std::cout << "Removed Principle" << std::endl;
			} else {
				std::cout << "getPrincipleAttributes Error: Code: " << clnt->getErrorCode() << " Msg: " << clnt->getErrorMsg() << std::endl;
			}
		}

		delete clnt;
	} catch ( CrowdException &e) {
		std::cout << "Exception Code:" << e.type() << " " << e.what() << std::endl;
	} catch (...) {
		std::cout << "Unhandled Exception" << std::endl;
	}
}
