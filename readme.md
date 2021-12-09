[comment]: # "Auto-generated SOAR connector documentation"
# ZETAlytics

Publisher: ZETAlytics  
Connector Version: 1\.1\.0  
Product Vendor: ZETAlytics, Inc\.  
Product Name: ZETAlytics  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.0\.1068  

This App implements investigative actions that query the ZETAlytics security feed and APIs


ZETAlytics is a cyber security company focusing on the critical layer of network security.
Unrivalled geo-diversity and exclusive global network visibility enables Zetalytics to consistently
make early threat intel discoveries.

The ZETAlytics app requires a user token for authentication. To request a key, please visit
**https://zetalytics.com/phantom. ZETAlytics will respond to token requests within one business
day.**


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a ZETAlytics asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**ZL\_user\_hash** |  required  | string | ZETAlytics user hash

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[domain reputation](#action-domain-reputation) - Queries domain info  
[ip reputation](#action-ip-reputation) - Queries IP info  
[search keyword](#action-search-keyword) - Search for domain names containing a keyword  
[reverse nameserver](#action-reverse-nameserver) - Get a list of domains and hostnames for an authoritative nameserver  
[whois domain](#action-whois-domain) - Get whois information for the given domain  
[reverse email domain](#action-reverse-email-domain) - Return a list of domains registered with the given email domain  
[lookup ip](#action-lookup-ip) - Query ZETAlytics APIs for an IP address  
[lookup domain](#action-lookup-domain) - Query ZETAlytics APIs for a domain name  
[query d8s](#action-query-d8s) - Query the ZETAlytics D8s service  
[on poll](#action-on-poll) - Callback action to ingest security feed items  
[reverse email](#action-reverse-email) - Find domains with this email address in their Whois record or SOA email records  
[ip dns history](#action-ip-dns-history) - Find domains that have resolved to this IP address  
[domain dns history](#action-domain-dns-history) - Find IP addresses this domain has resolved to  
[lookup nameserver](#action-lookup-nameserver) - Get information for an authoritative nameserver  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'domain reputation'
Queries domain info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.status | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ip reputation'
Queries IP info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.tags | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'search keyword'
Search for domain names containing a keyword

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**keyword** |  required  | Keyword to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.keyword | string | 
action\_result\.status | string | 
action\_result\.summary\.count | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'reverse nameserver'
Get a list of domains and hostnames for an authoritative nameserver

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hostname** |  required  | Nameserver hostname to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.hostname | string | 
action\_result\.summary\.count | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'whois domain'
Get whois information for the given domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string | 
action\_result\.data\.\*\.whois\.creation\_date | string | 
action\_result\.data\.\*\.whois\.owner | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'reverse email domain'
Return a list of domains registered with the given email domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string | 
action\_result\.status | string | 
action\_result\.summary\.domain\_count | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup ip'
Query ZETAlytics APIs for an IP address

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string | 
action\_result\.data\.\*\.security\_feed\_tags | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup domain'
Query ZETAlytics APIs for a domain name

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string | 
action\_result\.data\.\*\.security\_feed\_tags | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'query d8s'
Query the ZETAlytics D8s service

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string | 
action\_result\.data\.\*\.d8s\.creation\_date | string | 
action\_result\.data\.\*\.d8s\.owner | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Callback action to ingest security feed items

Type: **generic**  
Read only: **True**

Callback action to ingest security feed items\. Configure periodic polling for the security feed when configuring the ZETAlytics asset using Ingest Settings\. Polling at five minute intervals is recommended\.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'reverse email'
Find domains with this email address in their Whois record or SOA email records

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email address to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.email | string | 
action\_result\.status | string | 
action\_result\.summary\.count | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ip dns history'
Find domains that have resolved to this IP address

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string | 
action\_result\.summary\.record\_count | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'domain dns history'
Find IP addresses this domain has resolved to

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string | 
action\_result\.summary\.record\_count | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup nameserver'
Get information for an authoritative nameserver

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hostname** |  required  | Nameserver hostname to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.hostname | string | 
action\_result\.summary\.record\_count | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 