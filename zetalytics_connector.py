# -----------------------------------------
# ZETAlytics App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.rules as phrules

# Usage of the consts file is recommended
# from zetalytics_consts import *
import requests
import json


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ZetalyticsConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ZetalyticsConnector, self).__init__()

        self._state = None

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = 'https://zonecruncher.com/' + self._user_hash + '/terabithia/security/'
        self.save_progress('Connecting to ' + url)
        self.save_progress('This may take a few minutes')

        r = requests.get(url)

        if not r.status_code == 200:
            self.save_progress("Test Connectivity Failed.")
            msg = "Connection error. Response code " + r.status_code
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def getSecurityFeedTags(self, domain=None, ip=None, cidr=None):
        data = phrules.get_data('ZL', clear_data=False)

        tags = ''
        if domain:
            if domain in data['hnames']:
                for tag in data['hnames'][domain]:
                    tags = tags + 'zetalytics-' + tag + ', '
                tags = tags.rstrip(', ')

        if ip:
            if ip in data['ips']:
                for tag in data['ips'][ip]:
                    tags = tags + 'zetalytics-' + tag + ', '
                tags = tags.rstrip(', ')

        if cidr:
            if cidr in data['cidrs']:
                for tag in data['cidrs'][cidr]:
                    tags = tags + 'zetalytics-' + tag + ', '
                tags = tags.rstrip(', ')

        if tags == '':
            tags = 'None'

        return tags

    def getCurrentDNS(self, domain):

        url = 'https://zonecruncher.com/' + self._user_hash + '/terabithia/json-digat?d=' + domain
        r = requests.get(url)

        if r.status_code == 200:
            data = r.json()
            return data['results']

        return None

    def getDomainWhois(self, domain):

        whois = {}

        url = 'https://zonecruncher.com/' + self._user_hash + '/terabithia/json-d8s?d=' + domain
        # url = 'https://zonecrcher.com/' + self._user_hash + '/terabithi/json-d8s?d=' + domain

        # try:
        r = requests.get(url)
        # except requests.exceptions.ConnectionError as e:
        #    msg = "Connection failed to zonecruncher.com d8s"
        #    # return self.set_status_save_progress(phantom.APP_ERROR, msg)
        #    return self.set_status_save_progress(phantom.APP_ERROR, str(e))

        # if not r.status_code == 200:
        #    msg = "Connection error. Response code " + r.status_code
        #    # return self.set_status_save_progress(phantom.APP_ERROR, msg)
        #    return self.set_status(phantom.APP_ERROR, msg)

        data = r.json()

        try:
            whois['creation_date'] = data['response']['c']
        except KeyError:
            pass

        try:
            whois['update_date'] = data['response']['u']
        except KeyError:
            pass

        try:
            whois['expire_date'] = data['response']['e']
        except KeyError:
            pass

        try:
            whois['registrar'] = data['response']['r']
        except KeyError:
            pass

        try:
            whois['owner'] = data['response']['o']
        except KeyError:
            pass

        try:
            whois['registration_emails'] = data['response']['x']
        except KeyError:
            pass

        try:
            whois['nameservers'] = data['response']['n']
        except KeyError:
            pass

        try:
            whois['status'] = data['response']['s']
        except KeyError:
            pass

        return whois

    def getRawWhois(self, domain):

        url = 'https://zonecruncher.com/' + self._user_hash + '/terabithia/json-get-raw-whois?subject=' + domain
        r = requests.get(url)
        if r.status_code == 200:
            try:
                data = r.json()
                return data['rawdata']
            except:
                return None
        else:
            return None

    def getNetblockWhois(self, ip):

        whois = {}

        url = 'https://zonecruncher.com/' + self._user_hash + '/terabithia/json-d8s-ip?ip=' + ip
        r = requests.get(url)

        if r.status_code == 200:
            data = r.json()
            for label in data['results']:
                for value in label:

                    if value == 'c':
                        whois['creation_date'] = label[value]
                    elif value == 'r':
                        whois['rir'] = label[value]
                    elif value == 'o':
                        whois['owner_name'] = label[value]
                    elif value == 's':
                        whois['status'] = label[value]
                    elif value == 'y':
                        whois['country_code'] = label[value]
                    elif value == 'a':
                        whois['asn'] = label[value]
                    elif value == 'x':
                        whois['email'] = label[value]
                    elif value == 'ptr':
                        whois['ptr'] = label[value]
                    elif value == 'rdns':
                        whois['rdns'] = label[value]
                    elif value == 'ptrns':
                        whois['ptrns'] = label[value]
                    elif value == 'ptrnsq':
                        whois['ptrnsq'] = label[value]
                    elif value == 'ptrsoa':
                        whois['ptrsoa'] = label[value]
                    elif value == 'u':
                        whois['u'] = label[value]

        return whois

    def getReverseEmailDomain(self, domain):

        url = 'https://zonecruncher.com/' + self._user_hash + '/_search/d8s_email?all_email.domain=' + domain
        # url = 'https://zonecruncher.com/' + self._user_hash + '/_search/d8s_email?all_email.domain=' + domain + '&size=2'
        r = requests.get(url)

        domains = {}

        if r.status_code == 200:

            data = json.loads(r.text)

            for record in data['results']:
                d = record['d']
                domains[d] = {}

                try:
                    domains[d]['creation_date'] = record['c']
                except KeyError:
                    pass

                try:
                    domains[d]['expire_date'] = record['e']
                except KeyError:
                    pass

                try:
                    domains[d]['update_date'] = record['u']
                except KeyError:
                    pass

                try:
                    domains[d]['owner'] = record['o']
                except KeyError:
                    pass

                try:
                    domains[d]['status'] = record['s']
                except KeyError:
                    pass

                try:
                    domains[d]['first_seen'] = record['first_ts']
                except KeyError:
                    pass

                try:
                    domains[d]['last_seen'] = record['last_ts']
                except KeyError:
                    pass

                try:
                    domains[d]['registrar'] = record['r']
                except KeyError:
                    pass

                try:
                    domains[d]['nameservers'] = record['n']
                except KeyError:
                    pass

        return domains

    def checkTor(self, ip):

        url = 'https://zonecruncher.com/' + self._user_hash + '/terabithia/json-lookup-tor?ip=' + ip + '&mask=32'
        r = requests.get(url)

        response = []

        if r.status_code == 200:
            try:
                data = r.json()
                for record in data['hits']['hits']:
                    result = {}
                    result['ts'] = record['_source']['ts']
                    result['name'] = record['_source']['name']
                    result['rport'] = record['_source']['rport']
                    result['dport'] = record['_source']['dport']
                    result['type'] = record['_type']
                    response.append(result)
            except:
                pass

        return response

    def getMalwareDNSActivity(self, domain):

        url = 'https://zonecruncher.com/' + self._user_hash + '/terabithia/discovery-malware-domain-strings?s=' + domain + '&t=hname'
        r = requests.get(url)

        response = []

        if r.status_code == 200:
            data = r.json()
            for record in data['hits']['hits']:
                result = {}
                result['ts'] = record['_source']['ts']
                result['hash'] = record['_source']['hash']
                result['hname'] = record['_source']['hname']
                result['ip'] = record['_source']['ipv4']
                response.append(result)

        return response

    def getIPMalwareDNSActivity(self, ip):

        url = 'https://zonecruncher.com/' + self._user_hash + '/terabithia/discovery-malware-domain-strings?s=' + ip + '/32&t=ipv4'
        r = requests.get(url)

        response = []

        if r.status_code == 200:
            try:
                data = r.json()
                for record in data['hits']['hits']:
                    result = {}
                    result['ts'] = record['_source']['ts']
                    result['hash'] = record['_source']['hash']
                    result['hname'] = record['_source']['hname']
                    result['ip'] = record['_source']['ipv4']
                    response.append(result)
            except:
                pass

        return response

    def getReverseDomain(self, domain):

        url = 'https://zonecruncher.com/' + self._user_hash + '/_search/1203-j-passive-ns?q=' + domain
        r = requests.get(url)

        if r.status_code == 200:
            data = r.json()
            return data['results']

    def getReverseIP(self, ip):

        url = 'https://zonecruncher.com/' + self._user_hash + '/terabithia/j-rdata?mask=32&ip=' + ip

        r = requests.get(url)
        if r.status_code == 200:
            try:
                data = r.json()
                return data['results']
            except:
                return []

        return []

    def getRDNS(self, ip):

        response = []

        url = 'https://zonecruncher.com/' + self._user_hash + '/terabithia/json-lookup-ptr?ip=' + ip + '&mask=32'
        r = requests.get(url)
        if r.status_code == 200:
            try:
                data = r.json()
                for record in data['hits']['hits']:
                    result = {}
                    result['hname'] = record['_source']['hname']
                    result['ip'] = record['_source']['ipv4']
                    result['first_ts'] = record['_source']['first_ts']
                    result['last_ts'] = record['_source']['last_ts']
                    response.append(result)
            except:
                pass

        return response

    def getReverseNS(self, ns):

        # url = 'https://zonecruncher.com/' + self._user_hash + '/zonedata/ns2domains?q=' + ns + '&size=4000'
        url = 'https://zonecruncher.com/' + self._user_hash + '/zonedata/ns2domains?q=' + ns

        domains = {}

        self.save_progress('Attempting ns2domains query for ' + ns)
        r = requests.get(url)
        if r.status_code == 200:
            data = r.json()

            for record in data['results']:
                domains[record['domain']] = {}
                domains[record['domain']]['creation_date'] = record['date']
                domains[record['domain']]['last_seen'] = record['last_seen']

        return domains

    def getNSGlue(self, domain):

        url = 'https://zonecruncher.com/' + self._user_hash + '/terabithia/json-lookup-ns-glue-history?d=' + domain
        response = []
        r = requests.get(url)
        if r.status_code == 200:
            data = r.json()
            for record in data['hits']['hits']:
                result = {}
                result['hname'] = record['_source']['hname']
                result['ip'] = record['_source']['ipv4']
                result['ts'] = record['_source']['ts']
                response.append(result)

        return response

    def _handle_domain_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']

        response = {}
        response['domain'] = domain

        tags = self.getSecurityFeedTags(domain=domain)

        response['tags'] = tags

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['tags'] = response['tags']

        return action_result.set_status(phantom.APP_SUCCESS)

    # Question - keep Tor?
    def _handle_ip_reputation(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']

        response = {}
        response['ip'] = ip

        tags = self.getSecurityFeedTags(ip=ip)

        response['tags'] = tags
        response['tor'] = self.checkTor(ip)

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['tags'] = response['tags']
        if response['tor']:
            summary['tor'] = True

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_search_keyword(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        keyword = param['keyword']
        url = 'https://zonecruncher.com/' + self._user_hash + '/zonedata/search-1k-maps-term?q=' + keyword

        r = requests.get(url)

        domains = {}

        if not r.status_code == 200:
            msg = "Connection error. Response code " + r.status_code
            return action_result.set_status(phantom.APP_ERROR, msg)

        data = r.json()

        for record in data['results']:
            domains[record['domain']] = {}
            domains[record['domain']]['ns'] = record['ns']

        action_result.add_data(domains)

        summary = action_result.update_summary({})
        summary['count'] = data['metadata']['counts']['matched']

        return action_result.set_status(phantom.APP_SUCCESS)

    # TO DO: Add parameter for result size
    def _handle_reverse_ns(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ns = param['hostname']

        response = {}
        response['nameserver'] = ns

        response['domains'] = self.getReverseNS(ns)
        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary['count'] = len(response['domains'])
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_whois_domain(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']

        response = {}
        response['domain'] = domain
        d8s = self.getDomainWhois(domain)

        if d8s:
            response['whois'] = d8s
            summary = action_result.update_summary({})
            try:
                summary['creation_date'] = response['whois']['creation_data']
                summary['owner'] = response['whois']['owner']
            except KeyError:
                pass

        response['raw_whois'] = self.getRawWhois(domain)

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    # Do we want to return only a list of domains or additional metadata (owner, create date, first seen, etc)
    def _handle_reverse_email_domain(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']

        response = {}
        response['email_domain'] = domain
        response['domains'] = self.getReverseEmailDomain(domain)

        action_result.add_data(response)

        summary = action_result.update_summary({})

        summary['domain_count'] = len(response['domains'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']

        response = {}
        response['ip'] = ip

        tags = self.getSecurityFeedTags(ip=ip)

        response['security_feed_tags'] = tags
        response['whois'] = {}
        response['whois'] = self.getNetblockWhois(ip)
        response['tor'] = self.checkTor(ip)
        response['dns_history'] = self.getReverseIP(ip)
        response['malware_dns'] = self.getIPMalwareDNSActivity(ip)
        response['rdns'] = self.getRDNS(ip)

        action_result.add_data(response)

        summary = action_result.update_summary({})

        if response['security_feed_tags']:
            summary['security_feed_tags'] = response['security_feed_tags']

        if response['malware_dns']:
            summary['malware_dns'] = len(response['malware_dns'])

        if response['tor']:
            summary['tor_data'] = len(response['tor'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_domain(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']

        response = {}
        response['domain'] = domain
        response['whois'] = self.getDomainWhois(domain)
        response['raw_whois'] = self.getRawWhois(domain)
        response['security_feed_tags'] = self.getSecurityFeedTags(domain=domain)
        response['dig'] = self.getCurrentDNS(domain)
        response['malware_dns'] = self.getMalwareDNSActivity(domain)
        response['dns_history'] = self.getReverseDomain(domain)
        response['ns_glue'] = self.getNSGlue(domain)

        action_result.add_data(response)

        summary = action_result.update_summary({})

        if response['security_feed_tags']:
            summary['security_feed_tags'] = response['security_feed_tags']

        if response['malware_dns']:
            summary['malware_dns'] = len(response['malware_dns'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ns(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ns = param['hostname']

        response = {}
        response['nameserver'] = ns
        response['reverse_ns'] = self.getReverseNS(ns)

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['record_count'] = len(response['reverse_ns'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_d8s(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']

        response = {}
        response['domain'] = domain
        response['d8s'] = self.getDomainWhois(domain)

        action_result.add_data(response)

        summary = action_result.update_summary({})
        try:
            summary['creation_date'] = response['whois']['creation_data']
            summary['owner'] = response['whois']['owner']
        except KeyError:
            pass

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress('Downloading ZETAlytics security feeds. This may take a few minutes')

        summary = {}
        summary['hnames'] = {}
        summary['ips'] = {}
        summary['cidrs'] = {}

        files = {}
        files['highconf'] = 'https://zonecruncher.com/' + self._user_hash + '/dl/highconf?format=json'
        files['highrisk'] = 'https://zonecruncher.com/' + self._user_hash + '/dl/highrisk?format=json'
        files['beacon'] = 'https://zonecruncher.com/' + self._user_hash + '/dl/beacon?format=json'
        files['beacon-nxd'] = 'https://zonecruncher.com/' + self._user_hash + '/dl/beacon-nxd?format=json'
        files['jthits'] = 'https://zonecruncher.com/' + self._user_hash + '/dl/jthits?format=txt'
        files['highrisk-ips'] = 'https://zonecruncher.com/' + self._user_hash + '/dl/highrisk-ips?format=json'
        files['highrisk-cidrs'] = 'https://zonecruncher.com/' + self._user_hash + '/dl/highrisk-cidrs?format=json'

        for f in files:
            url = files[f]
            self.save_progress('Connecting to ' + f)
            r = requests.get(url)

            if not r.status_code == 200:
                msg = "Connection error. Response code " + r.status_code
                return action_result.set_status(phantom.APP_ERROR, msg)

            if url.endswith('json'):
                data = r.json()
                self.save_progress(str(len(data['results'])))
                for record in data['results']:
                    try:
                        domain = record['hname']
                        if domain not in summary['hnames']:
                            summary['hnames'][domain] = set()

                        for tag in record['tags']:
                            summary['hnames'][domain].add(tag)
                    except KeyError:
                        pass

                    try:
                        ip = record['IPv4']
                        if ip not in summary['ips']:
                            summary['ips'][ip] = set()

                        for tag in record['tags']:
                            summary['ips'][ip].add(tag)
                    except KeyError:
                        pass

                    try:
                        cidr = record['CIDRv4']
                        if cidr not in summary['cidrs']:
                            summary['cidrs'][cidr] = set()

                        for tag in record['tags']:
                            summary['cidrs'][cidr].add(tag)
                    except KeyError:
                        pass

            elif url.endswith('txt'):
                for line in r.text.splitlines():
                    domain = line.strip()
                    if domain not in summary['hnames']:
                        summary['hnames'][domain] = set()

                    summary['hnames'][domain].add('jthits')

        phrules.save_data(summary, key='ZL')

        try:
            self.save_progress('Saving ' + str(len(summary['hnames'])) + ' security feed hname records')
            self.save_progress('Saving ' + str(len(summary['ips'])) + ' security feed IPv4 records')
            self.save_progress('Saving ' + str(len(summary['cidrs'])) + ' security feed CIDR records')
        except:
            self.save_progress('Encountered exception while storing security feed records')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_reverse_email(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        email = param['email']
        url = 'https://zonecruncher.com/' + self._user_hash + '/_search/d8s_email?size=500&email=' + email

        response = {}
        response['email'] = email

        r = requests.get(url)
        if not r.status_code == 200:
            msg = "Connection error. Response code " + r.status_code
            return action_result.set_status(phantom.APP_ERROR, msg)

        data = r.json()

        domains = []

        for record in data['results']:
            domain = {}
            domain['domain'] = record['d']
            domain['first_ts'] = record['first_ts']
            domain['last_ts'] = record['last_ts']
            domains.append(domain)

        response['reverse_email'] = domains
        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['count'] = data['total']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ip_dns_history(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']

        response = {}
        response['ip'] = ip

        response['dns_history'] = self.getReverseIP(ip)

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['record_count'] = len(response['dns_history'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_dns_history(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']

        response = {}
        response['domain'] = domain

        response['dns_history'] = self.getReverseDomain(domain)

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['record_count'] = len(response['dns_history'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'domain_reputation':
            ret_val = self._handle_domain_reputation(param)

        elif action_id == 'ip_reputation':
            ret_val = self._handle_ip_reputation(param)

        elif action_id == 'search_keyword':
            ret_val = self._handle_search_keyword(param)

        elif action_id == 'reverse_ns':
            ret_val = self._handle_reverse_ns(param)

        elif action_id == 'whois_domain':
            ret_val = self._handle_whois_domain(param)

        elif action_id == 'reverse_email_domain':
            ret_val = self._handle_reverse_email_domain(param)

        elif action_id == 'lookup_ip':
            ret_val = self._handle_lookup_ip(param)

        elif action_id == 'lookup_domain':
            ret_val = self._handle_lookup_domain(param)

        elif action_id == 'd8s':
            ret_val = self._handle_d8s(param)

        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        elif action_id == 'reverse_email':
            ret_val = self._handle_reverse_email(param)

        elif action_id == 'ip_dns_history':
            ret_val = self._handle_ip_dns_history(param)

        elif action_id == 'domain_dns_history':
            ret_val = self._handle_domain_dns_history(param)

        elif action_id == 'lookup_ns':
            ret_val = self._handle_lookup_ns(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        self._user_hash = config['ZL_user_hash']

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ZetalyticsConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
