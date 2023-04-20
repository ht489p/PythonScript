#!/usr/bin/python3
#mcd-aot-conversion init venue group
#mcd-aot-conversion verify venue group
#mcd-aot-conversion tac pre
#mcd-aot-conversion tac post
from ArubaApi import ArubaApi,Token
from simple_salesforce import Salesforce,format_soql,exceptions
from netmiko import ConnectHandler
import os
import pandas as pd
import json
import sys
import datetime
import logging
from argparse import ArgumentParser,RawTextHelpFormatter
import getpass
import time
import re
import configparser
import base64

date = datetime.datetime.now()

def check_arguments():
        parser = ArgumentParser(add_help=True, description = 'This tool can be used during mcd aot conversions.', formatter_class=RawTextHelpFormatter)
        parser.add_argument('action', choices=['start','verify','prechecks','postchecks'], help='The action you\'d like to take.\n\n' \
                                'start = Gather asset info, put switches in monitor mode, create a config backup,\n' \
                                'allow venue through variables firewall, and make Sales Force updates.\n\n' \
                                'verify = Verify configs got pushed to APC by checking some key asset variables,\n' \
                                'and put group back in variables firewall if variables are good.\n\n' \
                                'prechecks = Find what switch the gateway plugs into so ITAC can confirm it\n' \
                                'correlates to "Switch 1" in sales force, and run ping test to end user devices.\n' \
                                'postchecks = Add new VSF stack to Site label since it gets a new stack id/serial.')
        parser.add_argument('venue', help='The venues\' ID, which can be found in sales force, for ex: a030z00000kemAF')
        parser.add_argument('group', help='The group name, for ex: a030z00000kemAF_32034.')
        parser.add_argument('-logfile', default='mcd-aot-conversion.log', help='Script output is logged in this file. Default is mcd-aot-conversion.log')
        parser.add_argument('-debug', help='Log debug info.')

        args = parser.parse_args()
        return args

def get_logger(logger_name, output_log, debug):
        console_formatter = logging.Formatter('%(message)s')
        file_formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
        if debug == 'DEBUG':
                logger.setLevel(logging.DEBUG)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        #file_handler = logging.FileHandler(output_log, mode='a')
        file_handler = logging.handlers.RotatingFileHandler(output_log, maxBytes=10485760, backupCount=3)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        logger.propagate = False
        return logger

def check_dir(path):
        #if directory doesn't exist then create it
        if not os.path.exists(path):
                os.makedirs(path)

def get_assets_apc(group, asset_type):
        asset_dict = {}
        if asset_type == 'switches':
                assets = api.ListSwitches(filter_by='group', id=group)
        elif asset_type == 'aps':
                assets = api.ListAccessPoints(filter_by='group', id=group)
        elif asset_type == 'gateways':
                assets = api.ListMobilityControllers(filter_by='group', id=group)
        for a in assets:
                asset_dict[a['serial']] = {'name': a['name'], 'ip': a['ip_address'], 'status': a['status']}
        if asset_dict:
                logger.info('venue: %s group: %s got %s info from apc' %(args.venue, args.group, asset_type))
        else:
                logger.info('venue: %s group: %s no %s info found in apc' %(args.venue, args.group, asset_type))
        return asset_dict

def set_config_mode(asset_dict, mode):
        sns = list(asset_dict.keys())
        result = api.SetDevicesCfgMode(sns, mode)
        if result == 0:
                logger.info('venue: %s group: %s serials: %s updated to %s mode' %(args.venue, args.group, sns, mode))
        else:
                logger.error('venue: %s group: %s serials: %s could not update to %s mode.  Re-try or set manually via APC.' %(args.venue, args.group, sns, mode))
                sys.exit(1)

def create_config_backup(group):
        result = api.GroupSnapshot(group, 'MCD-before-AOT-conversion')
        logger.info('venue: %s group: %s config backup results: %s' %(args.venue, group, result))

def allow_through_varfw(group):
        varfw_groups = api.GetVarFwGroups()['groups']
        if group not in varfw_groups:
                #since AddGroupVarFw takes a list of group, convert string to a list
                group_list = [group]
                result = api.AddGroupVarFw(group_list)
                if result == 'Success':
                        logger.info('venue: %s group: %s allow through variables firewall: %s' %(args.venue, group, result))
                else:
                        logger.error('venue: %s group: %s group: %s could not allow through variables firewall.  Re-try or set manually via APC.' %(args.venue, group, result))
                        sys.exit(1)
        else:
                logger.info('venue: %s group: %s is already allowed through variables firewall' %(args.venue, group))

def removefrom_varfw(group):
        varfw_groups = api.GetVarFwGroups()['groups']
        if group in varfw_groups:
                result = api.DelGroupVarFw(group)
                if result == 'Success':
                        logger.info('venue: %s group: %s removed from variables firewall allowed list: %s' %(args.venue, group, result))
                else:
                        logger.info('venue: %s group: %s was not able to remove from variables firewall allowed list: %s' %(args.venue, group, result))
        else:
                logger.info('venue: %s group: %s has already been removed from variables firewall allowed list' %(args.venue, group))

def verify_ap_varaibles(asset_dict):
        variables_good = True
        sns = list(asset_dict.keys())
        ssids = ['MCD_VTT', 'IoT_Wireless']
        for sn in sns:
                vars = api.GetVariables(sn)['data']['variables']
                values = list(vars.values())
                for s in ssids:
                        if s not in values:
                                logger.info('venue: %s group: %s serial: %s %s is missing, verify it\'s ' \
                                            'in sales force and update template variables' %(args.venue, args.group, sn, s))
                                variables_good = False
        return variables_good

def verify_sw_variables(asset_dict):
        variables_good = True
        sns = list(asset_dict.keys())
        vlans = ['BRE-Backoffice', 'BRE-Cameras', 'IoT Wired', 'IoT Wireless']
        key_vars = ['stack_switch_count', 'vsf_command_mlv']
        for sn in sns:
                vars = api.GetVariables(sn)['data']['variables']
                values = list(vars.values())
                for v in vlans:
                        if v not in values:
                                logger.info('venue: %s group: %s serial: %s %s VLAN is missing, verify it\'s ' \
                                            'in sales force and update template variables' %(args.venue, args.group, sn, v))
                                variables_good = False
                for kv in key_vars:
                        if not vars.get(kv):
                                logger.info('venue: %s group: %s serial: %s %s is missing, verify it\'s ' \
                                            'in sales force and update template variables' %(args.venue, args.group, sn, kv))
                                variables_good = False
                #verify port tagging
                #values.count('41-42,44-45')
        return variables_good

def verify_gw_variabels(asset_dict):
        variables_good = True
        sns = list(asset_dict.keys())
        for sn in sns:
                vars = api.GetVariables(sn)['data']['variables']
                #values = list(vars.values())
                if not vars.get('redundant_config'):
                        logger.info('venue: %s group: %s serial: %s redundant_config is missing, verify it\'s ' \
                                    'in sales force and update template variables' %(args.venue, args.group, sn))
                        variables_good = False
        return variables_good

def ping_user_devices(asset_dict):
        #get list of gateway ips that are up, which is the only the primary to begin with
        asset_ips = []
        for key in asset_dict:
                if asset_dict[key]['status'] == 'Up' and asset_dict[key]['ip']:
                        asset_ips.append(asset_dict[key]['ip'])
        #log into gateway
        for asset_ip in asset_ips:
                try:
                        net_connect = ConnectHandler(device_type='aruba_os', host=asset_ip, username=un, password=pwd, conn_timeout=10, banner_timeout=20)
                except:
                        logger.info('venue: %s group: %s ip: %s Could not connect to device, try again later' %(args.venue, args.group, asset_ip))
                else:
                        #get ip interface and user table results
                        net_connect.send_command("no paging")
                        sh_ip_int_brief = net_connect.send_command("show ip interface brief")
                        sh_user_table= net_connect.send_command("show user-table")
                        #split ip interface results by line and
                        #search each line for vlan 410, 420, or 430, then get back office IP subnet(first 3 octets)
                        all_lines = sh_ip_int_brief.splitlines()
                        regexp = re.compile(r'vlan 4[123]0')
                        for line in all_lines:
                                if regexp.search(line):
                                        all_strings = line.split()
                                        interface_ip = all_strings[2]
                                        octects = interface_ip.split('.')
                                        first3_octects = octects[0] + '.' + octects[1] + '.' + octects[2] + '.'
                                        break
                        #split user table results by line and
                        #search each line for any user with an ip that is in the back office ip subnet(first 3 octects)
                        user_ips = []
                        all_lines = sh_user_table.splitlines()
                        regexp = re.compile(first3_octects)
                        for line in all_lines:
                                if regexp.search(line):
                                        all_strings = line.split()
                                        user_ips.append(all_strings[0])
                        logger.info('venue: %s group: %s asset ip: %s user ips: %s' %(args.venue, args.group, asset_ip, user_ips))
                        #ping each ip
                        for user_ip in user_ips:
                                ping_cmd = 'ping ' + user_ip
                                logger.info(ping_cmd)
                                ping_result = net_connect.send_command(ping_cmd)
                                logger.info(ping_result)

def get_backoffice_ip(asset_dict):
        #get asset ip(s)
        asset_ips = []
        for key in asset_dict:
                if asset_dict[key]['status'] == 'Up' and asset_dict[key]['ip']:
                        asset_ips.append(asset_dict[key]['ip'])
        #log into device
        for asset_ip in asset_ips:
                for i in range(3):
                        try:
                                net_connect = ConnectHandler(device_type='aruba_os', host=asset_ip, username=un, password=pwd, conn_timeout=10, banner_timeout=20)
                        except:
                                logger.info('venue: %s group: %s ip: %s Could not connect to device, retry' %(args.venue, args.group, asset_ip))
                                continue
                        else:
                                #get ip interface and user table results
                                net_connect.send_command("no paging")
                                sh_ip_int_brief = net_connect.send_command("show ip interface brief")
                                #split ip interface results by line and
                                #search each line for vlan 410, 420, or 430, then get back office IP subnet(first 3 octets)
                                all_lines = sh_ip_int_brief.splitlines()
                                regexp = re.compile(r'vlan 4[123]0')
                                for line in all_lines:
                                        if regexp.search(line):
                                                all_strings = line.split()
                                                interface_ip = all_strings[2]
                                                octets = interface_ip.split('.')
                                                first3_octets = octets[0] + '.' + octets[1] + '.' + octets[2] + '.'
                                                logger.info('venue: %s group: %s ip: %s back office ip: %s' %(args.venue, args.group, asset_ip, first3_octets))
                                                #found back office network ip, disconnect and return ip
                                                net_connect.disconnect()
                                                return first3_octets

def get_user_ips(asset_dict, backoffice_ip):
        user_ips = []
        asset_ips = []
        #get asset ip(s)
        for key in asset_dict:
                if asset_dict[key]['status'] == 'Up' and asset_dict[key]['ip']:
                        asset_ips.append(asset_dict[key]['ip'])
        #log into device
        for asset_ip in asset_ips:
                for i in range(3):
                        try:
                                net_connect = ConnectHandler(device_type='aruba_os', host=asset_ip, username=un, password=pwd, conn_timeout=10, banner_timeout=20)
                        except:
                                logger.info('venue: %s group: %s ip: %s Could not connect to device, retry' %(args.venue, args.group, asset_ip))
                                continue
                        else:
                                net_connect.send_command("no paging")
                                sh_arp = net_connect.send_command("show arp")
                                all_lines = sh_arp.splitlines()
                                regexp = re.compile(backoffice_ip)
                                for line in all_lines:
                                        if regexp.search(line):
                                                all_strings = line.split()
                                                user_ips.append(all_strings[0])
                                net_connect.disconnect()
                                break
        logger.info('venue: %s group: %s user ips: %s ' %(args.venue, args.group, user_ips))
        return user_ips

def ping_user_ips(asset_dict, user_ips):
        asset_ips = []
        for key in asset_dict:
                if asset_dict[key]['status'] == 'Up' and asset_dict[key]['ip']:
                        asset_ips.append(asset_dict[key]['ip'])
        #log into device
        for asset_ip in asset_ips:
                for i in range(3):
                        try:
                                net_connect = ConnectHandler(device_type='aruba_os', host=asset_ip, username=un, password=pwd, conn_timeout=10, banner_timeout=20)
                        except:
                                logger.info('venue: %s group: %s ip: %s Could not connect to device, retry' %(args.venue, args.group, asset_ip))
                                continue
                        else:
                                for user_ip in user_ips:
                                        ping_cmd = 'ping ' + user_ip
                                        logger.info(ping_cmd)
                                        ping_result = net_connect.send_command(ping_cmd)
                                        logger.info(ping_result)
                                net_connect.disconnect()
                                break

def find_gateway_uplink(asset_dict):
        sns = list(asset_dict.keys())
        for sn in sns:
                session = api.StartTsSession(sn, 'SWITCH', 1201)
                if 'session_id' in session:
                        session_id =  session['session_id']
                else:
                        logger.info('venue: %s group: %s serial: %s Could not start troubleshooting session' %(args.venue, args.group,sn))
                        break
                time.sleep(10)
                results = api.GetTsOutput(sn, session_id)
                if 'output' in results:
                        output = results['output'].splitlines()
                        for o in output:
                                if '7005' in o:
                                        logger.info('venue: %s group: %s serial: %s Gateway is plugged into - device name: %s ' \
                                                        'ip: %s' %(args.venue, args.group, sn, asset_dict[sn]['name'], asset_dict[sn]['ip']))
                else:
                        logger.info('venue: %s group: %s serial: %s Could not get troubleshooting output' %(args.venue, args.group,sn))

def get_site_id(group):
        site_id = ''
        #get store number
        store_num = group.split('_')[-1]
        site_name = 'MCD_' + store_num
        #get site id
        all_sites = api.ListSites()
        for s in all_sites:
                if s['site_name'] == site_name:
                        site_id = s['site_id']
                        break
        return site_id

def associate_stack_tosite(asset_dict, site_id):
        sns = list(asset_dict.keys())
        result = api.AssociateSiteToDevices(sns, 'SWITCH', site_id)
        logger.info('venue: %s group: %s serials: %s Associate new vsf stack to site id %s: %s' %(args.venue, args.group, sns, site_id, result))

def sf15to18(id):
        if not id:
                raise ValueError('No id given.')
        if not isinstance(id, str):
                raise TypeError('The given id isn\'t a string')
        if len(id) == 18:
                return id
        if len(id) != 15:
                raise ValueError('The given id isn\'t 15 characters long.')
        # Generate three last digits of the id
        for i in range(0,3):
                f = 0
                # For every 5-digit block of the given id
                for j in range(0,5):
                        # Assign the j-th chracter of the i-th 5-digit block to c
                        c = id[i * 5 + j]
                        # Check if c is an uppercase letter
                        if c >= 'A' and c <= 'Z':
                                # Set a 1 at the character's position in the reversed segment
                                f += 1 << j
                # Add the calculated character for the current block to the id
                id += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'[f]
        return id

def get_assets(sf, venues):
        csvfile = 'mcd-aot-conversions/mcd_assets_query_' + args.group + '_' + date.strftime('%m%d%Y_%H%M%S') + '.csv'
        query = "Select Id, Name, SerialNumber, Status, "\
                                "Ship_Date__c, Activation_Date__c, Device_Name__c, Folder_Name__c, "\
                                "LAN_MAC_Address__c, Venue__c, Active__c, Corporate_Account_ID__c, "\
                                "Invoice_Account_ID__c, AP_Alias__c, Asset_Type__c, ECM_Activation_Status__c, "\
                                "EOD_Activation__c, Routing_Number__c, ECM_Group_ID__c, Redundant_Configuration__c, "\
                                "Manufacturer__c, Vendor__c, AssetId18digit__c, Firmware__c, "\
                                "stack_switch_count__c, VSF__c,  Stack_Index__c, Stack_Set__c, Stack_Master_ID__c, "\
                                "EOD_Activation_Status__c, SFDC_PicklistModel__c, Venue_Name__c FROM Asset "+\
                    format_soql("WHERE Venue__r.Id IN {} ", venues) +\
                                format_soql("AND Status IN {} ", ['Shipped', 'Active']) +\
                                format_soql("AND Asset_Type__c IN {} ",['AP','Switch','Gateway'])
        assets = sf.query_all_iter(query)
        assets_dict = []
        try:
                for item in assets:
                        del item['attributes']
                        assets_dict.append(item)
        except:
                logger.error('%s,get assets query failed' %venues)
        pd.DataFrame(assets_dict).to_csv(csvfile, index=False)
        return assets_dict


def get_ports2(sf, asset_ids):
        csvfile = 'mcd-aot-conversions/mcd_ports_query.csv_' + args.group + '_' + date.strftime('%m%d%Y_%H%M%S') + '.csv'
        query = "Select Id, Name, Asset__c, Enable__c, Port_Number__c, VLAN_Assignment__c, VLAN_ID__c, Asset_Model__c, " \
                "Connected_Downstream_Asset__c, Managed_By__c, POE_Capable__c, POE_Enabled__c, PoE_Mode__c, Asset__r.Id, " \
                "Port_Label__c, Port_Mode__c, Port_Speed__c, Port_Type__c, Portal_Flag__c, Read_Only__c, Tagged_VLAN__c, " \
                "Untagged_VLAN__c, Card_Model__c, Dual_Purpose__c, Existing_Port__c, Extra_Port__c, Port_Pos__c, " \
                "Power_Cycle_Response__c, Connected_MAC__c, IsSwitch__c, Port_s_Asset_Type__c, VenueID__c, " \
                "AssetNamePortNumber__c, Uplink__c, Port_Alias__c, Dynamic_VLAN_Assignment__c, X802_1x_Enabled__c, " \
                "Brand_ID__c, Authentication__c, Formula_Venue_Cascade_Status__c, Port_Preset__c, Connected_Circuit__c, " \
                "BrandJoinedPort__c, EntPortCounterpart__c, Trunk__c, ARP_Protect_Trust_All_Ports__c, " \
                "Action_for_Uknown_VLANs__c, DHCP_Snooping_Trust_All_Ports__c, Enable_POE_LLDP_Detect__c, " \
                "IP_Access_Group_Name__c, Include_in_IP_Access_Group__c, POE_Allocated_By__c, POE_Value__c, " \
                "ISC_Port__c, Mirror_Monitor_Interface__c, Mirror_Monitor_Session__c, Monitor_Direction__c, " \
                "Formula_Trunk_ISC__c, StackSet__c, Replaced_Asset_Ports__c, Zone__c, Deleted__c, OldPortId__c, " \
                "loop_protect__c, LLDP_Receive_Only__c, Allow8021xValue__c, X802_1x_Alias__c, EnterpriseCascadeID__c, " \
                "IsVendor_Changed__c, Is_Cascade_Port__c, Manufacturer__c, QOS__c, " \
                "Primary_Authentication_Method__c FROM Port__c "+\
                    format_soql("WHERE Asset__r.Id IN {} ", asset_ids)
        ports = sf.query_all_iter(query)
        ports_dict = []
        try:
                for item in ports:
                        del item['attributes']
                        item['Asset ID'] = item['Asset__r']['Id']
                        ports_dict.append(item)
        except:
                logger.error('%s,get ports query failed' %sf.venue)
        pd.DataFrame(ports_dict).to_csv(csvfile, index=False)
        return ports_dict

def get_ports(sf, asset_ids):
        csvfile = 'mcd-aot-conversions/mcd_ports_query.csv_' + args.group + '_' + date.strftime('%m%d%Y_%H%M%S') + '.csv'
        query = "Select Id, Name, Asset__c, Enable__c, Port_Number__c, VLAN_Assignment__c, VLAN_ID__c, " \
                "Connected_Downstream_Asset__c, Managed_By__c, POE_Capable__c, POE_Enabled__c, PoE_Mode__c, Asset__r.Id, " \
                "Port_Label__c, Port_Mode__c, Port_Speed__c, Port_Type__c, Portal_Flag__c, Read_Only__c, Tagged_VLAN__c, " \
                "Untagged_VLAN__c, Card_Model__c, Dual_Purpose__c, Existing_Port__c, Port_Pos__c, " \
                "Connected_MAC__c, Port_s_Asset_Type__c, " \
                "AssetNamePortNumber__c, Uplink__c, Port_Alias__c, Dynamic_VLAN_Assignment__c, X802_1x_Enabled__c, " \
                "Brand_ID__c, Authentication__c, Formula_Venue_Cascade_Status__c, Port_Preset__c, Connected_Circuit__c, " \
                "BrandJoinedPort__c, EntPortCounterpart__c, Trunk__c, ARP_Protect_Trust_All_Ports__c, " \
                "Action_for_Uknown_VLANs__c, DHCP_Snooping_Trust_All_Ports__c, Enable_POE_LLDP_Detect__c, " \
                "IP_Access_Group_Name__c, Include_in_IP_Access_Group__c, POE_Allocated_By__c, POE_Value__c, " \
                "ISC_Port__c, Mirror_Monitor_Interface__c, Mirror_Monitor_Session__c, Monitor_Direction__c, " \
                "Replaced_Asset_Ports__c, Zone__c, Deleted__c, OldPortId__c, " \
                "loop_protect__c, LLDP_Receive_Only__c, Allow8021xValue__c, X802_1x_Alias__c, EnterpriseCascadeID__c, " \
                "IsVendor_Changed__c, Is_Cascade_Port__c, Manufacturer__c, QOS__c, " \
                "Primary_Authentication_Method__c FROM Port__c "+\
                    format_soql("WHERE Asset__r.Id IN {} ", asset_ids)
        ports = sf.query_all_iter(query)
        ports_dict = []
        try:
                for item in ports:
                        del item['attributes']
                        item['Asset ID'] = item['Asset__r']['Id']
                        ports_dict.append(item)
        except:
                logger.error('%s,get ports query failed' %sf.venue)
        pd.DataFrame(ports_dict).to_csv(csvfile, index=False)
        return ports_dict


def get_ssids2(sf, venues):
        csvfile = 'mcd-aot-conversions/mcd_ssids_query.csv_' + args.group + '_' + date.strftime('%m%d%Y_%H%M%S') + '.csv'
        query = "Select Id,  Name, Venue__c, Active__c, Broadcast__c, Company_Level__c, CorporateAccountId__c, " \
                "Enable_to_Select_less_Secure_Protocol__c, MAC_ACL_Enabled__c, PSK__c, Radio_Preference__c, " \
                "SSID_Name__c, Security_Profile__c, URL_Filter__c, VLAN__c, isDefaultSSID__c, Venue_Name__c, " \
                "StatusForGS__c, RadioPreferenceGS__c, VLAN_ID__c, VLAN_Name__c, Allowed_to_Accept_VPN_Traffic__c, " \
                "Fast_Roaming_802_11r__c, Allow_local_DHCP_support__c, Date_Assigned__c, X8021_x_Authentication__c, " \
                "Download_Bandwidth_Cap__c, Formula_BrandAutoNumber__c, Upload_Bandwidth_Cap__c, Vendor_SSID_ID__c, " \
                "Connection_Page__c, Formula_Venue_Cascade_Status__c, Connection_Page_Last_Modified_By__c, " \
                "Connection_Page_Last_Modified_Date__c, SSID_Zone_Name__c, SSID_Type__c, a_basic_rates__c, " \
                "a_max_tx_rates__c, a_min_tx_rates__c, a_tx_rates__c, broadcast_filter__c, d_mcast_optimization__c, " \
                "dmo_channel_utilization_threshold__c, eng_DTIM__c, g_basic_rates__c, g_max_tx_rates__c, " \
                "g_min_tx_rates__c, g_tx_rates__c, inactivity_timeout__c, local_probe_req_thresh__c, RecordTypeId, " \
                "max_authentication_failures__c, max_clients_threshold__c, mcast_rate_optimization__c, " \
                "radius_accounting__c, radius_interim_accounting_interval__c, voice_dscp__c, wmm_uapsd_disable__c, " \
                "SSIDAutoNumber__c, Service_Discovery__c, Zone__c, Number_of_Schedule_Check_Delete_SSID__c, " \
                "Number_of_Schedule__c, isEnterpriseAccount__c, isOldestPubSSID__c, Activity_Instance_Trigger__c, " \
                "Event_SSID__c, VLANAllowVPNTraffic__c, Limited_Provisioning__c, ATT_Management_VLAN__c, " \
                "SSID_Type_Formula__c, VLAN_Type__c, isInfrastructure__c, Vendor_Portal_ID__c, Allow8021xValue__c, " \
                "Deleted__c, X802_1x_Alias__c, EnterpriseCascadeID__c, VenueCountry__c FROM SSID__c "+\
                    format_soql("WHERE Venue__r.Id IN {} ", venues)
        ssids = sf.query_all_iter(query)
        ssids_dict = []
        try:
                for item in ssids:
                        del item['attributes']
                        ssids_dict.append(item)
        except:
                logger.error('%s,get ssids query failed' %venues)

        pd.DataFrame(ssids_dict).to_csv(csvfile, index=False)
        return ssids_dict

def get_ssids(sf, venues):
        csvfile = 'mcd-aot-conversions/mcd_ssids_query.csv_' + args.group + '_' + date.strftime('%m%d%Y_%H%M%S') + '.csv'
        query = "Select Id,  Name, Venue__c, Active__c, Broadcast__c, Company_Level__c, " \
                "Enable_to_Select_less_Secure_Protocol__c, MAC_ACL_Enabled__c, PSK__c, Radio_Preference__c, " \
                "SSID_Name__c, Security_Profile__c, URL_Filter__c, VLAN__c, isDefaultSSID__c, Venue_Name__c, " \
                "RadioPreferenceGS__c, VLAN_ID__c, VLAN_Name__c, Allowed_to_Accept_VPN_Traffic__c, " \
                "Fast_Roaming_802_11r__c, Allow_local_DHCP_support__c, Date_Assigned__c, X8021_x_Authentication__c, " \
                "Download_Bandwidth_Cap__c, Formula_BrandAutoNumber__c, Upload_Bandwidth_Cap__c, Vendor_SSID_ID__c, " \
                "Connection_Page__c, Formula_Venue_Cascade_Status__c, Connection_Page_Last_Modified_By__c, " \
                "Connection_Page_Last_Modified_Date__c, SSID_Zone_Name__c, SSID_Type__c, a_basic_rates__c, " \
                "a_max_tx_rates__c, a_min_tx_rates__c, a_tx_rates__c, broadcast_filter__c, d_mcast_optimization__c, " \
                "dmo_channel_utilization_threshold__c, eng_DTIM__c, g_basic_rates__c, g_max_tx_rates__c, " \
                "g_min_tx_rates__c, g_tx_rates__c, inactivity_timeout__c, local_probe_req_thresh__c, RecordTypeId, " \
                "max_authentication_failures__c, max_clients_threshold__c, mcast_rate_optimization__c, " \
                "radius_accounting__c, radius_interim_accounting_interval__c, voice_dscp__c, wmm_uapsd_disable__c, " \
                "SSIDAutoNumber__c, Service_Discovery__c, Zone__c, Number_of_Schedule_Check_Delete_SSID__c, " \
                "Number_of_Schedule__c, isEnterpriseAccount__c, isOldestPubSSID__c, Activity_Instance_Trigger__c, " \
                "Event_SSID__c, VLANAllowVPNTraffic__c, Limited_Provisioning__c, ATT_Management_VLAN__c, " \
                "VLAN_Type__c, isInfrastructure__c, Vendor_Portal_ID__c, Allow8021xValue__c, " \
                "Deleted__c, X802_1x_Alias__c, EnterpriseCascadeID__c, VenueCountry__c FROM SSID__c "+\
                    format_soql("WHERE Venue__r.Id IN {} ", venues)

        ssids = sf.query_all_iter(query)
        ssids_dict = []
        try:
                for item in ssids:
                        del item['attributes']
                        ssids_dict.append(item)
        except:
                logger.error('%s,get ssids query failed' %venues)

        pd.DataFrame(ssids_dict).to_csv(csvfile, index=False)
        return ssids_dict

def get_vlans2(sf, venues):
        csvfile = 'mcd-aot-conversions/mcd_vlans_query.csv_' + args.group + '_' + date.strftime('%m%d%Y_%H%M%S') + '.csv'
        query = "Select Id, Name, CurrencyIsoCode, VLAN_ID__c, VLAN_Name__c, Venue_ID__c, " \
                "Venue_Name__c, VLAN_Description__c, AniraCheckbox__c, Allow_local_DHCP_support__c, " \
                "Allowed_to_Accept_VPN_Traffic__c, Status__c, Network_IP__c, Network_Subnet_Mask__c, " \
                "Network_Role__c, Brand_Name__c, Cascaded__c, Quarantine_VLAN__c, ATT_Management_VLAN__c, " \
                "End_IP_Address__c, Formula_Venue_Cascade_Status__c, Specify_VPN_Services__c, " \
                "Start_IP_Address__c, Subnet_Advertising__c, VLAN_Network_Gateway__c, VLAN_Network_Type__c, " \
                "vlan_dns_primary_ip__c, vlan_dns_secondary_ip__c, EntVlanCounterPart__c, VPN_Configuration__c, " \
                "DHCP_Lease_Time__c, URLFilterfromSSID__c, URL_Filter__c, Allow_Wired_to_Wireless_Access__c, " \
                "Peer_Keep_Alive_VLAN__c, Trusted_VLAN__c, IsInfrastructure__c, Controller_VLAN__c, " \
                "FormulaVLANAutoNumber__c, OldVlanId__c, arp_protect_vlans__c, VLAN_Type__c, EnterpriseCascadeID__c, " \
                "IGMP__c, PrivateVLAN__c, VOIP__c, MTU__c, ServerType__c, emptynexthop__c, CorporateAccount__c FROM VLAN__c "+\
                    format_soql("WHERE Venue_ID__c IN {} ", venues)
        vlans = sf.query_all_iter(query)
        vlans_dict = []
        try:
                for item in vlans:
                        del item['attributes']
                        vlans_dict.append(item)
        except:
                logger.error('%s,get vlans query failed' %venues)
        pd.DataFrame(vlans_dict).to_csv(csvfile, index=False)
        return vlans_dict

def get_vlans(sf, venues):
        csvfile = 'mcd-aot-conversions/mcd_vlans_query.csv_' + args.group + '_' + date.strftime('%m%d%Y_%H%M%S') + '.csv'
        query = "Select Id, Name, CurrencyIsoCode, VLAN_ID__c, VLAN_Name__c, Venue_ID__c, " \
                "Venue_Name__c, VLAN_Description__c, AniraCheckbox__c, Allow_local_DHCP_support__c, " \
                "Allowed_to_Accept_VPN_Traffic__c, Status__c, Network_IP__c, Network_Subnet_Mask__c, " \
                "Network_Role__c, Cascaded__c, Quarantine_VLAN__c, ATT_Management_VLAN__c, " \
                "End_IP_Address__c, Formula_Venue_Cascade_Status__c, Specify_VPN_Services__c, " \
                "Start_IP_Address__c, Subnet_Advertising__c, VLAN_Network_Gateway__c, VLAN_Network_Type__c, " \
                "vlan_dns_primary_ip__c, vlan_dns_secondary_ip__c, EntVlanCounterPart__c, " \
                "DHCP_Lease_Time__c, URLFilterfromSSID__c, URL_Filter__c, Allow_Wired_to_Wireless_Access__c, " \
                "Peer_Keep_Alive_VLAN__c, Trusted_VLAN__c, IsInfrastructure__c, Controller_VLAN__c, " \
                "FormulaVLANAutoNumber__c, OldVlanId__c, arp_protect_vlans__c, VLAN_Type__c, EnterpriseCascadeID__c, " \
                "IGMP__c, PrivateVLAN__c, VOIP__c, MTU__c, ServerType__c, emptynexthop__c, CorporateAccount__c FROM VLAN__c "+\
                    format_soql("WHERE Venue_ID__c IN {} ", venues)

        vlans = sf.query_all_iter(query)
        vlans_dict = []
        try:
                for item in vlans:
                        del item['attributes']
                        vlans_dict.append(item)
        except:
                logger.error('%s,get vlans query failed' %venues)

        pd.DataFrame(vlans_dict).to_csv(csvfile, index=False)
        return vlans_dict

def get_port_joins2(sf, assets):
        csvfile = 'mcd-aot-conversions/mcd_portjoins_query.csv_' + args.group + '_' + date.strftime('%m%d%Y_%H%M%S') + '.csv'
        query = "Select Id, Name, AssetId__c, PortType__c, Port_ID__c, VLAN_ID__c, PORT_ID__r.Name FROM VLAN_Port_Join__c "+\
                format_soql("WHERE AssetId__c IN {}", assets)
        port_joins = sf.query_all_iter(query)
        port_joins_dict = []
        try:
                for item in port_joins:
                        del item['attributes']
                        item['Port Name'] = item['Port_ID__r']['Name']
                        port_joins_dict.append(item)
        except:
                logger.error('%s,get port joins query failed' %venues)
        pd.DataFrame(port_joins_dict).to_csv(csvfile, index=False)
        return port_joins_dict

def get_port_joins(sf, assets):
        csvfile = 'mcd-aot-conversions/mcd_portjoins_query.csv_' + args.group + '_' + date.strftime('%m%d%Y_%H%M%S') + '.csv'
        query = "Select Id, Name, AssetId__c, PortType__c, Port_ID__c, VLAN_ID__c, Tagged_Untagged__c, PORT_ID__r.Name FROM VLAN_Port_Join__c "+\
                format_soql("WHERE AssetId__c IN {}", assets)

        port_joins = sf.query_all_iter(query)
        port_joins_dict = []
        try:
                for item in port_joins:
                        del item['attributes']
                        item['Port Name'] = item['Port_ID__r']['Name']
                        port_joins_dict.append(item)
        except:
                logger.error('%s,get port joins query failed' %venues)

        pd.DataFrame(port_joins_dict).to_csv(csvfile, index=False)
        return port_joins_dict


def get_macacls(sf, venues):
        csvfile = 'mcd-aot-conversions/mcd_macacl_query_' + args.group + '_' + date.strftime('%m%d%Y_%H%M%S') + '.csv'
        query = "Select Id,MAC_ACL_Name__c,MAC_Address1__c,MAC_Address2__c,MAC_Address3__c,MAC_Address4__c,MAC_Address5__c,MAC_Address6__c,MAC_Address7__c, "\
                "MAC_Address8__c,MAC_Address9__c,MAC_Address10__c,MAC_Address11__c,MAC_Address12__c,MAC_Address13__c,MAC_Address14__c, "\
                "MAC_Address15__c,MAC_Address16__c,MAC_Address17__c,MAC_Address18__c,MAC_Address19__c,MAC_Address20__c,MAC_Address21__c, "\
                "MAC_Address22__c,MAC_Address23__c,MAC_Address24__c,MAC_Address25__c,MAC_Address26__c,MAC_Address27__c,MAC_Address28__c, "\
                "MAC_Address29__c,MAC_Address30__c,MAC_OUI_1__c,MAC_OUI_2__c,MAC_OUI_3__c,MAC_OUI_4__c,MAC_OUI_5__c,MAC_OUI_6__c,MAC_OUI_7__c, "\
                "MAC_OUI_8__c,MAC_OUI_9__c,MAC_OUI_10__c,MAC_OUI_11__c,MAC_OUI_12__c,MAC_OUI_13__c,MAC_OUI_14__c,MAC_OUI_15__c,MAC_OUI_16__c, "\
                "MAC_OUI_17__c,MAC_OUI_18__c,MAC_OUI_19__c,MAC_OUI_20__c,MAC_OUI_21__c,MAC_OUI_22__c,MAC_OUI_23__c,MAC_OUI_24__c,MAC_OUI_25__c,MAC_OUI_26__c, "\
                "MAC_OUI_27__c,MAC_OUI_28__c,MAC_OUI_29__c,MAC_OUI_30__c,Name,Status__c,Venue_External_Location_ID__c,Venue_ID__c FROM MAC_ACL__c "+\
                    format_soql("WHERE Venue_ID__c IN {} ", venues)
        macacls = sf.query_all_iter(query)
        macacls_dict = []
        try:
                for item in macacls:
                        del item['attributes']
                        macacls_dict.append(item)
        except:
                logger.error('%s,get macacls query failed' %venues)
        pd.DataFrame(macacls_dict).to_csv(csvfile, index=False)
        return macacls_dict

class AOTSetupManager():
        def __init__(self, sf, venue):
                self.sf = sf
                self.assets = []
                self.ports = []
                self.ssids = []
                self.vlans = []
                self.port_joins = []
                self.venue = venue
                self.VLAN = {
                        'BRE-Backoffice': {
                                'Status__c': 'Active',
                                'VLAN_Network_Type__c': 'Private',
                                'VLAN_Name__c': 'BRE-Backoffice',
                                'VLAN_ID__c': '460',
                                'Venue_ID__c':  self.venue
                        },
                        'BRE-Cameras': {
                                'Status__c': 'Active',
                                'VLAN_Network_Type__c': 'Private',
                                'VLAN_Name__c': 'BRE-Cameras',
                                'VLAN_ID__c': '491',
                                'Venue_ID__c': self.venue,
                                'Allow_local_DHCP_support__c': True,
                                'Start_IP_Address__c': '192.168.91.101',
                                'End_IP_Address__c': '192.168.91.250',
                                'Network_IP__c': '192.168.91.0',
                                'VLAN_Network_Gateway__c': '192.168.91.1',
                                'Network_Subnet_Mask__c': '255.255.255.0',
                                'vlan_dns_primary_ip__c': '208.67.222.222',
                                'vlan_dns_secondary_ip__c': '208.67.220.220'
                        },
                        'IoT Wired': {
                                'Status__c': 'Active',
                                'VLAN_Network_Type__c': 'Private',
                                'VLAN_Name__c': 'IoT Wired',
                                'VLAN_ID__c': '492',
                                'Venue_ID__c': self.venue,
                                'Allow_local_DHCP_support__c': True,
                                'Start_IP_Address__c': '192.168.93.1',
                                'End_IP_Address__c': '192.168.93.252',
                                'Network_IP__c': '192.168.92.0',
                                'VLAN_Network_Gateway__c': '192.168.92.1',
                                'Network_Subnet_Mask__c': '255.255.254.0',
                                'vlan_dns_primary_ip__c': '208.67.222.222',
                                'vlan_dns_secondary_ip__c': '208.67.220.220'
                        },
                        'IoT Wireless': {
                                'Status__c': 'Active',
                                'VLAN_Network_Type__c': 'Private',
                                'VLAN_Name__c': 'IoT Wireless',
                                'VLAN_ID__c': '494',
                                'Venue_ID__c': self.venue,
                                'Allow_local_DHCP_support__c': True,
                                'Start_IP_Address__c': '192.168.95.1',
                                'End_IP_Address__c': '192.168.95.252',
                                'Network_IP__c': '192.168.94.0',
                                'VLAN_Network_Gateway__c': '192.168.94.1',
                                'Network_Subnet_Mask__c': '255.255.254.0',
                                'vlan_dns_primary_ip__c': '208.67.222.222',
                                'vlan_dns_secondary_ip__c': '208.67.220.220'
                        },
                }
                self.SSID = {
                        'MCD_VTT': {
                                'Venue__c': self.venue,
                                'RecordTypeId': '012600000009f8QAAQ',
                                'SSID_Name__c': 'MCD_VTT',
                                'Security_Profile__c': 'WPA 2 - AES',
                                'Active__c': True,
                                'PSK__c': 'V4FsEck2i6',
                                'SSID_Type__c': 'Employee',
                                'Broadcast__c': 'Hide',
                                'broadcast_filter__c': 'arp',
                                'inactivity_timeout__c': '300'
                        },
                        'MCD_VTT-vlan': 'BRE-Backoffice',
                        'IoT_Wireless': {
                                'Venue__c': self.venue,
                                'SSID_Name__c': 'IoT_Wireless',
                                'RecordTypeId': '012600000009f8QAAQ',
                                'Security_Profile__c': 'WPA 2 - AES',
                                'Active__c': True,
                                'PSK__c': 'V4FsEck2i6',
                                'SSID_Type__c': 'Employee',
                                'Broadcast__c': 'Hide',
                                'broadcast_filter__c': 'arp',
                                'inactivity_timeout__c': '300'
                        },
                        'IoT_Wireless-vlan': 'IoT Wireless'
                }

        def update_queries(self):
                self.assets = get_assets(self.sf, [self.venue])
                self.ssids = get_ssids(self.sf, [self.venue])
                self.vlans = get_vlans(self.sf, [self.venue])
                self.macacls = get_macacls(self.sf, [self.venue])
                self.ports = get_ports(self.sf, [x['Id'] for x in self.assets])
                self.port_joins = get_port_joins(self.sf, [x['Id'][:15] for x in self.assets])

        def update_config_flag(self):
                try:
                        results = self.sf.query(format_soql("Select NonStandardConfigurationFlag__c From Venue__c WHERE Id = {}", self.venue))
                        flag = results['records'][0]['NonStandardConfigurationFlag__c']
                except:
                        logger.error('%s could not get current non standard configuration flag value' %self.venue)
                else:
                        if flag != 'HA Site':
                                update = {"NonStandardConfigurationFlag__c": "HA Site"}
                                try:
                                        self.sf.Venue__c.update(self.venue, update)
                                except:
                                        logger.error('%s,failed to update non standard configuration flag' %self.venue)
                                else:
                                        logger.info('%s,updated non standard configuration flag' %self.venue)


        def configure_vlans(self):
                # check if VLANs are created already, or VLAN exists that we can configure for our purposes
                def vlan_already_exists(vlan_name):
                        # returns either vlan object or None, which evaluate as True and False respectively
                        vlan = [x for x in self.vlans if x['VLAN_Name__c'] == vlan_name]
                        if len(vlan) == 1:
                                return vlan[0]
                        elif len(vlan) == 0:
                                logger.info('venue: %s vlan: %s no suitable VLANs found matching' %(self.venue,vlan_name))
                        elif len(vlan) > 1:
                                logger.info('venue: %s vlan: %s there are multiple VLANs present' %(self.venue,vlan_name))
                # check if pre-existing VLAN is already configured correctly
                def vlan_already_configured(vlan_name, vlan):
                        # we want to compare self.VLAN[vlan_name] with this VLAN
                        all_fields_correct = True
                        for field in self.VLAN[vlan_name]:
                                if vlan[field] != self.VLAN[vlan_name][field]:
                                        return False
                        return True
                # handle branching logic for VLAN creation and configuring, makes main loop pretty
                def create_vlan_if_required(vlan_name):
                        vlan = vlan_already_exists(vlan_name)
                        if vlan and vlan_already_configured(vlan_name, vlan):
                                logger.info('venue: %s vlan: %s VLAN already configured' %(self.venue,vlan_name))
                        elif vlan and not vlan_already_configured(vlan_name, vlan):
                                #logger.info(f'{self.venue},{vlan_name},must update VLAN')
                                try:
                                        self.sf.VLAN__c.update(vlan['Id'], self.VLAN[vlan_name])
                                except:
                                        logger.error('venue: %s vlan: %s failed to update VLAN' %(self.venue,vlan_name))
                                else:
                                        logger.info('venue: %s vlan: %s updated VLAN' %(self.venue,vlan_name))
                        elif not vlan:
                                #logger.info(f'{self.venue},{vlan_name},must create VLAN')
                                #logger.info(f'{self.venue},self.VLAN[vlan_name]')
                                try:
                                        created_vlan = self.sf.VLAN__c.create(self.VLAN[vlan_name])
                                        self.sf.VLAN__c.update(created_vlan['id'], {'Status__c': 'Active', 'vlan_dns_primary_ip__c': '208.67.222.222', 'vlan_dns_secondary_ip__c': '208.67.220.220'})
                                except:
                                        logger.error('venue: %s vlan: %s failed to create VLAN' %(self.venue,vlan_name))
                                else:
                                        logger.info('venue: %s vlan: %s created VLAN' %(self.venue,vlan_name))

                for AOT_vlan in ['BRE-Backoffice', 'BRE-Cameras', 'IoT Wired', 'IoT Wireless']:
                        create_vlan_if_required(AOT_vlan)
                self.update_queries()

        def configure_ssids(self):
                # check if ssids are created already, or ssid exists that we can configure for our purposes
                def ssid_already_exists(ssid_name):
                        # returns either ssid object or None, which evaluate as True and False respectively
                        ssid = [x for x in self.ssids if x['SSID_Name__c'] == ssid_name]
                        if len(ssid) == 1:
                                return ssid[0]
                        elif len(ssid) == 0:
                                logger.info('venue: %s ssid: %s no suitable ssids found matching' %(self.venue,ssid_name))
                        elif len(ssid) > 1:
                                logger.info('venue: %s ssid: %s there are multiple ssids present' %(self.venue,ssid_name))
                # check if pre-existing ssid is already configured correctly
                def ssid_already_configured(ssid_name, ssid):
                        # we want to compare self.ssid[ssid_name] with this ssid
                        all_fields_correct = True
                        for field in self.SSID[ssid_name]:
                                if ssid[field] != self.SSID[ssid_name][field]:
                                        return False
                        vlan_name = self.SSID[f'{ssid_name}-vlan']
                        vlan_id = [x['Id'] for x in self.vlans if x['VLAN_Name__c'] == vlan_name][0]
                        if ssid['VLAN__c'] != vlan_id:
                                return False
                        return True
                # handle branching logic for ssid creation and configuring, makes main loop pretty
                def create_ssid_if_required(ssid_name):
                        ssid = ssid_already_exists(ssid_name)
                        vlan_name = self.SSID[f'{ssid_name}-vlan']
                        vlan_id = [x['Id'] for x in self.vlans if x['VLAN_Name__c'] == vlan_name][0]
                        if ssid and ssid_already_configured(ssid_name, ssid):
                                logger.info('venue: %s ssid: %s ssid already configured' %(self.venue,ssid_name))
                        elif ssid and not ssid_already_configured(ssid_name, ssid):
                                #logger.info(f'{self.venue},{ssid_name},must update ssid')
                                update =  {**self.SSID[ssid_name], 'VLAN__c': vlan_id}
                                del update['Venue__c']
                                try:
                                        self.sf.ssid__c.update(ssid['Id'], update)
                                except:
                                        logger.error('venue: %s ssid: %s failed to update ssid' %(self.venue,ssid_name))
                                else:
                                        logger.info('venue: %s ssid: %s updated ssid' %(self.venue,ssid_name))
                        elif not ssid:
                                #logger.info(f'{self.venue},{ssid_name},must create ssid')
                                #logger.info(self.venue,self.SSID[ssid_name])
                                try:
                                        self.sf.ssid__c.create({**self.SSID[ssid_name], 'VLAN__c': vlan_id})
                                except:
                                        logger.error('venue: %s ssid: %s failed to create ssid' %(self.venue,ssid_name))
                                else:
                                        logger.info('venue: %s ssid: %s ssid created' %(self.venue,ssid_name))

                for AOT_ssid in ['MCD_VTT', 'IoT_Wireless']:
                        create_ssid_if_required(AOT_ssid)

                self.update_queries()


        def configure_switches(self):
                switches = [x for x in self.assets if x['Asset_Type__c'] == 'Switch']
                switches = sorted(switches, key= lambda x: x['Device_Name__c'])
                for i, switch in enumerate(switches):
                        device_name = switch['Device_Name__c']
                        device_id = switch['Id']
                        logger.info('venue: %s device name: %s device id: %s configuring switch' %(self.venue, device_name, device_id))
                        # check switch fields for vsf config
                        stack_index = i+1
                        # stack_switch_count__c, VSF__c,  Stack_Index__c, Stack_Set__c
                        switch_config = {"stack_switch_count__c": "0",
                                         "VSF__c": False,
                                         "Stack_Set__c": "0",
                                         "Stack_Index__c": "0",
                                         "Stack_Master_ID__c": None}
                        try:
                                switch_config = {"stack_switch_count__c": str(int(switch["stack_switch_count__c"])),
                                         "VSF__c": switch["VSF__c"],
                                         "Stack_Set__c": str(int(switch["Stack_Set__c"])),
                                         "Stack_Index__c": str(int(switch["Stack_Index__c"])),
                                         "Stack_Master_ID__c": switch["Stack_Master_ID__c"]}
                        except:
                                pass
                        # if primary switch save id and name to use in vsf stack master config on non primary switches
                        if stack_index == 1:
                                primary_id = device_id
                                update = {"stack_switch_count__c": str(len(switches)),
                                  "VSF__c": True,
                                  "Stack_Set__c": "1",
                                  "Stack_Index__c": str(int(stack_index)),
                                  "Stack_Master_ID__c": None}
                        # not the primary so add stack master id config
                        else:
                                update = {"stack_switch_count__c": str(len(switches)),
                                  "VSF__c": True,
                                  "Stack_Set__c": "1",
                                  "Stack_Index__c": str(int(stack_index)),
                                  "Stack_Master_ID__c": primary_id}
                        if json.dumps(switch_config) != json.dumps(update):
                                logger.info('venue: %s device name: %s device id: %s some misalignment between expected from actual switch config' %(self.venue, device_name, device_id))
                                logger.info('venue: %s device name: %s device id: %s current config: %s' %(self.venue,device_name,device_id,switch_config))
                                logger.info('venue: %s device name: %s device id: %s new config: %s' %(self.venue,device_name,device_id,update))
                                try:
                                        self.sf.Asset.update(switch['Id'], update)
                                except:
                                        logger.error('venue: %s device name: %s device id: %s failed to update switch vsf config' %(self.venue, device_name, device_id))
                                else:
                                        logger.info('venue: %s device name: %s device id: %s updated switch vsf config' %(self.venue, device_name, device_id))

                        # update port presets for ports 45,46,47, and 48, if it already exist don't do anything
                        # port 45 and 47 should be set to VSF Port Link
                        # ports 46 and 48 should be set to VSF Port Link 2
                        for port_number in ['45', '47']:
                                port = [x for x in self.ports if
                                              x['Asset__c'] == switch['Id'] and
                                              port_number in x['Name']][0]
                                if port['Port_Preset__c'] != 'VSF Port Link':
                                        update = {'Port_Preset__c': 'VSF Port Link'}
                                        try:
                                                self.sf.Port__c.update(port['Id'], update)
                                        except:
                                                logger.error('%s,%s,%s,%s,failed to update port preset' %(self.venue,device_name,device_id,port['Name']))
                                        else:
                                                logger.info('%s,%s,%s,%s,updated port preset' %(self.venue,device_name,device_id,port['Name']))
                        for port_number in ['46', '48']:
                                port = [x for x in self.ports if
                                              x['Asset__c'] == switch['Id'] and
                                              port_number in x['Name']][0]
                                if port['Port_Preset__c'] != 'VSF Port Link 2':
                                        update = {'Port_Preset__c': 'VSF Port Link 2'}
                                        try:
                                                self.sf.Port__c.update(port['Id'], update)
                                        except:
                                                logger.error('%s,%s,%s,%s,failed to update port preset' %(self.venue,device_name,device_id,port['Name']))
                                        else:
                                                logger.info('%s,%s,%s,%s,updated port preset' %(self.venue,device_name,device_id,port['Name']))
                        # create tagged port joins on 41,42,44 - will fail silently if already exists
                        for vlan in self.VLAN:
                                venue_vlan = [x for x in self.vlans if str(int(x['VLAN_ID__c'])) == self.VLAN[vlan]['VLAN_ID__c']][0]
                                for port_number in ['41','42','44']:
                                        port = [x for x in self.ports if
                                                      x['Asset__c'] == switch['Id'] and
                                                      port_number in x['Name']][0]
                                        # Select AssetId__c, Port_ID__c, Tagged_Untagged__c, VLAN_ID__c FROM VLAN_Port_Join__c
                                        pj = {'Port_ID__c': port['Id'],
                                              'Tagged_Untagged__c': 'Tagged',
                                              'VLAN_ID__c': venue_vlan['Id']}
                                        # port must be set to trunk for these port joins to be created
                                        # if port isn't trunk, program halts and user should inspect the port directly
                                        try:
                                                self.sf.VLAN_Port_Join__c.create(pj)
                                        except exceptions.SalesforceMalformedRequest as ex:
                                                if 'duplicate value found' in ex.content[0]['message']:
                                                        pass
                                                else:
                                                        port_id = port['Id']
                                                        logger.info('venue: %s device id: %s port id: %s ex: %s' %(self.venue, device_id, port_id, ex))
                                                        return
                                        else:
                                                logger.info('%s,%s,%s,%s,created port join' %(self.venue,device_name,device_id,pj))
                self.update_queries()

        def compare_switches(self):
                switches = [x['Id'] for x in self.assets if x['Asset_Type__c'] == 'Switch']
                primary_switch = switches[0]
                primary_switch_ports_joins = [json.dumps({'Port Name': x['Port Name'], 'VLAN': x['VLAN_ID__c']})
                                              for x in self.port_joins if x['AssetId__c'] == primary_switch[:15]]
                primary_ports = [json.dumps({'POE': f"{x['POE_Capable__c']} {x['POE_Enabled__c']} {x['PoE_Mode__c']}", 'Name': x['Name'],
                                              'Enable': x['Enable__c'], 'Mode': x['Port_Mode__c']} )
                                              for x in self.ports if x['Asset ID'] == primary_switch]
                clones = switches[1:]
                for clone in clones:
                        clone_port_joins = [json.dumps({'Port Name': x['Port Name'], 'VLAN': x['VLAN_ID__c']})
                                        for x in self.port_joins if x['AssetId__c'] == clone[:15]]
                        clone_ports = [
                                json.dumps({'POE': f"{x['POE_Capable__c']} {x['POE_Enabled__c']} {x['PoE_Mode__c']}", 'Name': x['Name'],
                                            'Enable': x['Enable__c'], 'Mode': x['Port_Mode__c']})
                                                        for x in self.ports if x['Asset ID'] == clone]
                        for p in primary_ports:
                                if p not in clone_ports:
                                        logger.info('venue: %s clone: %s not identical due to this port diffrence %s' %(self.venue, clone, p))
                        for pj in primary_switch_ports_joins:
                                if pj not in clone_port_joins:
                                        logger.info('venue: %s clone: %s missing %s' %(self.venue, clone, pj))

        def configure_gateways(self):
                gateways = [x for x in self.assets if x['Asset_Type__c'] == 'Gateway']
                gateways = sorted(gateways, key= lambda x: x['Device_Name__c'])
                if len(gateways) == 2:
                        for i, gateway in enumerate(gateways):
                                gateway_name = gateway['Device_Name__c']
                                gateway_id = gateway['Id']
                                #logger.info('%s,%s,%s' %(gateway_name,gateway_id,gateway['Redundant_Configuration__c']))
                                # first gateway is primary
                                if i == 0 and gateway['Redundant_Configuration__c'] != 'primary':
                                        update = {"Redundant_Configuration__c": "primary"}
                                        try:
                                                self.sf.Asset.update(gateway['Id'], update)
                                        except:
                                                logger.error('venue: %s device_name: %s, device_id: %s failed to update redundant config to primary' %(self.venue,gateway_name,gateway_id))
                                        else:
                                                logger.info('venue: %s device_name: %s, device_id: %s updated redundant config to primary' %(self.venue,gateway_name,gateway_id))
                                elif i == 1 and gateway['Redundant_Configuration__c'] != 'secondary':
                                        update = {"Redundant_Configuration__c": "secondary"}
                                        try:
                                                result = self.sf.Asset.update(gateway['Id'], update)
                                        except:
                                                logger.error('venue: %s device_name: %s, device_id: %s failed to update redundant config to secondary' %(self.venue,gateway_name,gateway_id))
                                        else:
                                                logger.info('venue: %s device_name: %s, device_id: %s updated redundant config to secondary' %(self.venue,gateway_name,gateway_id))
                else:
                        logger.info('venue: %s more than 2 gateways set to Active or Shipped,unable to set primary and secondary' %self.venue)

        def check_ap(self):
                pass
        def check_gateway(self):
                pass

if __name__=='__main__':
        args = check_arguments()

        logger = get_logger('MyLogger', args.logfile, args.debug)
        #get mcd token and setup api
        tok = Token(account='apc-mcd', debug=args.debug)
        mcd_token = tok.GetTokenFromMsp('6666778917')
        api = ArubaApi(account='apc-mcd', access_token=mcd_token, debug=args.debug)
        #get group asset info
        aps = get_assets_apc(args.group, 'aps')
        sws = get_assets_apc(args.group, 'switches')
        gws = get_assets_apc(args.group, 'gateways')

        if args.action == 'start':
                #convert sales force venue id to 18 chars since sales force needs the 18 character id
                venue = args.venue
                if len(venue) == 15:
                        venue = sf15to18(venue)
                        logger.info('venue: %s starting apc and sfdc updates' %venue)
                elif len(venue) == 18:
                        logger.info('venue: %s starting apc and sfdc updates' %venue)
                else:
                        logger.warning('%s not 15 or 18 characters' %venue)
                        sys.exit(1)
                #verify 3 switches and 2 gateways are in apc before proceeding
                #if len(sws) != 3:
                #       logger.error('venue: %s group: %s all 3 switches are not in apc, try to reprovision and verify it gets added to apc' %(args.venue, args.group))
                #       sys.exit(1)
                #if len(gws) != 2:
                #       logger.error('venue: %s group: %s both gateways  are not in apc, try to reprovison and verify it gets added to apc' %(args.venue, args.group))
                #       sys.exit(1)
                #prompt for SFDC login info if you don't have enviornment variables saved
                #un = os.getenv('SFDCuser') or input('SFDC username: ')
                #pwd = os.getenv('SFDCpass') or getpass.getpass(prompt='Enter SFDC password: ')
                #token = os.getenv('SFDCtoken') or getpass.getpass(prompt='Enter SFDC token: ')
                #connect to sales force
                #sf = Salesforce(username=un, password=pwd, security_token=token)
                #set switches and gateways to monitor mode since some of the sfdc pushes can break stuff
                #get mech id info
                config = configparser.ConfigParser()
                config.read('/prod/noc/bin/mcd-aot-conversion-base-config')
                mechun = config['main']['sfdc_user'] or getpass.getpass(prompt='Enter SFDC password: ')
                mechpwd = base64.b64decode(config['main']['sfdc_pass']).decode('utf-8') or getpass.getpass(prompt='Enter SFDC password: ')
                mechtoken = base64.b64decode(config['main']['sfdc_token']).decode('utf-8') or getpass.getpass(prompt='Enter SFDC token: ')
                #connect to sales force with mech id
                try:
                    sf = Salesforce(username=mechun, password=mechpwd, security_token=mechtoken)
                except Exception as err:
                    logger.error('Could not connect to sales force with %s credentials, %s %(mechun,err}')
                    sys.exit(1)
                set_config_mode(sws, 'Monitor')
                set_config_mode(gws, 'Monitor')
                #create a config backup in apc just in case stuff breaks we can rollback to that
                create_config_backup(args.group)
                #allow group through mcds variable firewall
                allow_through_varfw(args.group)
                #check if mcd-aot-conversions directory exists, if not create it.  We save some sfdc queries here just in case we need for rollback
                check_dir('mcd-aot-conversions')
                #make sfdc updates
                boss = AOTSetupManager(sf, venue)
                boss.update_queries()
                boss.update_config_flag()
                boss.configure_vlans()
                #per net-eng mcd no longer wants to create the SSIDs.  commented out 11/17/21
                #boss.configure_ssids()
                boss.configure_switches()
                boss.configure_gateways()
                boss.compare_switches()
                logger.info('COMPLETE THESE STEPS BEFORE PROCEEDING!')
                logger.info('In Sales Force, click on Update All Template Variables from Venue Level.')
                logger.info('Also, from Switch 1 Asset Details page, click on the Virtual Switching Framework (VSF) button.')
                logger.info('Verify all Activity Instances completed.  If they didn\'t click on Update Template Variables button for each asset to ensure all the variables get pushed to APC.')
        elif args.action == 'verify':
                logger.info('venue: %s group: %s Verifying some key variables exist in APC' %(args.venue, args.group))
                #ap_var_chk = verify_ap_varaibles(aps)
                sw_var_chk = verify_sw_variables(sws)
                gw_var_chk = verify_gw_variabels(gws)
                #if all variables checks return true then re-add group to variable firewall
                if sw_var_chk and gw_var_chk:
                        logger.info('venue: %s group %s APC variables are good' %(args.venue, args.group))
                        removefrom_varfw(args.group)
        elif args.action == 'prechecks':
                find_gateway_uplink(sws)
                #get wayad credentials so we can log into gateway
                un = getpass.getuser()
                pwd = getpass.getpass(prompt='Enter wayad password: ')
                #ping_user_devices(gws)
                backoffice_ip = get_backoffice_ip(gws)
                user_ips = get_user_ips(sws, backoffice_ip)
                ping_user_ips(gws, user_ips)
        elif args.action == 'postchecks':
                site_id = get_site_id(args.group)
                associate_stack_tosite(sws, site_id)
