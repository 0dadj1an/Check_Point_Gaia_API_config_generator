#!/usr/local/bin/python3.8
__author__ = "ivo hrbacek"
__credits__ = ["ivosh", "laura"]
__version__ = "1.0"
__maintainer__ = "ivo hrbacek"
__email__ = "ihr@actinet.cz"
__status__ = "production"
__dev_version__ = "v1"

__spec__= "GaiaAPI connector"


import requests
import urllib3
import json
import sys
import time
import getpass
import logging
import os
import base64
import ipaddress
import signal
import argparse
from datetime import datetime


######## Class############
class DoLogging():

    """
    Logging class, to have some possibility debug code in the future

    """

    def __init__(self) -> None:

        """
        Constructor does not do anything
        """
        pass


    def do_logging(self:object, msg:str) -> None:

        """
        Log appropriate message into log file
        """

        # if needed change to DEBUG for more data
        current_path=(os.path.dirname(os.path.abspath(__file__)))
        log='{0}/gaia_api_connector.elg'.format(current_path)
        logging.basicConfig(filename=log, level=logging.DEBUG)
        msgq = 'TIME:{}:{}'.format(str(datetime.now()),msg)

        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True
        logging.info(msgq)
        logging.info(requests_log)





######## Class############
class Connector():

    """
    Connector class is main class handling connectivity to CP API
    """

    # do not care about ssl cert validation for now
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



    @classmethod
    def task_method(cls, sid:str, url:str, task:str) -> dict:

        """
        this is help method which is checking task status when publish is needed
        """

        payload_list={}
        payload_list['task-id']=task
        headers = {
            'content-type': "application/json",
            'Accept': "*/*",
            'x-chkp-sid': sid,
        }
        response = requests.post(url+"show-task", json=payload_list, headers=headers, verify=False)
        return response


    def __init__(self, url:str, payload:dict) -> dict:

        """
        This is constructor for class, login to API server is handled here - handling also conectivity problems to API
        """

        self.sid=""
        # default header without SID
        self.headers_default = {
             'content-type': "application/json",
              'Accept': "*/*",
             }
        # headers for usage in instance methods - with self.SID - will be filled up in constructor
        self.headers = {}
        self.url=url
        self.payload_list = payload # default only username and passowrd
        done=False
        counter=0

        # loop to handle connection interuption
        while not done:
            counter +=1
            if counter == 5:
                DoLogging().do_logging ('Connector() - init() - connection to API can not be established even in loop, check your credentials or IP connectivity')
                sys.exit(1)
            try:
                self.response = requests.post(self.url+"login", json=self.payload_list, headers=self.headers_default, verify=False)
                DoLogging().do_logging('Connector() - init() - login OK: {}'.format(self.url))

                DoLogging().do_logging('Connector() - init() - login data: {}'.format(self.response.text))
                if self.response.status_code == 200:
                    #print(json.loads(self.response.text))
                    try:
                        sid_out=json.loads(self.response.text)
                        self.sid = sid_out['sid']
                        self.headers = {
                                'content-type': "application/json",
                                'Accept': "*/*",
                                'x-chkp-sid': self.sid,
                        }
                        DoLogging().do_logging('Connector() - init() - Connection to API is okay')

                    except Exception as e:
                        DoLogging().do_logging(' Connector() - init() - API is not running probably: {}..'.format(e))
                else:
                    a = json.loads(self.response.text)
                    DoLogging().do_logging("Connector() - init() - Exception occured: {}".format(a))

                    DoLogging().do_logging('Connector() - init() - There is no SID, connection problem to API gateway, trying again..')
                    time.sleep (1)
                    continue
            except Exception as e:
                DoLogging().do_logging(' Connector() - init() - exception occured..can not connect to mgmt server, check IP connectivity or ssl certificates!!! : {}'.format(e))
            else:
                done=True



    def logout(self) -> None:

        """
        Logout method for correct disconenction from API

        """

        done=False
        counter=0
        while not done:
            counter +=1
            if counter == 5:
                DoLogging().do_logging('Connector() - logout() - logout can not be done because connection to mgmt is lost and reconnect does not work...')
                sys.exit(1)

            else:
                try:
                    payload_list={}
                    self.response = requests.post(self.url+"logout", json=payload_list, headers=self.headers, verify=False)
                    if self.response.status_code == 200:
                        DoLogging().do_logging ('Connector() - logout() - logout from API is okay')
                        return self.response.json()
                    else:
                        out = json.loads(self.response.text)
                        DoLogging().do_logging (" ")
                        DoLogging().do_logging(out)
                        DoLogging().do_logging (" ")
                        return self.response.json()

                except Exception as e:
                   DoLogging().do_logging ('Connector() - logout() - connection to gateway is broken, trying again: {}'.format(e))

    @staticmethod
    def base64_ascii(base64resp:str) -> str:
        """Converts base64 to ascii for run command/showtask."""
        try:
            return base64.b64decode(base64resp).decode('utf-8')
        except Exception as e:
            DoLogging().do_logging("base64 error:{}".format(e))



    def run_script(self, payload:dict) -> str:

        """
        run script method is responsible for running script on target (ls -la, df -lh etc. basic linux commands)
        """

        payload_list=payload
        headers = {
            'content-type': "application/json",
            'Accept': "*/*",
            'x-chkp-sid': self.sid,
        }


        return_string = ''

        done=False
        counter=0

        while not done:
            counter +=1
            if counter == 5:
                DoLogging().do_logging('Connector() - run_script() - discard can not be done because connection to mgmt is lost and reconnect does not work...')
                sys.exit(1)

            else:
                try:
                    self.response = requests.post(self.url+"run-script", json=payload_list, headers=headers, verify=False)

                    task=json.loads(self.response.text)

                    while True:
                        show_task=Connector.task_method(self.sid,self.url,task['task-id'])
                        show_task_text=json.loads(show_task.text)
                        #DoLogging().do_logging ("Connector() - run_script() - :{}".format(show_task_text))
                        time.sleep (5)
                        if show_task_text['tasks'][0]['progress-percentage'] == 100:
                            base64resp = (str(self.send_cmd('show-task', payload={"task-id":show_task_text['tasks'][0]['task-id']})['tasks'][0]['task-details'][0]['output']))
                            asciiresp = self.base64_ascii(base64resp)
                            return_string=return_string+"\n\n"+"Data for target:"+"\n"+asciiresp+"\n\n\n\n\n\n"
                            #DoLogging().do_logging ("Connector() - run_script() - :{}".format(show_task_text))
                            break
                        else:
                            continue


                    return return_string

                except Exception as e:
                    DoLogging().do_logging ("Connector() - run_script() - Exception in run_script method, some data not returned, continue: {} {}".format(e, tasks))
                else:
                    done=True




    def send_cmd(self, cmd:str, payload:dict) -> dict:

        """
        Core method, all data are exchanged via this method via cmd variable, you can show, add data etc.
        """

        done=False
        counter=0
        while not done:
            counter +=1
            if counter == 5:
                DoLogging().do_logging ("Connector() - send_cmd() - Can not send API cmd in loop, there are some problems, changes are unpublished, check it manually..")
                self.logout()
                sys.exit(1)
            else:
                try:
                     payload_list=payload
                     self.response = requests.post(self.url + cmd, json=payload_list, headers=self.headers, verify=False)
                     if self.response.status_code == 200:
                         #uncomment for TSHOOT purposes
                         DoLogging().do_logging ('Connector() - send_cmd() - send cmd is okay')
                         #out = json.loads(self.response.text)
                         #DoLogging().do_logging ('Connector() - send_cmd() - send cmd response is 200 :{}'.format(out))
                         return self.response.json()
                     else:
                         out = json.loads(self.response.text)
                         DoLogging().do_logging(" Connector() - send_cmd() - response code is not 200 :{}".format(out))
                         return self.response.json()


                except Exception as e:
                    DoLogging().do_logging ("Connector() - send_cmd() - POST operation to API is broken due connectivity flap or issue.. trying again..: {}".format(e))



######## Class############
class Interactive_Init_Handler():
    """
    Init class for getting basic data about user/pwd/GW IP and establishing connector for API
    """

    def __init__(self) -> None:
        self.user=''
        self.password=''
        self.IP=''
        self.node1IP=''
        self.node2IP=''
        self.connector=None
        self.connectors=[]
        self.version=''
        self.data = None
        self.path=''

    @staticmethod
    def validate_ip(ip:str) -> bool:

        """
        validate ip format to avoid adding crazy data for IP based variable
        """

        check = True


        try:
            data = ip.split(":")
            ip = ipaddress.ip_address(data[0])

            return check

        except Exception as e:

            check= False
            print ("IP validation failed for some reason!: {}".format(e))
            return check


    def _single(self, singleIP=None)-> None:

        """
        establishing single connector to appropriate gateways via special class Connector() object
        depends on the call from Interactive_Init_Handler().run() it is asking for path to json or not
        """
        try:

            if singleIP == None:
                self.IP=input("Enter GW IP: ")

            else:
                self.IP = singleIP


            if not self.user or not self.password or not self.IP:
                print ("Empty username or password or server IP, finish..")
                sys.exit(1)

            else:
                if self.validate_ip(self.IP):
                    payload ={
                        "user":self.user,
                        "password":self.password
                    }
                    try:
                        connector = Connector('https://{}/gaia_api/'.format(self.IP), payload)
                        self.connector = connector

                    except Exception as e:
                        print ("Can not establish connector, check logcp_gaia_api.elg : {}".format(e))
                else:
                    print ("Wrong IP for single GW, exit")
                    raise Exception ("Wrong IP for single GW, exit")


        except Exception as e:
            raise Exception ("Error in Interactive_Init_Handler()._single() method")



        print ("Connector to single gw is established")


    def _cluster (self, nodeIP1=None, nodeIP2=None) -> None:

        """
        establishing cluster connectors to appropriate gateways via special class Connector() object
        depends on the call from Interactive_Init_Handler().run() it is asking for path to json or not
        """
        try:

            if nodeIP1 == None and nodeIP2 == None:
                self.node1IP=input("Enter node1 IP: ")
                self.node2IP=input("Enter node2 IP: ")
            else:
                self.node1IP = nodeIP1
                self.node2IP = nodeIP2

            if not self.user or not self.password or not self.node1IP or not self.node2IP:
                print ("Empty username or password or server IP, finish..")
                sys.exit(1)

            else:
                if self.validate_ip(self.node1IP):
                    payload ={
                        "user":self.user,
                        "password":self.password
                    }
                    try:
                        connector = Connector('https://{}/gaia_api/'.format(self.node1IP), payload)
                        self.connectors.append(connector)
                    except Exception as e:
                        print ("Can not establish connector, check logcp_gaia_api.elg : {}".format(e))

                if self.validate_ip(self.node2IP):
                    payload ={
                        "user":self.user,
                        "password":self.password
                    }
                    try:
                        connector = Connector('https://{}/gaia_api/'.format(self.node2IP), payload)
                        self.connectors.append(connector)
                    except Exception as e:
                        print ("Can not establish connector, check logcp_gaia_api.elg : {}".format(e))

                else:
                    print ("Wrong IP for single GW, exit")
                    raise Exception ("Wrong IP for single GW, exit")

        except Exception as e:
            raise Exception ("Error in Interactive_Init_Handler()._cluster() method")


        print ("Connectors to cluster established")


    def _load_data(self, path=None)-> dict:

        """
        load json data via separate object via class Load_Data()
        depends on the call from Interactive_Init_Handler().run() it is asking for path to json or not

        """
        try:
            if path == None:
                # interactive mode
                path=input("Where is your json file with data for vlan manipulation?\n If no path specified, I count file data.json is in same folder as script\n")
                if not path:
                    data = Load_Data()
                    return data.load_data()
                else:
                    data = Load_Data(path)
                    return data.load_data()
            else:
                # mode with args
                data = Load_Data(path)
                return data.load_data()

        except Exception as e:
            raise Exception




    def run(self) -> None:

        """
        handle user input at the beginning //  handle argparse parameters - depends on the format

        """

        try:

            argParser = argparse.ArgumentParser(description='_Script for Gaia API modification_')

            argParser.add_argument("-s", dest="single", help=('specify single GW IP'), required=False)
            argParser.add_argument("-jh", dest="jh", help=('display json format help'), required=False)
            argParser.add_argument("-n1", dest="node1", help=('spiecify cluster node1 IP'), required=False)
            argParser.add_argument("-n2", dest="node2", help=('spiecify cluster node2 IP'), required=False)
            argParser.add_argument("-u", dest="user", help=('spiecify user name'), required=False)
            #argParser.add_argument("-p", dest="password", help=('spiecify password'), required=False)
            argParser.add_argument("-v", dest="version", help=('spiecify version to run [cluster/single]'), required=False)
            argParser.add_argument("-d", dest="path", help=('spiecify path to json data, default is the same directory'), required=False)
            args = argParser.parse_args()
            if  args.jh == "TRUE":
                print (Error_Msg().display())
                sys.exit(1)

            # check if args are filled up, if not do interactive mode
            if args.user == None and args.version == None and args.path == None:

                print("###############################",

                    "Check Point GAiA API connector, interactive mode for Gaia OS modification via API",
                    "",
                    "XXXXXXXXXX Training version for ihr XXXXXXXXXXXX",
                    "There is a log file: logcp_gaia_api.elg  in the same folder as this script, check it if something goes wrong ",
                    "",
                    "This script takes json data [keys node1,node2,single in XXX.json are mandatory!] -> respect general GAiA API calls -> for other keys and payloads for that call consult gaia API reference",
                    "",
                    "!!!!! IF you do not want to use interactive mode, just hit ctrl+c and run python gaia_api_connector.py -h !!!!",
                    "",
                    "If you want to see supported json format, run gaia_api_connector.py -jh TRUE ",
                    "",
                    "###############################",
                    sep="\n")



                self.user=input("Enter API/GUI user name with write permissions: ")
                self.password=getpass.getpass()
                self.version=input("Is this single GW or Cluster?\n Type: [single] for single GW or [cluster] for cluster GW:")
                if self.version == "single":
                    try:
                        self.version='single'
                        self._single()
                        self.data = self._load_data()
                        print ("")
                        print ("#########################################")
                        print ("Running on single node: {}".format(self.IP))
                        try:
                            Operate_CP(self.data['single'],self.connector).run()
                        except Exception as e:
                            raise Exception("json data issue, single, interactive..")
                        print ("#########################################")
                        print ("")
                    except Exception as e:
                        print ("issue when calling single gw from interactive mode in run() method : {}".format(e))
                        raise Exception ("Clean  up in progress in progress")



                elif self.version == "cluster":
                    try:
                        self.version='cluster'
                        self._cluster()
                        self.data = self._load_data()
                        print ("")
                        print ("#########################################")
                        print ("Running on node: {}".format(self.node1IP))
                        try:
                            Operate_CP(self.data['node1'],self.connectors[0]).run()
                        except Exception as e:
                            raise Exception("json data issue, cluster, interactive..")

                        print ("#########################################")
                        print ("")
                        print ("")
                        print ("#########################################")
                        print ("Running on node: {}".format(self.node2IP))
                        try:
                            Operate_CP(self.data['node2'], self.connectors[1]).run()
                        except Exception as e:
                            raise Exception("json data issue, cluster, interactive..")

                        print ("#########################################")
                        print ("")



                    except Exception as e:
                        print ("issue when calling cluster from interactive mode in run() method : {}".format(e))
                        raise Exception ("Clean  up in progress")

                else:
                    print ("")
                    print ("")
                    print ("You were asked for something, your input was wrong, now you have to start again :P\n Press ctrl+c for exit")
                    print ("")
                    print ("")
                    self.run()

            # non interactive mode here
            else:
                if args.user == None or args.version == None or args.path == None :
                    print ("migging arguments, run -h option")
                else:
                    self.user = args.user
                    self.password = getpass.getpass()
                    self.version = args.version
                    self.path = args.path


                    if self.version == "single":
                        if args.single == None:
                            print ("migging or wrong arguments, run -h option")
                        else:
                            try:

                                self.IP = args.single
                                self._single(self.IP)
                                self.data = self._load_data(self.path)


                                print ("")
                                print ("#########################################")
                                print ("Running on node: {}".format(self.IP))
                                try:
                                    Operate_CP(self.data['single'],self.connector).run()
                                except Exception as e:
                                    raise Exception ("json data issue, single, non-interactive..")

                                print ("#########################################")
                                print ("")
                            except Exception as e:
                                print ("issue when calling single gw from non-interactive mode in run() method : {}".format(e))
                                raise Exception ("Clean up in progress")


                    else:
                        if args.node1 == None and args.node2 == None:
                            print ("migging or wrong arguments, run -h option")
                        else:
                            try:
                                self.node1IP = args.node1
                                self.node2IP = args.node2
                                self._cluster(self.node1IP, self.node2IP)
                                self.data = self._load_data(self.path)

                                try:
                                    print ("")
                                    print ("#########################################")
                                    print ("Running on node: {}".format(self.node1IP))
                                    Operate_CP(self.data['node1'],self.connectors[0]).run()
                                    print ("#########################################")
                                    print ("")

                                    print ("")
                                    print ("##########################################")
                                    print ("Running on node: {}".format(self.node2IP))
                                    Operate_CP(self.data['node2'], self.connectors[1]).run()
                                    print ("#########################################")
                                    print ("")
                                except Exception as e:
                                    raise Exception ("json data issue, cluster, non-interactive..")


                            except Exception as e:
                                print ("issue when calling cluster from non-interactive mode in run() method : {}".format(e))
                                raise Exception ("Clean up in progress")





        except KeyboardInterrupt:
            print ("\n ctrl+c pressed, exit..")
            # if there is no connector just leave
            try:
                self.connector.logout()
                sys.exit(1)
            except:
                try:
                    for item in self.connectors:
                        item.logout()
                    sys.exit(1)
                except:
                    sys.exit(1)

        except Exception as e:
            print ("\n Interactive_Init_Handler().run() error: {}".format(e))
            # if there is no connector just leave
            try:
                self.connector.logout()
                sys.exit(1)
            except:
                try:
                    for item in self.connectors:
                        item.logout()
                    sys.exit(1)
                except:
                    sys.exit(1)



######## Class############
class Operate_CP():

    """
    data are extracted here and send against Gaia API

    """

    def __init__(self, data:list, connector:object) -> None:
        self.data = data
        self.connector = connector


    def run(self):
        try:
            check_msg02_sent = False # check if special error msg has been displayed
            for cmd in self.data: # every item in self.data is like a call with payload
                keys = list(cmd.keys()) # I need keys since I do not know what is there - key is api call
                i=0 # aka first key in keys list
                for item in keys:
                    try:
                        if i > 0: # if there is more keys in dict, finsh, this is unsupported format for this script
                            raise Exception ("Unsupported json format for this script")
                    except Exception as e:
                        print ("Operate_CP().run() issue: {}!! \n {}".format(e, Error_Msg().display2()))
                        check_msg02_sent = True # msg has been send, set check
                        raise Exception ("Unsupported json format for this script")

                    else:
                        print ("#####################################")
                        print ("running API call:{}".format(keys[i]))
                        if keys[i] =="run-script":
                            #run script has special method because output is encoded in base64 format
                            for item in cmd[keys[i]]:# for every item in apicall -> {"apicall": [{payload}, payload]} -> run the payload against API
                                print ("")
                                print ("payload:\n {}".format(item))
                                print ("result: {}".format(self.connector.run_script(item)))
                                print ("")
                        else:
                            for item in cmd[keys[i]]:# for every item in apicall -> {"apicall": [{payload}, payload]} -> run the payload against API
                                print ("")
                                print ("payload:\n {}".format(item))
                                print ("result: {}".format(json.dumps(self.connector.send_cmd(keys[i],item), indent=4, sort_keys=True)))
                                print ("")
                            print ("#######################################")
                            i+=1

        except Exception as e:
            if check_msg02_sent == False:
                print ("Operate_CP().run() issue: Follow right json data format for this script!! \n {}".format(Error_Msg().display()))
            raise Exception ("Unsupported json format for this script")



######## Class############
class Error_Msg():

    def __init__(self) -> None:
        pass



    def display2(self):
        return ("""Make sure you have right format:\n

     You defined just one item in node1 list and rest as part of dict -->\n
      [{"cmd1":[{payload_data01}, {payload-data02}], "cmd2":[{payload_data01}, {payload-data02}]}]

      this format is not supported... \n
      be really careful, you can owerwrite your data (eth1.11 overwritten by eth1.20) if you do something like this since in python dict :\n

     "node1": [
      {"delete-vlan-interface":[

        {"name":"eth1.11"},

        {"name":"eth1.12"},

        {"name":"eth1.13"},

        {"name":"eth1.14"}],

      "add-vlan-interface":[

        {"parent":"eth1","id":11, "ipv4-address":"10.10.20.2", "ipv4-mask-length":24},

        {"parent":"eth1","id":12, "ipv4-address":"10.10.30.2", "ipv4-mask-length":24},

        {"parent":"eth1","id":13, "ipv4-address":"10.10.40.2", "ipv4-mask-length":24},

        {"parent":"eth1","id":14, "ipv4-address":"10.10.50.2", "ipv4-mask-length":24}],

      "delete-vlan-interface":[

        {"name":"eth1.20"},

        {"name":"eth1.12"},

        {"name":"eth1.13"},

        {"name":"eth1.14"}]

      }
    ],

    "node2":[
        {XXX}
      ]

     "single":[
        {XXX}
      ]
    }

    """)


    def display(self):
        return (""" Make sure you have right format:\n
                Keys node1, node2, single are mandatory!\n

    define as dedicated item in node1[] list -->\n
    [{"apiCall":[{payload_data01}, {payload-data02}]},{"apiCall":[{payload_data01}, {payload-data02}]}]
    prefered format!!!

    {
    "node1": [

      {"add-vlan-interface":[

      {"parent":"eth1","id":11, "ipv4-address":"10.10.20.2", "ipv4-mask-length":24},

      {"parent":"eth1","id":12, "ipv4-address":"10.10.30.2", "ipv4-mask-length":24},

      {"parent":"eth1","id":13, "ipv4-address":"10.10.40.2", "ipv4-mask-length":24},

      {"parent":"eth1","id":14, "ipv4-address":"10.10.50.2", "ipv4-mask-length":24}]},


      {"add-vlan-interface":[

      {"parent":"eth1","id":11, "ipv4-address":"10.10.20.2", "ipv4-mask-length":24},

      {"parent":"eth1","id":12, "ipv4-address":"10.10.30.2", "ipv4-mask-length":24},

      {"parent":"eth1","id":13, "ipv4-address":"10.10.40.2", "ipv4-mask-length":24},

      {"parent":"eth1","id":14, "ipv4-address":"10.10.50.2", "ipv4-mask-length":24}]}

    ],


     "node2": [
       {XXX},
       {XXX}
    ],

     "single":[
       {XXX},
       {XXX}
    ]
    }

    if you are using cluster, define node1 and node2, but leave single in json file as follow:
    "single":[]

    same for case you are running via single, just leave node1, node2 lists empty but keep the keys!!!

    """)

######## Class############

class Load_Data():

    def __init__(self, path='data.json') -> None:
        self.path = path


    def _validate_data(self, data) -> bool:


        try:
            if 'node1' in data and 'node2' in data and 'single' in data:
                return True
        except Exception as e:
            print ("There is wrong data format: {} gateway".format(e))
            return False



    def load_data(self) -> dict:
        try:
            with open(self.path) as f:
                data = json.load(f)
                if self._validate_data(data):
                    if data == None:
                        raise Exception(Error_Msg().display())
                    else:
                        return data
                else:
                    raise Exception(Error_Msg().display())

        except Exception as e:
            print ("Can not load data, make sure path to data.json is right or json is in same folder as script, make sure your format is right: {}".format(e))
            print(Error_Msg().display())

######## Class############




def handler(signum, frame):

    """
    just handling if someone press ctrl+z
    """

    print ("Ctrl+Z pressed, but ignored")



def main():

    """
    main method where all starts
    enjoy! ihr..

    """

    try:
        current_path=(os.path.dirname(os.path.abspath(__file__)))
        log='{0}/gaia_api_connector.elg'.format(current_path)
        os.remove(log)
    except Exception as e:
        pass


    signal.signal(signal.SIGTSTP, handler)
    run = Interactive_Init_Handler()
    run.run()



if __name__ == "__main__":

    main()
