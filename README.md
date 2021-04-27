# Check_Point_Gaia_API_config_generator
configure CP FW via Gaia OS API only


# GAIA_API_davkovac

- data from json file are pushed to Gaia OS via API 

- interaactive mode:
mode single - single IP (single node) /// mode cluster -  (IP of every node)

- params mode:
see help below


- script respects generall API calls for Gaia OS /// what you can use, that can be added to json file ///
- call = delete-vlan-interface ( needs to be valid Gia OS API call),  payload = {"name":"eth1.11"} - needs to be valid payload

- keys node1, node2, singe are mandatory, but can be empty, see  ```python gaia_api_connector.py -jh JH```

- Gaia OS API viz.
https://sc1.checkpoint.com/documents/latest/GaiaAPIs/index.html?#introduction~v1.5%20



- help:
```
python gaia_api_connector.py -h
usage: gaia_api_connector.py [-h] [-s SINGLE] [-jh JH] [-n1 NODE1] [-n2 NODE2]
                             [-u USER] [-p PASSWORD] [-v VERSION] [-d PATH]

_Script for Gaia API modification_

optional arguments:
  -h, --help   show this help message and exit
  -s SINGLE    specify single GW IP
  -jh JH       display json format help
  -n1 NODE1    spiecify cluster node1 IP
  -n2 NODE2    spiecify cluster node2 IP
  -u USER      spiecify user name
  -p PASSWORD  spiecify password
  -v VERSION   spiecify version to run [cluster/single]
  -d PATH      spiecify path to json data, default is the same directory
```


json data:
```
{   
    "node1": [
      
      {"delete-vlan-interface":[

        {"name":"eth1.11"},
    
        {"name":"eth1.12"},
    
        {"name":"eth1.13"},
    
        {"name":"eth1.14"}]
      },

      {"add-vlan-interface":[

        {"parent":"eth1","id":11, "ipv4-address":"10.10.20.2", "ipv4-mask-length":24},
    
        {"parent":"eth1","id":12, "ipv4-address":"10.10.30.2", "ipv4-mask-length":24},
    
        {"parent":"eth1","id":13, "ipv4-address":"10.10.40.2", "ipv4-mask-length":24},
    
        {"parent":"eth1","id":14, "ipv4-address":"10.10.50.2", "ipv4-mask-length":24}]},


    ],
  
     "node2": [
      {"delete-vlan-interface":[

        {"name":"eth1.11"},
    
        {"name":"eth1.12"},
    
        {"name":"eth1.13"},
    
        {"name":"eth1.14"}]},


      {"add-vlan-interface":[

        {"parent":"eth1","id":11, "ipv4-address":"10.10.20.2", "ipv4-mask-length":24},
    
        {"parent":"eth1","id":12, "ipv4-address":"10.10.30.2", "ipv4-mask-length":24},
    
        {"parent":"eth1","id":13, "ipv4-address":"10.10.40.2", "ipv4-mask-length":24},
    
        {"parent":"eth1","id":14, "ipv4-address":"10.10.50.2", "ipv4-mask-length":24}]}

     ],
  
     "single":[
      {"delete-vlan-interface":[

        {"name":"eth1.11"},
    
        {"name":"eth1.12"},
    
        {"name":"eth1.13"},
    
        {"name":"eth1.14"}]},


      {"add-vlan-interface":[
      
        {"parent":"eth1","id":11, "ipv4-address":"10.10.20.2", "ipv4-mask-length":24, "comments":"9000"},
    
        {"parent":"eth1","id":12, "ipv4-address":"10.10.30.2", "ipv4-mask-length":24},
    
        {"parent":"eth1","id":13, "ipv4-address":"10.10.40.2", "ipv4-mask-length":24},
    
        {"parent":"eth1","id":14, "ipv4-address":"10.10.50.2", "ipv4-mask-length":24}]},
      
      {"set-physical-interface":[
        {"name":"eth1", "mtu":9000}]},

      {"set-vlan-interface":[
        {"name":"eth1.11", "mtu":9000}]},

      {"show-static-routes":[
        {}]},

      {"run-script":[
        {"script": "route -n"},
        {"script": "clish -c \"lock database override \""},
        {"script": "uname -a"},
        {"script": "clish -c \"set hostname IVOSH\""},
        {"script": "uname -a"}]}

        
     ]
    }
    
