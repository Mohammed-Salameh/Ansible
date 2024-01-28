vyos-inventory.ini

[vyos_devices]
vyos ansible_host=172.16.1.150

[vyos_devices:vars]
ansible_user=vyos
ansible_password=P@ssw0rd
ansible_network_os=vyos.vyos.vyos
ansible_connection=network_cli
ansible_become=yes

vyos-requirements.yml

---
collections:
  - name: vyos.vyos
    version: 4.1.0


vyos-playbook.yml

---
# Playbook name: Configure Vyos
# Target hosts: Vyos
# Collections: vyos.vyos
# Variables: Loaded from variables.yml
# Gathering facts: No
# Tasks: List of tasks to configure Vyos.

- name: Configure Vyos
  hosts: vyos
  collections:
    - vyos.vyos
  vars_files:
    - Vyos-variables.yml
  gather_facts: no
  tasks:
    # Task 1: Configure Host Name
    - name: Configure Host Name
      vyos.vyos.vyos_hostname:
        config:
          hostname: "{{ vyos_host_name | default('vyos') }}"
      loop:
        - "{{ vyos_host_name | default('vyos') }}"
      when: vyos_host_names is defined
      # This task configures the host name on the Vyos router
      # using the value provided in the `vyos_host_name` variable.

    # Task 2: Configure SSH Service and Port
    - name: Configure SSH Service and Port
      vyos.vyos.vyos_config:
        config:
          - "set service ssh port {{ vyos_ssh_port | default(22) }}"
      loop:
        - "{{ vyos_ssh_port | default(22) }}"
      when: vyos_ssh_port is defined
      # This task configures the SSH service and port on the Vyos router
      # using the value provided in the `vyos_ssh_port` variable.

    # Task 3: Configure L3 Interfaces
    - name: Configure L3 Interfaces
      vyos.vyos.vyos_l3_interfaces:
        config:
          - name: "{{ item.name }}"
            ipv4:
              - address: "{{ item.address }}"
              # TODO: Add configuration for description and duplex
      loop: "{{ vyos_l3_interfaces }}"
      when: vyos_l3_interfaces is defined
      # This task configures L3 interfaces on the Vyos router
      # using the values provided in the `vyos_l3_interfaces` variable.

    # Task 4: Configure Firewall Rules
    - name: Configure Firewall Rules
      vyos.vyos.vyos_firewall_rules:
        config:
          - afi: "ipv4"
            rule_sets: "{{ vyos_firewall_rule_sets }}"
      when: vyos_firewall_rule_sets is defined
      # This task configures firewall rules on the Vyos router
      # using the values provided in the `vyos_firewall_rule_sets` variable.

    # Task 5: Configure VRRP Groups
    - name: Configure VRRP Groups
      vyos.vyos.vyos_config:
        lines:
          - "set interfaces ethernet {{ item.interface }} vrrp vrrp-group {{ vrrp_group.group }} virtual-address {{ vrrp_address }}"
          - "set interfaces ethernet {{ item.interface }} vrrp vrrp-group {{ vrrp_group.group }} priority {{ vrrp_group.priority }}"
          - "set interfaces ethernet {{ item.interface }} vrrp vrrp-group {{ vrrp_group.group }} description '{{ vrrp_group.description }}'"
        save: true
        parents: ["interfaces ethernet {{ item.interface }}"]
      loop: "{{ vyos_vrrp_groups }}"
      loop_control:
        loop_var: item
      vars:
        vrrp_group: "{{ item.vrrp_group | first }}"
        vrrp_address: "{{ vrrp_group.virtual_addresses | first }}"
      when: vyos_vrrp_groups is defined

      # This task configures VRRP groups on the Vyos router
      # using the values provided in the `vyos_vrrp_groups` variable.

    # Task 6: Configure VRRP
    - name: Configure VRRP
      vyos.vyos.vyos_config:
        config:
          - "set high-availability vrrp group {{ item.group }} authentication password '{{ item.authentication.password }}'"
          - "set high-availability vrrp group {{ item.group }} authentication type '{{ item.authentication.type }}'"
          - "set high-availability vrrp group {{ item.group }} hello-source-address '{{ item.hello_source_address }}'"
          - "set high-availability vrrp group {{ item.group }} interface '{{ item.interface }}'"
          - "set high-availability vrrp group {{ item.group }} peer-address '{{ item.peer_address }}'"
          - "set high-availability vrrp group {{ item.group }} priority '{{ item.priority }}'"
          - "set high-availability vrrp group {{ item.group }} virtual-address {{ item.virtual_address }}"
          - "set high-availability vrrp group {{ item.group }} vrid '{{ item.vrid }}'"
      loop: "{{ vrrp_groups }}"
      when: vrrp_groups is defined
      # This task configures VRRP on the Vyos router
      # using the values provided in the `vrrp_groups` variable.

    # Task 7: Configure NAT Rules
    - name: Configure NAT Rules
      vyos.vyos.vyos_config:
        config:
          - "set nat source rule {{ item.rule_number }}"
          - "set nat source rule {{ item.rule_number }} destination address '{{ item.destination_address | default(omit) }}'"
          - "set nat source rule {{ item.rule_number }} exclude {{ item.exclude | default(omit) }}'"
          - "set nat source rule {{ item.rule_number }} outbound-interface '{{ item.outbound_interface }}'"
          - "set nat source rule {{ item.rule_number }} source address '{{ item.source_address }}'"
          - "set nat source rule {{ item.rule_number }} translation address '{{ item.translation_address | default(omit) }}'"
          - "set nat source rule {{ item.rule_number }} description '{{ item.description | default(omit) }}'"
      loop: "{{ nat_rules }}"
      when: nat_rules is defined and nat_rules | length > 0
      # This task configures NAT rules on the Vyos router
      # using the values provided in the `nat_rules` variable.

    # Task 8: Set DHCP Failover Globally
    - name: Set DHCP Failover Globally
      vyos.vyos.vyos_config:
        config:
          - "set service dhcp-server failover enable"
      when: configure_dhcp
      # This task enables DHCP failover globally on the Vyos router
      # if the `configure_dhcp` variable is defined and true.

    # Task 9: Set DHCP Failover
    - name: Set DHCP Failover
      vyos.vyos.vyos_config:
        config:
          - "set service dhcp-server failover name '{{ dhcp_failover.name }}'"
          - "set service dhcp-server failover remote '{{ dhcp_failover.remote }}'"
          - "set service dhcp-server failover source-address '{{ dhcp_failover.source_address }}'"
          - "set service dhcp-server failover status '{{ dhcp_failover.status }}'"
      when: configure_dhcp
      # This task configures DHCP failover on the Vyos router
      # if the `configure_dhcp` variable is defined andContinuing from where we left off:


    # Task 10: Set DHCP Listen Addresses
    - name: Set DHCP Listen Addresses
      vyos.vyos.vyos_config:
        config:
          - "set service dhcp-server listen-address '{{ item }}'"
      loop: "{{ dhcp_listen_addresses }}"
      when: configure_dhcp
      # This task sets DHCP listen addresses on the Vyos router
      # if the `configure_dhcp` variable is defined and true.

    # Task 11: Set DHCP Shared Network
    - name: Set DHCP Shared Network
      vyos.vyos.vyos_config:
        config:
          - "set service dhcp-server shared-network-name {{ dhcp_shared_network.name }} authoritative"
          - "set service dhcp-server shared-network-name {{ dhcp_shared_network.name }} name-server '{{ item }}'"
      loop: "{{ dhcp_shared_network.name_servers }}"
      when: configure_dhcp
      # This task sets DHCP shared network configuration on the Vyos router
      # if the `configure_dhcp` variable is defined and true.

    # Task 12: Configure Zones
    - name: Configure Zones
      vyos.vyos.vyos_config:
        config:
          - "set zone-policy zone {{ item.zone_name }} interface {{ item.interfaces }}"
          - "set zone-policy zone {{ item.zone_name }} action {{ item.zone_action }}"
      loop: "{{ vyos_zones }}"
      when: vyos_zones is defined
      # This task configures zones on the Vyos router
      # using the values provided in the `vyos_zones` variable.

    # Task 13: Configure Zone Policies
    - name: Configure Zone Policies
      vyos.vyos.vyos_config:
        config:
          - "set zone-policy policy {{ item.name }} from {{ item.from_zones }}"
          - "set zone-policy policy {{ item.name }} action {{ item.policy_action }}"
      loop: "{{ vyos_zone_policies }}"
      when: vyos_zone_policies is defined
      # This task configures zone policies on the Vyos router
      # using the values provided in the `vyos_zone_policies` variable.

    # Task 14: Configure DNS Forwarding
    - name: Configure DNS Forwarding
      vyos.vyos.vyos_config:
        config:
          - "set service dns forwarding allow-from '{{ item.allow_from }}'"
          - "set service dns forwarding listen-address '{{ item.listen_address }}'"
          - "set service dns forwarding system"
      loop: "{{ dns_forwarding }}"
      when: dns_forwarding is defined
      # This task configures DNS forwarding on the Vyos router
      # using the values provided in the `dns_forwarding` variable.

    # Task 15: Configure IPsec
    - name: Configure IPsec
      vyos.vyos.vyos_config:
        config:
          - "{{ item }}"
      loop: "{{ ipsec_config }}"
      when: ipsec_config is defined
      # This task configures IPsec on the Vyos router
      # using the values provided in the `ipsec_config` variable.

    # Task 16: Configure NTP Servers
    - name: Configure NTP
      vyos.vyos.vyos_config:
        config:
          - "set service ntp"
          - "set service ntp server {{ item }}"
      loop: "{{ ntp_servers }}"
      when: ntp_servers is defined and ntp_servers | length > 0
      # This task configures NTP servers on the Vyos router
      # using the values provided in the `ntp_servers` variable.

    
    # Task 17: Configure Name Servers
    - name: Configure Name Servers
      vyos.vyos.vyos_config:
        config:
          - "set system name-server '{{ item }}'"
      loop: "{{ name_servers }}"
      when: name_servers is defined and name_servers | length > 0
      # This task configures name servers on the Vyos router
      # using the values provided in the `name_servers` variable.

    # Task 18: Configure Firewall State Policies
    - name: Configure Firewall State Policies
      vyos.vyos.vyos_config:
        config:
          - "set firewall state-policy established action 'accept'"
          - "set firewall state-policy invalid action 'reject'"
          - "set firewall state-policy related action 'accept'"
      when: state_policies is defined and state_policies | length > 0
      # This task configures firewall state policies on the Vyos router
      # if the `state_policies` variable is defined and not empty.

    # Task 19: Configure Static Routes
    - name: Configure Static Routes
      vyos.vyos.vyos_config:
        config:
          - "set protocols static route {{ item.destination }} next-hop {{ item.next_hop }}"
      loop: "{{ static_routes }}"
      when: static_routes is defined
      # This task configures static routes on the Vyos router
      # using the values provided in the `static_routes` variable.

    # Task 20: Configure BGP
    - name: Configure BGP
      vyos.vyos.vyos_config:
        config:
          - "set protocols bgp {{ item.as_number }}"
          - "set protocols bgp {{ item.as_number }} neighbor {{ item.neighbor }} remote-as {{ item.remote_as }}"
          - "set protocols bgp {{ item.as_number }} neighbor {{ item.neighbor }} update-source {{ item.update_source }}"
          # Add more BGP configuration commands here if needed
      loop: "{{ bgp_config }}"
      when: bgp_config is defined and bgp_config | length > 0
      # This task configures BGP on the Vyos router
      # using the values provided in the `bgp_config` variable.

    # Task 21: Configure Webproxy
    - name: Configure Webproxy
      vyos.vyos.vyos_config:
        config:
          - "set service webproxy cache-size '{{ item.cache_size }}'"
          - "set service webproxy default-port '{{ item.default_port }}'"
          - "set service webproxy listen-address {{ item.listen_address }} disable-transparent"
          - "set service webproxy listen-address {{ item.listen_address }} port '{{ item.port }}'"
          - "set service webproxy url-filtering squidguard auto-update update-hour '{{ item.update_hour }}'"
          - "set service webproxy url-filtering squidguard default-action '{{ item.default_action }}'"
          - "set service webproxy url-filtering squidguard redirect-url '{{ item.redirect_url }}'"
      loop: "{{ webproxy_config }}"
      when: webproxy_config is defined and webproxy_config | length > 0
      # This task configures the web proxy on the Vyos router
      # using the values provided in the `webproxy_config` variable.

# End of playbook


vyos-variables.yml

---
# Defines hostnames
vyos_host_name:
  - vyos1
# The code for the hostname is set to loop, but it might change in the future.

# Defines SSH service
vyos_ssh_port:
  - port: 2222
# Defines the SSH port for the Vyos router.

# Defines Interfaces
vyos_l3_interfaces:
  - name: "eth0"
    address: "192.0.2.1/24"
  - name: "eth2"
    address: "192.0.2.2/24"
# Defines the L3 interfaces and their addresses on the Vyos router.
# Additional interfaces can be added below.

# Defines firewall rules
vyos_firewall_rule_sets:
  - name: "example_rule_set"
    default_action: "accept"
    description: "Example rule set"
    enable_default_log: true
    rules:
      - number: 10
        action: "accept"
        description: "Allow HTTP"
        destination:
          address: "192.0.2.0/24"
          port: "80"
        protocol: "tcp"
# Defines firewall rules and rule sets on the Vyos router.
# Additional rules can be added below.

# Defines VRRP
vrrp_groups:
  - group: alb
    authentication:
      password: 'vGS44ubG'
      type: 'plaintext-password'
    hello_source_address: '10.64.4.60'
    interface: 'eth2'
    peer_address: '10.64.4.61'
    priority: '249'
    virtual_address: '10.64.4.62/26'
    vrid: '11'
# Defines VRRP groups and their configurations on the Vyos router.
# Aditional VRRP groups can be added below

# Defines NAT
nat_rules:
  - rule_number: 110
    destination_address: '192.254.254.254/32'
    exclude: true
    outbound_interface: 'eth0'
    source_address: '192.168.99.2/32'

  - rule_number: 1000
    description: 'NAT Outgoing Internet access'
    outbound_interface: 'eth0'
    source_address: '10.0.0.0/8'
    translation_address: 'masquerade'

  - rule_number: 1100
    description: 'NAT Outgoing IPsec Traffic'
    outbound_interface: 'any'
    source_address: '10.0.0.0/8'
    translation_address: '172.16.0.0/22'
# Defines NAT rules and their configurations on the Vyos router.
# Additional NAT rules can be added below

# Defines DHCP
configure_dhcp: true

dhcp_failover:
  name: 'leptodon-okd-failover'
  remote: '10.65.0.2'
  source_address: '10.65.0.1'
  status: 'secondary'
# Configures DHCP failover settings on the Vyos router.

dhcp_listen_addresses:
  - '10.64.4.60'
  - '10.64.3.252'
# Sets DHCP listen addresses on the Vyos router.

dhcp_shared_network:
  name: 'leptodon'
  authoritative: true
  name_servers:
    - '10.64.4.252'
    - '10.64.4.254'
  subnet:
    address: '10.64.0.0/22'
    default_router: '10.64.4.253'
    enable_failover: true
    range:
      name: 'OKD'
      start: '10.64.0.1'
      stop: '10.64.2.255'
    static_mapping:
      name: 'leptodon-n7hyy3ox'
      ip_address: '10.64.0.1'
# Configures DHCP settings, shared network, and subnet on the Vyos router.

# Define Zone Policies
vyos_zones:
  - zone_name: "zone1"
    interfaces: "eth0"
    zone_action: "accept"
  - zone_name: "zone2"
    interfaces: "eth1"
    zone_action: "drop"
# Defines zone names, interfaces, and zone actions for zone policies on the Vyos router.
# Additional zones can be added below

# Configures Zone Policies
vyos_zone_policies:
  - name: "policy1"
    from_zones: "zone1"
    policy_action: "accept"
  - name: "policy2"
    from_zones: "zone2"
    policy_action: "drop"
# Configures zone policies with their names, source zones, and policy actions on the Vyos router.
# Additional Zone Policies can be added below 
dns_forwarding:
  - allow_from: '10.0.0.0/8'
    listen_address: '10.67.0.252'
# Configures DNS forwarding settings on the Vyos router.
# Additional DNS forwarding settings can be added below
# IPSEC VPN
ipsec_config:
  - name: "esp-group"
    options:
      - "compression: disable"
      - "lifetime: 1800"
      - "mode: tunnel"
      - "pfs: enable"
      - "proposal 1 encryption: aes256"
      - "proposal 1 hash: sha1"
  - name: "ike-group"
    options:
      - "close-action: none"
      - "ikev2-reauth: no"
      - "key-exchange: ikev1"
      - "lifetime: 3600"
      - "proposal 1 dh-group: 2"
      - "proposal 1 encryption: aes256"
      - "proposal 1 hash: sha1"
# Configures IPsec VPN settings on the Vyos router.
# Additional IPSEC configuration can be added below

# NTP Variables
ntp_servers:
  - 0.pool.ntp.org
  - 1.pool.ntp.org
  - 2.pool.ntp.org
# Configures NTP server addresses on the Vyos router.
# Additional NTP servers can be added below

# DNS Name servers for Vyos
name_servers:
  - 1.1.1.1
  - 8.8.8.8
# Configures DNS name servers on the Vyos router.
# Additional DNS name servers can be added below

static_routes:
  - destination: "0.0.0.0/0"
    next_hop: "152.228.148.254"
# Configures static routes on the Vyos router.
# Additional static routes can be added below

bgp_config:
  - as_number: 65000
    neighbor: 192.0.2.1
    remote_as: 65001
    update_source: eth0
  - as_number: 65000
    neighbor: 203.0.113.1
    remote_as: 65002
    update_source: eth1
# Configures BGP settings on the Vyos router.
# Additional BGP settings can be added below
webproxy_config:
  - cache_size: 100
    default_port: 3128
    listen_address: 10.65.0.1
    port: 3128
    update_hour: 1
    default_action: allow
    redirect_url: 
# Configures web proxy settings on the Vyos router.
# Add more webproxy configurations as needed
