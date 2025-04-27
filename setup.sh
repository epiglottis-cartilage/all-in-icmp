#!/bin/bash

# Auto-detect if nftables is available
if command -v nft &> /dev/null; then
    echo "Using nftables..."
    
    # Create table and chains if they don't existsudo nft add table ip filter
    sudo nft 'add table ip filter'

    sudo nft 'add chain ip filter output { type filter hook output priority 0 ; }'
    sudo nft 'add chain ip filter input { type filter hook input priority 0 ; }'

    
    # Add rules for both subnets
    sudo nft add rule ip filter input ip saddr 10.161.0.0/16 ip protocol icmp queue num 444
    sudo nft add rule ip filter output ip daddr 10.161.0.0/16 ip protocol tcp queue num 444
    sudo nft add rule ip filter output ip daddr 10.161.0.0/16 ip protocol udp queue num 444

    sudo nft add rule ip filter input ip saddr 10.211.0.0/16 ip protocol icmp queue num 444
    sudo nft add rule ip filter output ip daddr 10.211.0.0/16 ip protocol tcp queue num 444
    sudo nft add rule ip filter output ip daddr 10.211.0.0/16 ip protocol udp queue num 444

else
    echo "Using iptables..."
    
    # Load kernel module for packet queue
    sudo modprobe ipt_run_queue 2>/dev/null
    
    # Add rules for both subnets
    sudo iptables -A INPUT -s 10.161.0.0/16 -p icmp -j RUN_QUEUE --queue-num 444
    sudo iptables -A OUTPUT -d 10.161.0.0/16 -p tcp -j RUN_QUEUE --queue-num 444
    sudo iptables -A OUTPUT -d 10.161.0.0/16 -p udp -j RUN_QUEUE --queue-num 444

    sudo iptables -A INPUT -s 10.211.0.0/16 -p icmp -j RUN_QUEUE --queue-num 444
    sudo iptables -A OUTPUT -d 10.211.0.0/16 -p tcp -j RUN_QUEUE --queue-num 444
    sudo iptables -A OUTPUT -d 10.211.0.0/16 -p udp -j RUN_QUEUE --queue-num 444

fi

echo "Rules added successfully!"