#!/bin/bash

# Auto-detect if nftables is available
if command -v nft &> /dev/null; then
    echo "Using nftables..."
    
    # Delete rules for both subnetssudo nft delete rule ip filter input handle 0
    sudo nft delete rule ip filter output handle 0
    sudo nft delete chain ip filter input
    sudo nft delete chain ip filter output
    sudo nft delete table ip filter
    
    # Note: This assumes the rules are the last ones added. For precise deletion, track rule handles.

else
    echo "Using iptables..."
    
    # Delete rules for both subnets
    sudo iptables -D INPUT -s 10.161.0.0/16 -p icmp -j RUN_QUEUE --queue-num 444
    sudo iptables -D OUTPUT -d 10.161.0.0/16 -p tcp -j RUN_QUEUE --queue-num 444
    sudo iptables -D OUTPUT -d 10.161.0.0/16 -p udp -j RUN_QUEUE --queue-num 444

    sudo iptables -D INPUT -s 10.211.0.0/16 -p icmp -j RUN_QUEUE --queue-num 444
    sudo iptables -D OUTPUT -d 10.211.0.0/16 -p tcp -j RUN_QUEUE --queue-num 444
    sudo iptables -D OUTPUT -d 10.211.0.0/16 -p udp -j RUN_QUEUE --queue-num 444

fi

echo "Rules removed successfully!"