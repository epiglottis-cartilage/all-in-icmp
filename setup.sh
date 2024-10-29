sudo nft add table ip filter

sudo nft 'add chain ip filter output { type filter hook output priority 0 ; }'
sudo nft 'add chain ip filter input { type filter hook input priority 0 ; }'

sudo nft add rule ip filter input ip saddr 10.161.0.0/16 ip protocol icmp queue num 444
sudo nft add rule ip filter output ip daddr 10.161.0.0/16 ip protocol tcp queue num 445
sudo nft add rule ip filter output ip daddr 10.161.0.0/16 ip protocol udp queue num 445
