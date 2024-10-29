# ALL in Icmp

## Intro

**Linux Only** and even WSL is **NOT** supposed. install your dual boot linux.

Using icmp to pass though firewall. that is wrapping everything in icmp packet.

## Usage

### Install

```bash
sudo apt install nftables
```

### Setup netfilters rules

```bash
sudo sh ./setup.sh
```

#### Compile and Run

```bash
cargo build --release
```

And run the executable file with sudo
