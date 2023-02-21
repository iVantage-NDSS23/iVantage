# Introduction

This project provides source code of the NDSS'23 paper: [Your Router is My Prober: Measuring IPv6 Networks via ICMP Rate Limiting Side Channels](https://www.ndss-symposium.org/ndss-paper/your-router-is-my-prober-measuring-ipv6-networks-via-icmp-rate-limiting-side-channels/).

This project mainly consists of two tools:

* `iSAV`. A tool for Internet-scale active measurement of deploymenet of IPv6 inbound source address validation. To put it simply, it detects whether an IPv6 network has deployed filtering policy of incoming spoofed-source packets.

* `RVPing`. A tool to measure the reachability between two IPv6 nodes without directing controlling any of them.

# Preparation

## Discovering RVPs (Remote ''Vantage Points'')
As we introduced in our paper, discovering RVPs is a crucial preliminary. 
For ethical concerns, we don't provide code to discover RVPs, which requires sending numerous packets to specific networks.

You can implement a stateless scanner like many well-known tools (e.g., [ZMap](https://github.com/zmap/zmap)) to discover RVPs. 

`targetgen.c` may be a reference for you to generate your scanning targets to discover RVPs. 
You can read our paper for more details.

Organize your scanning result in the following format (`data/RVPs.txt` for reference):
```
# <Prefix> <AS Number>
<Periphery (RVP)> <ICMPv6 Type> <ICMPv6 Code> <Target>
<Periphery (RVP)> <ICMPv6 Type> <ICMPv6 Code> <Target>
...
# <Prefix> <AS Number>
<Periphery (RVP)> <ICMPv6 Type> <ICMPv6 Code> <Target>
<Periphery (RVP)> <ICMPv6 Type> <ICMPv6 Code> <Target>
<Periphery (RVP)> <ICMPv6 Type> <ICMPv6 Code> <Target>
...
```
Actually, the `<Periphery, Target>` is what we mentioned in our paper. By sending packets to `Target` (hereinafter referred to as *RVP Target*), we can receive specific ICMP messages sent from `Periphery`.


## Build
```
make
```

`GCC` or `clang` are required to compile the code (Default: clang).

## Configuration
Edit `config.ini`:

* `INTERFACE`: Name of your network interface, which will be used to send and sniff packets. You can easily get them by `ifconfig`. Example: `eth0`.

* `SRC_IPV6_ADDR`: Your IPv6 address. You can also easily find it in `ifconfig`. Example: `2001:1234:5678:9a00::1234`.

* `GATEWAY_MAC`: The MAC address of your gateway. The programs send packets at the link layers for better performance. Manually specifying your gateway MAC address prevents the program from parsing routes of netlink messages to get gateway MAC address, which usually brings accidental errors. You can get your gateway MAC address by simply capturing several packets in `tcpdump` (e.g., run `tcpdump -e -vvv`). Example: `00:1b:44:11:3a:b7`.
* Other Ad-hoc Parameters: We've discussed them detailedly in our paper, i.e., how many probe packets / noise packets to send.


## Note
The program requires *sending packets with spoofed source addresses*, **make sure that you are aware of potential ethical issues and also make sure that your ISP will not filter them**.



# iSAV
The provided program is used for an Internet-scale ISAV (inbound source address validation) measurements.

Put the RVPs you've discovered in `data/RVPs.txt`, then run `./isav`. The program will consistently measures the `rcv1`, `rcv2` and `rcv3` of each prefix, as we introduced in our paper.

We recommend redirecting the `stdout` of the program to a file, and then write scripts to analyze your measurement results.


# RVPing
Measuring the reachability between two IPv6 nodes without directing controlling any of them is a theoretically impossible measurement task. Therefore, the process of `RVPing` is quite complicated and there are still many aspects to improve.

Suppose you'd like to measure the reachability of two IPv6 Nodes *A* and *B*.

1. Find an RVP as close to either *A* or *B* as possible. We call it *Proxy RVP*, it usually shares same network with either of the targets. Since the loss of reachability is unlikely to occur between two close Internet nodes, the *Proxy RVP* can be a good representative of either *A* or *B*.

2. Measure the reachability between the *Proxy RVP* and the other node (*B* or *A*) using `RVPing`.

## Usage

```
rvping -a <RVP> -b <target (A or B)> -x <RVP target> [-r<specified RTT>] [-t<threshold>] [-n<measurement times>] 
```

* `RVP`: IPv6 address of the (proxy) RVP (remote ''vantage point'').
* `target`: The reachability between the `target` and (proxy) RVP is what you want to measure.
* `RVP target`: By sending packets to `RVP target`, you can receive ICMP error messages (mainly ICMP Destinaion Unreachable) from RVP. This is actually the way we discover RVPs.
* `specified RTT`: The measurement requires estimation of the RTT between the targets. Since the estimation can be difficult and our algorithm remains not so robust, we recommend you manully specify a estimated value of the RTT.
* `threshold`: The threshold to determine the reachability (unreachability). See paper for more details. (default: 0.6)
* `measurement times`: How many times the reachability measurements will be performed. (default: 3)



# Contact

Corresponding author of this paper: [he-lin@tsinghua.edu.cn](mailto:he-lin@tsinghua.edu.cn).





