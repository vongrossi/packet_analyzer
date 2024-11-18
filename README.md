# packet_analyzer

```bash
gcc -o packet_analyzer packet_analyzer.c
```

```bash
./packet_analyzer bytes.txt
```

```bash
sudo tcpdump -i <interface> -w capture.pcap
```

```bash
sudo tcpdump -xx -r capture.pcap > bytes.txt
```

```bash
sudo tcpdump -xx -r capture.pcap 'ip host 192.168.0.10 and tcp port 80' > bytes.txt
```


