# pcap2ps
从抓包文件（tcpdump or wireshark）中提取国标流

仅是个demo，代码不规范，懒得改。但是功能是好用的， 我日常工作中常用

window也是可以用的

注意：由于pcap中的数据不经过ip层，所以基于tcp协议传输时，pcap中的数据有可能发生乱序

如果发生了乱序， 程序将不再提取，一般已经提取出来的部分足够我们用来分析了

使用方法 ： 

1,gcc pcap2ps.c

2, ./a.out test.pcap（pcap文件） test.ps（生成的国标流文件） 4000（接收rtp数据的端口）

./a.out test.pcap test.ps 4000
