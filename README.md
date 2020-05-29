#Extract network features from pcap files using python pyshark and storing them in SQL LITE DB



**Features**
1) session_ttl_min : return min ttl value. ttl is extracted using pkt.ip.ttl as ttl is part of ip header
2) session_packets : returns total number of packets in that session.
3) session_packet_size_avg : returns avg length of packets in that session . Calculate using pkt.length (part of frame) of each packet added divided by total packets (using feature 2)
4) session_tcp_analysis_retransmission : returns number of retransmission packets per session. retramission is property of tcp analysis thus is calculated by finding number of packets with "analysis_retransmission" in pkt.tcp.field_names
5) session_tcp_analysis_duplicate_ack  : returns number of duplicate ack packets per session. duplicate ack is also property of tcp analysis thus is calculated by finding number of packets with "analysis_duplicate_ack" in pkt.tcp.field_names


**Files used**
1) iot1_new.pcap : number of packets 5000 :329 session
2) iot2_new.pcap : number of packets 5000 : 275 session

**Libraries used** 
numpy, pandas, pyshark (tshark's python wrapper), splite3( for sql lite db), statistics, os, nest_asyncia 

**Functions**
1) create_connection(db_file) : to create a db
2) create_table(conn, table) : to create db table
3) create_entry(conn,task) : to insert data values in db



