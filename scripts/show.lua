-- Copyright (c) Denatured Ethyl Crew
--
-- This file is part of GroinK.
--
-- GroinK is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- GroinK is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with GroinK.  If not, see <http://www.gnu.org/licenses/>.

-- show.lua
-- Packet dissector

local core = require("core")
local printf = core.printf
-- local ouidb = require("ouidb")

-- -- Print IEEE 802.11 radiotap header
-- local function print_ieee80211_radio(radio)
--    printf("IEEE 802.11 RADIOTAP version %d, pad %d, len %d, bitmap fields:\n", radio:version(), radio:pad(), radio:length())
--    for k,v in pairs(radio:fields()) do
--       if k == RadiotapBit.TSFT then
-- 	 printf("\ttsft: %lu\n", v)
--       elseif k == RadiotapBit.FLAGS then
-- 	 printf("\tflags:")
-- 	 if v.cfp then
-- 	    printf(" cfp")
-- 	 end
-- 	 if v.shortpre then
-- 	    print(" short-preamble")
-- 	 end
-- 	 if v.wep then
-- 	    printf(" wep")
-- 	 end
-- 	 if v.badfcs then
-- 	    printf(" bad-fcs")
-- 	 end
-- 	 if v._value == 0 then
-- 	    printf(" none")
-- 	 end
-- 	 printf(" (0x%02x)\n", v._value)
--       elseif k == RadiotapBit.RATE then
-- 	 printf("\trate: %2.1f Mb/s\n", v)
--       elseif k == RadiotapBit.CHANNEL then
-- 	 printf("\tchannel: freq %u MHz, flags 0x%04x, type", v.freq, v.flags._value)
-- 	 local f = v.flags
-- 	 -- Channel FHSS
-- 	 if f.fhss then
-- 	    print(" FHSS")
-- 	 end
-- 	 -- Channel A
-- 	 if f["5ghz"] and f.ofdm then
-- 	    printf(" 11a")
-- 	    if f.half then
-- 	       printf("/10MHz")
-- 	    elseif f.quarter then
-- 	       printf("/5MHz")
-- 	    end
-- 	 end
-- 	 -- Channel G or pureG
-- 	 if (f["2ghz"] and f.dyn) or (f["2ghz"] and f.ofdm) then
-- 	    printf(" 11g")
-- 	    if f.half then
-- 	       printf("10MHz")
-- 	    elseif f.quarter then
-- 	       printf("/5MHz")
-- 	    end
-- 	 elseif f["2ghz"] and f.cck then -- Channel B
-- 	    printf(" 11b")
-- 	 end
-- 	 -- Channel TURBO
-- 	 if f.turbo then
-- 	    printf(" turbo")
-- 	 end
-- 	 -- Channel HT/20
-- 	 if f["ht20"] then
-- 	    printf(" ht/20")
-- 	 end
-- 	 -- Channel HT/40-
-- 	 if f["ht40d"] then
-- 	    printf(" ht/40-")
-- 	 end
-- 	 -- Channel HT/40+
-- 	 if f["ht40u"] then
-- 	    printf(" ht/40+")
-- 	 end
-- 	 printf("\n")
--       elseif k == RadiotapBit.FHSS then
-- 	 printf("\tfhset: %d, fhpat: %d\n", v.fhset, v.fhpat)
--       elseif k == RadiotapBit.DBM_ANTSIGNAL then
-- 	 printf("\tsingal: %d dB\n", v)
--       elseif k == RadiotapBit.DBM_ANTNOISE then
-- 	 printf("\tnoise: %d dB\n", v)
--       elseif k == RadiotapBit.LOCK_QUALITY then
-- 	 printf("\tlock quality: %u sq\n", v)
--       elseif k == RadiotapBit.TX_ATTENUATION then
-- 	 printf("\ttx attenuation: %d\n", v)
--       elseif k == RadiotapBit.DB_TX_ATTENUATION then
-- 	 printf("\ttx attenuation: %d dB\n")
--       elseif k == RadiotapBit.DBM_TX_POWER then
-- 	 printf("\ttx power: %d dBm\n", v)
--       elseif k == RadiotapBit.ANTENNA then
-- 	 printf("\tantenna: %u\n", v)
--       elseif k == RadiotapBit.DB_ANTSIGNAL then
-- 	 printf("\tsignal: %d dB\n", v)
--       elseif k == RadiotapBit.DB_ANTNOISE then
-- 	 printf("\tnoise: %d dB\n", v)
--       elseif k == RadiotapBit.RX_FLAGS then
-- 	 printf("\trx flags: 0x%04x\n", v._value)
--       elseif k == RadiotapBit.TX_FLAGS then
-- 	 printf("\ttx flags: 0x%04x\n", v._value)
--       elseif k == RadiotapBit.RTS_RETRIES then
-- 	 printf("\trts restries: %u\n", v)
--       elseif k == RadiotapBit.DATA_RETRIES then
-- 	 printf("\tdata restries: %u\n", v)
--       end
--    end
-- end

-- -- Print PPPoE Discovery header
-- local function print_pppoe(p)

--    local pppoe = p:get_header(Proto.PPPOE)

--    if pppoe:code() == PPPoE.CODE_SESSION then
--       return
--    end

--    printf("PPPoED ")

--    if pppoe:code() == PPPoE.CODE_DISCOVER_PADI then
--       printf("PADI packet, ")
--    elseif pppoe:code() == PPPoE.CODE_DISCOVER_PADO then
--       printf("PADO packet, ")
--    elseif pppoe:code() == PPPoE.CODE_DISCOVER_PADR then
--       printf("PADR packet, ")
--    elseif pppoe:code() == PPPoE.CODE_DISCOVER_PADT then
--       printf("PADT packet, ")
--    elseif pppoe:code() == PPPoE.CODE_DISCOVER_PADS then
--       printf("PADS packet, ")
--    end

--    printf("version %d, type %d, code 0x%02x, session id 0x%0002x, payload length %d",
-- 	  pppoe:version(), pppoe:type(), pppoe:code(), pppoe:session(), 
-- 	  pppoe:payload_length())

--    local tags = pppoe:tags()
--    if tags ~= nil then
--       printf(", tags:\n")
--       for k,v in pairs(tags) do
--    	 printf("\t0x%x : %s\n", k, v)
--       end
--    else
--       printf("\n")
--    end
-- end

-- -- Print ARP/RARP packet
-- local function print_arp(p)

--    local arp = p:get_header(Proto.ARP)

--    printf("ARP ")
--    local arpe = arp:arp_ethip()

--    if arpe ~= nil then
--       if arp:opcode() == ARP.OP_REQUEST then
-- 	 printf("Request who-as %s tell %s", arpe.tpa, arpe.spa)
--       elseif arp:opcode() == ARP.OP_REPLY then
-- 	 printf("Reply %s is-at %s", arpe.spa, arpe.sha)
-- 	 -- get company name from oui
-- 	 local company = ouidb.oui_from_addr(arpe.sha)
-- 	 if company ~= nil then
-- 	    printf(" (%s)", company)
-- 	 end
--       elseif arp:opcode() == ARP.OP_REQUEST then
-- 	 printf("Reverse Request who-is %s tell %s", arpe.tha, arpe.sha)
--       elseif arp:opcode() == ARP.OP_RREPLY then
-- 	 printf("Reverse Reply %s at %s", arpe.tha, arpe.tpa)
--       elseif arp:opcode() == ARP.OP_InREQUEST then
-- 	 printf("Inverse Request who-is %s tell %s", arpe.tha, arpe.sha)
--       elseif arp:opcode() == ARP.OP_InREPLY then
-- 	 printf("Inverse Reply %s at %s", arpe.tha, arpe.tpa)
--       elseif arp:opcode() == ARP.OP_NAK then
-- 	 printf("NACK Reply")
--       end
--    else
--       if arp:opcode() == ARP.OP_REQUEST then
-- 	 printf("Request")
--       elseif arp:opcode() == ARP.OP_REPLY then
-- 	 printf("Reply")
--       elseif arp:opcode() == ARP.OP_REQUEST then
-- 	 printf("Reverse Request")
--       elseif arp:opcode() == ARP.OP_RREPLY then
-- 	 printf("Reverse Reply")
--       elseif arp:opcode() == ARP.OP_InREQUEST then
-- 	 printf("Inverse Request")
--       elseif arp:opcode() == ARP.OP_InREPLY then
-- 	 printf("Inverse Reply")
--       elseif arp:opcode() == ARP.OP_NAK then
-- 	 printf("NACK Reply")
--       end
--    end
--    printf("\n")
-- end

-- -- Print tcp packet
-- local function print_tcp(p)
--    local tcp = p:get_header(Proto.TCP)
--    local fcount = 0  -- Flags counter

--    if p:contains_header(Proto.IPV6) then
--       printf("TCP [%s]:%d > [%s]:%d flags [", p:net_srcaddr(), tcp:src_port(), 
-- 	  p:net_dstaddr(), tcp:dst_port())
--    else
--       printf("TCP %s:%d > %s:%d flags [", p:net_srcaddr(), tcp:src_port(), 
-- 	     p:net_dstaddr(), tcp:dst_port())
--    end

--    local flags = tcp:flags()

--    if flags.fin then
--       printf("F")
--       fcount = fcount + 1
--    end

--    if flags.syn then
--       printf("S")
--       fcount = fcount + 1
--    end

--    if flags.rst then
--       printf("R")
--       fcount = fcount + 1
--    end

--    if flags.push then
--       printf("P")
--       fcount = fcount + 1
--    end

--    if flags.ack then
--       printf("A")
--       fcount = fcount + 1
--    end

--    if flags.urg then
--       printf("U")
--       fcount = fcount + 1
--    end

--    -- If there aren't flags print "none"
--    if fcount == 0 then
--       printf("none")
--    end

--    printf("] seq %d, ack %d, win %d, cksum 0x%x\n", tcp:seq(), tcp:ack(), 
-- 	  tcp:window(), tcp:cksum())
-- end

-- -- Print udp packet
-- local function print_udp(p)
--    local udp = p:get_header(Proto.UDP)

--    if p:contains_header(Proto.IPV6) then
--       printf("UDP [%s]:%d > [%s]:%d cksum 0x%x\n", p:net_srcaddr(), udp:src_port(), 
-- 	  p:net_dstaddr(), udp:dst_port(), udp:cksum())
--       else
-- 	 printf("UDP %s:%d > %s:%d cksum 0x%x\n", p:net_srcaddr(), udp:src_port(), 
-- 		p:net_dstaddr(), udp:dst_port(), udp:cksum())
--       end
-- end

-- -- Print icmp header
-- local function print_icmp(p)
--    local icmp = p:get_header(Proto.ICMP)
--    local body = icmp:body()
   
--    printf("ICMP %s > %s ", p:net_srcaddr(), p:net_dstaddr())
   
--    if icmp:type() == ICMP.TYPE_ECHO_REQUEST then
--       printf("echo request")
--    elseif icmp:type() == ICMP.TYPE_ECHO_REPLY then
--       printf("echo reply")
--    elseif icmp:type() == ICMP.TYPE_REDIRECT then
--       printf("redirect ")
--       if body ~= nil then
-- 	 if icmp:code() == ICMP.CODE_REDIR_NET then
-- 	    printf("to net %s ", body.gw_addr)
-- 	 elseif icmp:code() == ICMP.CODE_REDIR_HOST then
-- 	    printf("to host %s ", body.gw_addr)
-- 	 else
-- 	    printf("to %s ", body.gw_addr)
-- 	 end
--       end
--    elseif icmp:type() == ICMP.TYPE_DEST_UNREACH then
--       if icmp:code() == ICMP.CODE_UNREACH_NET then
-- 	 printf("network unreachable")
--       elseif icmp:code() == ICMP.CODE_UNREACH_HOST then
-- 	 printf("host unreachable")
--       elseif icmp:code() == ICMP.CODE_UNREACH_PROTO then
-- 	 printf("protocol unreachable")
--       elseif icmp:code() == ICMP.CODE_UNREACH_PORT then
-- 	 printf("port unreachable")
--       elseif icmp:code() == ICMP.CODE_UNREACH_FRAG_NEEDED then
-- 	 printf("fragmentation needed")
--       else
-- 	 printf("destination unreachable")
--       end
--    elseif icmp:type() == ICMP.TYPE_TIME_EXCEEDED then
--       printf("time exceeded ")
--    end
--    printf("\n")
-- end

-- -- Print icmp6 header
-- local function print_icmp6(p)
--    local icmp = p:get_header(Proto.ICMP6)
--    local body = icmp:body()
   
--    printf("ICMPv6 %s > %s ", p:net_srcaddr(), p:net_dstaddr())
   
--    if icmp:type() == ICMP6.TYPE_ECHO_REQUEST then
--       printf("echo request")
--    elseif icmp:type() == ICMP6.TYPE_ECHO_REPLY then
--       printf("echo reply")
--    elseif icmp:type() == ICMP6.TYPE_DEST_UNREACH then
--       if icmp:code() == ICMP6.CODE_UNREACH_NO_ROUTE then
--    	 printf("no route to destination")
--       elseif icmp:code() == ICMP6.CODE_UNREACH_ADM_PROIB then
--    	 printf("communication with destination administratively prohibited")
--       elseif icmp:code() == ICMP6.CODE_UNREACH_ADDR then
--    	 printf("address unreachable")
--       elseif icmp:code() == ICMP6.CODE_UNREACH_PORT then
--    	 printf("port unreachable")
--       end
--    elseif icmp:type() == ICMP6.TYPE_TIME_EXCEEDED then
--       printf("time exceeded")
--       if icmp:code() == ICMP6.CODE_TEXC_HOP_LIMIT then
-- 	 printf(", hop limit exceeded in transit")
--       elseif icmp:code() == ICMP6.CODE_TEXC_FRAG_REASSEMBLY then
-- 	 printf(", fragment reassembly time exceeded")
--       end
--    elseif icmp:type() == ICMP6.TYPE_PARAM_PROB then
--       if icmp:code() == ICMP6.CODE_PARAM_PROB_ERR_HDR_FIELD then
-- 	 printf("erroneous header field")
--       elseif icmp:code() == ICMP6.CODE_PARAM_PROB_UNREC_NXT_HDR then
-- 	 printf("unrecognized Next Header type")
--       elseif icmp:code() == ICMP6.CODE_PARAM_PROB_UNREC_OPT then
-- 	 printf("unrecognized IPv6 option")
--       end
--    elseif icmp:type() == ICMP6.TYPE_PKT_TOO_BIG then
--       printf("packet too big, mtu: %d", body.mtu)
--    elseif icmp:type() == ICMP6.TYPE_ROUTER_SOL then
--       printf("router solicitation")
--    elseif icmp:type() == ICMP6.TYPE_ROUTER_ADV then
--       printf("router advertisement")
--    elseif icmp:type() == ICMP6.TYPE_NEIGH_SOL then
--       printf("neighbor solicitation")
--    elseif icmp:type() == ICMP6.TYPE_NEIGH_ADV then
--       printf("neighbor advertisement")
--    elseif icmp:type() == ICMP6.TYPE_REDIRECT then
--       printf("redirect")
--    elseif icmp:type() == ICMP6.TYPE_ROUTER_RENUMBERING then
--       printf("router renumbering")
--    end
--    printf("\n")
-- end

-- function proc_pkt(p)
--    if p:contains_header(Proto.ARP) then
--       print_arp(p)
--    elseif p:contains_header(Proto.PPPOE) then
--       print_pppoe(p)
--    elseif p:contains_header(Proto.ICMP) then
--       print_icmp(p)
--    elseif p:contains_header(Proto.ICMP6) then
--       print_icmp6(p)
--    elseif p:contains_header(Proto.TCP) then
--       print_tcp(p)
--    elseif p:contains_header(Proto.UDP) then
--       print_udp(p)
--    end
-- end

function proc_pkt(p)
   if p:tostring():len() > 0 then
      printf("%s\n", p:tostring())
   else
      printf("Unknown packet\n");
   end
end
