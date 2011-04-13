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
local ouidb = require("ouidb")
local dump = require("dump")

-- Print IEEE 802.11 radiotap header
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

-- Print PPPoE header
-- local function print_pppoe(pppoe)
--    printf("PPPoE")

--    if pppoe:code() == PppoeCode.SESSION then
--       printf("S Session data, ")
--    elseif pppoe:code() == PppoeCode.DISCOVER_PADI then
--       printf("D PADI packet, ")
--    elseif pppoe:code() == PppoeCode.DISCOVER_PADO then
--       printf("D PADO packet, ")
--    elseif pppoe:code() == PppoeCode.DISCOVER_PADR then
--       printf("D PADR packet, ")
--    elseif pppoe:code() == PppoeCode.DISCOVER_PADT then
--       printf("D PADT packet, ")
--    elseif pppoe:code() == PppoeCode.DISCOVER_PADS then
--       printf("D PADS packet, ")
--    end

--    printf("version %d, type %d, code 0x%02x, session id 0x%0002x, payload length %d\n", pppoe:version(), pppoe:type(),
-- 	  pppoe:code(), pppoe:session(), pppoe:payload_length())

--    -- local tags = pppoe:tags()
--    -- if tags ~= nil then
--    --    for k,v in pairs(tags) do
--    -- 	 printf("\t%x : %s\n", k, v)
--    --    end
--    -- end
-- end

-- Print ARP/RARP packet
-- local function print_arp(p)

--    local arp = p:get_header(Proto.ARP)

--    printf("ARP ")
--    local arpe = arp:arp_ether_info()

--    if arpe ~= nil then
--       if arp:opcode() == ArpOpcode.REQUEST then
-- 	 printf("Request who-as %s tell %s", arpe.tpa, arpe.spa)
--       elseif arp:opcode() == ArpOpcode.REPLY then
-- 	 printf("Reply %s is-at %s", arpe.spa, arpe.sha)
-- 	 -- get company name from oui
-- 	 local company = ouidb.oui_from_addr(arpe.sha)
-- 	 if company ~= nil then
-- 	    printf(" (%s)", company)
-- 	 end
--       elseif arp:opcode() == ArpOpcode.REQUEST then
-- 	 printf("Reverse Request who-is %s tell %s", arpe.tha, arpe.sha)
--       elseif arp:opcode() == ArpOpcode.RREPLY then
-- 	 printf("Reverse Reply %s at %s", arpe.tha, arpe.tpa)
--       elseif arp:opcode() == ArpOpcode.InREQUEST then
-- 	 printf("Inverse Request who-is %s tell %s", arpe.tha, arpe.sha)
--       elseif arp:opcode() == ArpOpcode.InREPLY then
-- 	 printf("Inverse Reply %s at %s", arpe.tha, arpe.tpa)
--       elseif arp:opcode() == ArpOpcode.NAK then
-- 	 printf("NACK Reply")
--       end
--    else
--       if arp:opcode() == ArpOpcode.REQUEST then
-- 	 printf("Request")
--       elseif arp:opcode() == ArpOpcode.REPLY then
-- 	 printf("Reply")
--       elseif arp:opcode() == ArpOpcode.REQUEST then
-- 	 printf("Reverse Request")
--       elseif arp:opcode() == ArpOpcode.RREPLY then
-- 	 printf("Reverse Reply")
--       elseif arp:opcode() == ArpOpcode.InREQUEST then
-- 	 printf("Inverse Request")
--       elseif arp:opcode() == ArpOpcode.InREPLY then
-- 	 printf("Inverse Reply")
--       elseif arp:opcode() == ArpOpcode.NAK then
-- 	 printf("NACK Reply")
--       end
--    end
--    printf("\n")
-- end

-- Print tcp packet
-- local function print_tcp(p)
--    local tcp = p:get_header(Proto.TCP)
--    local fcount = 0  -- Flags counter

--    printf("TCP %s:%d > %s:%d flags [", p:src_netaddr(), tcp:src_port(), p:dst_netaddr(), tcp:dst_port())
--    if tcp:flag_fin() then
--       printf("F")
--       fcount = fcount + 1
--    end

--    if tcp:flag_syn() then
--       printf("S")
--       fcount = fcount + 1
--    end

--    if tcp:flag_rst() then
--       printf("R")
--       fcount = fcount + 1
--    end

--    if tcp:flag_push() then
--       printf("P")
--       fcount = fcount + 1
--    end

--    if tcp:flag_ack() then
--       printf("A")
--       fcount = fcount + 1
--    end

--    if tcp:flag_urg() then
--       printf("U")
--       fcount = fcount + 1
--    end

--    -- If there aren't flags print "none"
--    if fcount == 0 then
--       printf("none")
--    end

--    printf("]\n")
-- end

-- Print udp packet
-- local function print_udp(p)
--    local udp = p:get_header(Proto.UDP)
--    printf("UDP %s:%d > %s:%d\n", p:src_netaddr(), udp:src_port(), p:dst_netaddr(), udp:dst_port())
-- end

-- Print icmp header
-- local function print_icmp(p)
--    local icmp = p:get_header(Proto.ICMP)
--    local body = icmp:body()
   
--    printf("ICMP %s > %s ", p:src_netaddr(), p:dst_netaddr())
   
--    if icmp:type() == IcmpType.ECHO then
--       printf("echo request")
--    elseif icmp:type() == IcmpType.ECHO_REPLY then
--       printf("echo reply")
--    elseif icmp:type() == IcmpType.REDIRECT then
--       printf("redirect ")
--       if body ~= nil then
-- 	 if icmp:code() == IcmpCode.REDIRECT_NET then
-- 	    printf("to net %s ", body.gw_addr)
-- 	 elseif icmp:code() == Icmp4.REDIRECT_HOST then
-- 	    printf("to host %s ", body.gw_addr)
-- 	 else
-- 	    printf("to %s ", body.gw_addr)
-- 	 end
--       end
--    elseif icmp:type() == IcmpType.DEST_UNREACH then
--       if icmp:code() == IcmpCode.UNREACH_NET then
-- 	 printf("network unreachable")
--       elseif icmp:code() == IcmpCode.UNREACH_HOST then
-- 	 printf("host unreachable")
--       elseif icmp:code() == IcmpCode.UNREACH_PROTO then
-- 	 printf("protocol unreachable")
--       elseif icmp:code() == IcmpCode.UNREACH_PORT then
-- 	 printf("port unreachable")
--       elseif icmp:code() == IcmpCode.FRAG_NEEDED then
-- 	 printf("fragmentation needed")
--       else
-- 	 printf("destination unreachable")
--       end
--    elseif icmp:type() == IcmpType.TIME_EXCEEDED then
--       printf("time exceeded ")
--    end
--    printf("\n")
-- end

-- Print raw header
-- local function print_raw(raw)
--    dump.hex_ascii(raw:data(), raw:length())
-- end

function proc_pkt(p)
   -- if p:contains_header(Proto.ARP) then
   --    print_arp(p)
   -- elseif p:contains_header(Proto.ICMP) then
   --    print_icmp(p)
   -- elseif p:contains_header(Proto.TCP) then
   --    print_tcp(p)
   -- elseif p:contains_header(Proto.UDP) then
   --    print_udp(p)
   -- end
end
