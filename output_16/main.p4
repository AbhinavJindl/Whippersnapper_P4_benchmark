#include <core.p4>
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header header_0_t {
	bit<16> field_0;
}

header header_0_0_t {
	bit<16> field_0;
}

header header_0_0_0_t {
	bit<16> field_0;
}

header header_0_0_1_t {
	bit<16> field_0;
}

header header_0_0_2_t {
	bit<16> field_0;
}

header header_0_1_t {
	bit<16> field_0;
}

header header_0_1_0_t {
	bit<16> field_0;
}

header header_0_1_1_t {
	bit<16> field_0;
}

header header_0_1_2_t {
	bit<16> field_0;
}

header header_0_2_t {
	bit<16> field_0;
}

header header_0_2_0_t {
	bit<16> field_0;
}

header header_0_2_1_t {
	bit<16> field_0;
}

header header_0_2_2_t {
	bit<16> field_0;
}

header header_1_t {
	bit<16> field_0;
}

header header_1_0_t {
	bit<16> field_0;
}

header header_1_0_0_t {
	bit<16> field_0;
}

header header_1_0_1_t {
	bit<16> field_0;
}

header header_1_0_2_t {
	bit<16> field_0;
}

header header_1_1_t {
	bit<16> field_0;
}

header header_1_1_0_t {
	bit<16> field_0;
}

header header_1_1_1_t {
	bit<16> field_0;
}

header header_1_1_2_t {
	bit<16> field_0;
}

header header_1_2_t {
	bit<16> field_0;
}

header header_1_2_0_t {
	bit<16> field_0;
}

header header_1_2_1_t {
	bit<16> field_0;
}

header header_1_2_2_t {
	bit<16> field_0;
}

header header_2_t {
	bit<16> field_0;
}

header header_2_0_t {
	bit<16> field_0;
}

header header_2_0_0_t {
	bit<16> field_0;
}

header header_2_0_1_t {
	bit<16> field_0;
}

header header_2_0_2_t {
	bit<16> field_0;
}

header header_2_1_t {
	bit<16> field_0;
}

header header_2_1_0_t {
	bit<16> field_0;
}

header header_2_1_1_t {
	bit<16> field_0;
}

header header_2_1_2_t {
	bit<16> field_0;
}

header header_2_2_t {
	bit<16> field_0;
}

header header_2_2_0_t {
	bit<16> field_0;
}

header header_2_2_1_t {
	bit<16> field_0;
}

header header_2_2_2_t {
	bit<16> field_0;
}

header ptp_t {
    bit<4> transportSpecific;
    bit<4> messageType;
    bit<4> reserved;
    bit<4> versionPTP;
    bit<16> messageLength;
    bit<8> domainNumber;
    bit<8> reserved2;
    bit<16> flags;
    bit<64> correction;
    bit<32> reserved3;
    bit<80> sourcePortIdentity;
    bit<16> sequenceId;
    bit<8> PTPcontrol;
    bit<8> logMessagePeriod;
    bit<80> originTimestamp;
}

struct metadata{
}

struct headers{
	@name(".ethernet")
	ethernet_t ethernet;
	@name(".header_0")
	header_0_t header_0;
	@name(".header_0_0")
	header_0_0_t header_0_0;
	@name(".header_0_0_0")
	header_0_0_0_t header_0_0_0;
	@name(".header_0_0_1")
	header_0_0_1_t header_0_0_1;
	@name(".header_0_0_2")
	header_0_0_2_t header_0_0_2;
	@name(".header_0_1")
	header_0_1_t header_0_1;
	@name(".header_0_1_0")
	header_0_1_0_t header_0_1_0;
	@name(".header_0_1_1")
	header_0_1_1_t header_0_1_1;
	@name(".header_0_1_2")
	header_0_1_2_t header_0_1_2;
	@name(".header_0_2")
	header_0_2_t header_0_2;
	@name(".header_0_2_0")
	header_0_2_0_t header_0_2_0;
	@name(".header_0_2_1")
	header_0_2_1_t header_0_2_1;
	@name(".header_0_2_2")
	header_0_2_2_t header_0_2_2;
	@name(".header_1")
	header_1_t header_1;
	@name(".header_1_0")
	header_1_0_t header_1_0;
	@name(".header_1_0_0")
	header_1_0_0_t header_1_0_0;
	@name(".header_1_0_1")
	header_1_0_1_t header_1_0_1;
	@name(".header_1_0_2")
	header_1_0_2_t header_1_0_2;
	@name(".header_1_1")
	header_1_1_t header_1_1;
	@name(".header_1_1_0")
	header_1_1_0_t header_1_1_0;
	@name(".header_1_1_1")
	header_1_1_1_t header_1_1_1;
	@name(".header_1_1_2")
	header_1_1_2_t header_1_1_2;
	@name(".header_1_2")
	header_1_2_t header_1_2;
	@name(".header_1_2_0")
	header_1_2_0_t header_1_2_0;
	@name(".header_1_2_1")
	header_1_2_1_t header_1_2_1;
	@name(".header_1_2_2")
	header_1_2_2_t header_1_2_2;
	@name(".header_2")
	header_2_t header_2;
	@name(".header_2_0")
	header_2_0_t header_2_0;
	@name(".header_2_0_0")
	header_2_0_0_t header_2_0_0;
	@name(".header_2_0_1")
	header_2_0_1_t header_2_0_1;
	@name(".header_2_0_2")
	header_2_0_2_t header_2_0_2;
	@name(".header_2_1")
	header_2_1_t header_2_1;
	@name(".header_2_1_0")
	header_2_1_0_t header_2_1_0;
	@name(".header_2_1_1")
	header_2_1_1_t header_2_1_1;
	@name(".header_2_1_2")
	header_2_1_2_t header_2_1_2;
	@name(".header_2_2")
	header_2_2_t header_2_2;
	@name(".header_2_2_0")
	header_2_2_0_t header_2_2_0;
	@name(".header_2_2_1")
	header_2_2_1_t header_2_2_1;
	@name(".header_2_2_2")
	header_2_2_2_t header_2_2_2;
	@name(".ptp")
	ptp_t ptp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
	@name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            	16w0x88f7: parse_ptp;
				default: accept;

        }
    }
	@name(".parser_header_0") state parser_header_0 {
        packet.extract(hdr.header_0);
        transition select(hdr.header_0.field_0) {
            	16w0    : parser_header_0_0;
	16w1    : parser_header_0_1;
	16w2    : parser_header_0_2;
				default: accept;

        }
    }
	@name(".parser_header_0_0") state parser_header_0_0 {
        packet.extract(hdr.header_0_0);
        transition select(hdr.header_0_0.field_0) {
            	16w0    : parser_header_0_0_0;
	16w1    : parser_header_0_0_1;
	16w2    : parser_header_0_0_2;
				default: accept;

        }
    }
	@name(".parser_header_0_0_0") state parser_header_0_0_0 {
        packet.extract(hdr.header_0_0_0);
        transition select(hdr.header_0_0_0.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_0_0_1") state parser_header_0_0_1 {
        packet.extract(hdr.header_0_0_1);
        transition select(hdr.header_0_0_1.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_0_0_2") state parser_header_0_0_2 {
        packet.extract(hdr.header_0_0_2);
        transition select(hdr.header_0_0_2.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_0_1") state parser_header_0_1 {
        packet.extract(hdr.header_0_1);
        transition select(hdr.header_0_1.field_0) {
            	16w0    : parser_header_0_1_0;
	16w1    : parser_header_0_1_1;
	16w2    : parser_header_0_1_2;
				default: accept;

        }
    }
	@name(".parser_header_0_1_0") state parser_header_0_1_0 {
        packet.extract(hdr.header_0_1_0);
        transition select(hdr.header_0_1_0.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_0_1_1") state parser_header_0_1_1 {
        packet.extract(hdr.header_0_1_1);
        transition select(hdr.header_0_1_1.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_0_1_2") state parser_header_0_1_2 {
        packet.extract(hdr.header_0_1_2);
        transition select(hdr.header_0_1_2.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_0_2") state parser_header_0_2 {
        packet.extract(hdr.header_0_2);
        transition select(hdr.header_0_2.field_0) {
            	16w0    : parser_header_0_2_0;
	16w1    : parser_header_0_2_1;
	16w2    : parser_header_0_2_2;
				default: accept;

        }
    }
	@name(".parser_header_0_2_0") state parser_header_0_2_0 {
        packet.extract(hdr.header_0_2_0);
        transition select(hdr.header_0_2_0.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_0_2_1") state parser_header_0_2_1 {
        packet.extract(hdr.header_0_2_1);
        transition select(hdr.header_0_2_1.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_0_2_2") state parser_header_0_2_2 {
        packet.extract(hdr.header_0_2_2);
        transition select(hdr.header_0_2_2.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_1") state parser_header_1 {
        packet.extract(hdr.header_1);
        transition select(hdr.header_1.field_0) {
            	16w0    : parser_header_1_0;
	16w1    : parser_header_1_1;
	16w2    : parser_header_1_2;
				default: accept;

        }
    }
	@name(".parser_header_1_0") state parser_header_1_0 {
        packet.extract(hdr.header_1_0);
        transition select(hdr.header_1_0.field_0) {
            	16w0    : parser_header_1_0_0;
	16w1    : parser_header_1_0_1;
	16w2    : parser_header_1_0_2;
				default: accept;

        }
    }
	@name(".parser_header_1_0_0") state parser_header_1_0_0 {
        packet.extract(hdr.header_1_0_0);
        transition select(hdr.header_1_0_0.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_1_0_1") state parser_header_1_0_1 {
        packet.extract(hdr.header_1_0_1);
        transition select(hdr.header_1_0_1.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_1_0_2") state parser_header_1_0_2 {
        packet.extract(hdr.header_1_0_2);
        transition select(hdr.header_1_0_2.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_1_1") state parser_header_1_1 {
        packet.extract(hdr.header_1_1);
        transition select(hdr.header_1_1.field_0) {
            	16w0    : parser_header_1_1_0;
	16w1    : parser_header_1_1_1;
	16w2    : parser_header_1_1_2;
				default: accept;

        }
    }
	@name(".parser_header_1_1_0") state parser_header_1_1_0 {
        packet.extract(hdr.header_1_1_0);
        transition select(hdr.header_1_1_0.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_1_1_1") state parser_header_1_1_1 {
        packet.extract(hdr.header_1_1_1);
        transition select(hdr.header_1_1_1.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_1_1_2") state parser_header_1_1_2 {
        packet.extract(hdr.header_1_1_2);
        transition select(hdr.header_1_1_2.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_1_2") state parser_header_1_2 {
        packet.extract(hdr.header_1_2);
        transition select(hdr.header_1_2.field_0) {
            	16w0    : parser_header_1_2_0;
	16w1    : parser_header_1_2_1;
	16w2    : parser_header_1_2_2;
				default: accept;

        }
    }
	@name(".parser_header_1_2_0") state parser_header_1_2_0 {
        packet.extract(hdr.header_1_2_0);
        transition select(hdr.header_1_2_0.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_1_2_1") state parser_header_1_2_1 {
        packet.extract(hdr.header_1_2_1);
        transition select(hdr.header_1_2_1.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_1_2_2") state parser_header_1_2_2 {
        packet.extract(hdr.header_1_2_2);
        transition select(hdr.header_1_2_2.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_2") state parser_header_2 {
        packet.extract(hdr.header_2);
        transition select(hdr.header_2.field_0) {
            	16w0    : parser_header_2_0;
	16w1    : parser_header_2_1;
	16w2    : parser_header_2_2;
				default: accept;

        }
    }
	@name(".parser_header_2_0") state parser_header_2_0 {
        packet.extract(hdr.header_2_0);
        transition select(hdr.header_2_0.field_0) {
            	16w0    : parser_header_2_0_0;
	16w1    : parser_header_2_0_1;
	16w2    : parser_header_2_0_2;
				default: accept;

        }
    }
	@name(".parser_header_2_0_0") state parser_header_2_0_0 {
        packet.extract(hdr.header_2_0_0);
        transition select(hdr.header_2_0_0.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_2_0_1") state parser_header_2_0_1 {
        packet.extract(hdr.header_2_0_1);
        transition select(hdr.header_2_0_1.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_2_0_2") state parser_header_2_0_2 {
        packet.extract(hdr.header_2_0_2);
        transition select(hdr.header_2_0_2.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_2_1") state parser_header_2_1 {
        packet.extract(hdr.header_2_1);
        transition select(hdr.header_2_1.field_0) {
            	16w0    : parser_header_2_1_0;
	16w1    : parser_header_2_1_1;
	16w2    : parser_header_2_1_2;
				default: accept;

        }
    }
	@name(".parser_header_2_1_0") state parser_header_2_1_0 {
        packet.extract(hdr.header_2_1_0);
        transition select(hdr.header_2_1_0.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_2_1_1") state parser_header_2_1_1 {
        packet.extract(hdr.header_2_1_1);
        transition select(hdr.header_2_1_1.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_2_1_2") state parser_header_2_1_2 {
        packet.extract(hdr.header_2_1_2);
        transition select(hdr.header_2_1_2.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_2_2") state parser_header_2_2 {
        packet.extract(hdr.header_2_2);
        transition select(hdr.header_2_2.field_0) {
            	16w0    : parser_header_2_2_0;
	16w1    : parser_header_2_2_1;
	16w2    : parser_header_2_2_2;
				default: accept;

        }
    }
	@name(".parser_header_2_2_0") state parser_header_2_2_0 {
        packet.extract(hdr.header_2_2_0);
        transition select(hdr.header_2_2_0.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_2_2_1") state parser_header_2_2_1 {
        packet.extract(hdr.header_2_2_1);
        transition select(hdr.header_2_2_1.field_0) {
            	default : accept;

        }
    }
	@name(".parser_header_2_2_2") state parser_header_2_2_2 {
        packet.extract(hdr.header_2_2_2);
        transition select(hdr.header_2_2_2.field_0) {
            	default : accept;

        }
    }
	@name(".parse_ptp") state parse_ptp {
        packet.extract(hdr.ptp);
        transition select(hdr.ptp.reserved2) {
            	8w0     : parser_header_0;
	8w1     : parser_header_1;
	8w2     : parser_header_2;
				default: accept;

        }
    }
	@name(".start") state start {
        transition parse_ethernet;
    }
}



    
control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".forward") action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    @name(".forward_table") table forward_table {
        actions = {
            forward;
            _drop;
        }
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        size = 4;
    }
    apply {
        forward_table.apply();
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
		packet.emit(hdr.ptp);
		packet.emit(hdr.header_0);
		packet.emit(hdr.header_0_0);
		packet.emit(hdr.header_0_0_0);
		packet.emit(hdr.header_0_0_1);
		packet.emit(hdr.header_0_0_2);
		packet.emit(hdr.header_0_1);
		packet.emit(hdr.header_0_1_0);
		packet.emit(hdr.header_0_1_1);
		packet.emit(hdr.header_0_1_2);
		packet.emit(hdr.header_0_2);
		packet.emit(hdr.header_0_2_0);
		packet.emit(hdr.header_0_2_1);
		packet.emit(hdr.header_0_2_2);
		packet.emit(hdr.header_1);
		packet.emit(hdr.header_1_0);
		packet.emit(hdr.header_1_0_0);
		packet.emit(hdr.header_1_0_1);
		packet.emit(hdr.header_1_0_2);
		packet.emit(hdr.header_1_1);
		packet.emit(hdr.header_1_1_0);
		packet.emit(hdr.header_1_1_1);
		packet.emit(hdr.header_1_1_2);
		packet.emit(hdr.header_1_2);
		packet.emit(hdr.header_1_2_0);
		packet.emit(hdr.header_1_2_1);
		packet.emit(hdr.header_1_2_2);
		packet.emit(hdr.header_2);
		packet.emit(hdr.header_2_0);
		packet.emit(hdr.header_2_0_0);
		packet.emit(hdr.header_2_0_1);
		packet.emit(hdr.header_2_0_2);
		packet.emit(hdr.header_2_1);
		packet.emit(hdr.header_2_1_0);
		packet.emit(hdr.header_2_1_1);
		packet.emit(hdr.header_2_1_2);
		packet.emit(hdr.header_2_2);
		packet.emit(hdr.header_2_2_0);
		packet.emit(hdr.header_2_2_1);
		packet.emit(hdr.header_2_2_2);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
