#!/usr/bin/perl -w
use strict;
use feature 'say';
use Text::CSV_PP;
use  Data::Dumper;
my $parser = Text::CSV_PP->new();


my @rows = ();
open (PCAP, "< test2.wireshark");
while (my $line = <PCAP>){
	chomp($line);
	next if ($. == 1);
	$parser->parse($line);
	my @columns = $parser->fields();

	my %wireshark = (
		No => $columns[0],
		Time => $columns[1],
		Source => $columns[2],
		Destination => $columns[3],
		Protocol => $columns[4],
		Length => $columns[5],
		Info => $columns[6],
		beaconInt => $columns[7],
		managementFrame => $columns[8],
		frameType => $columns[9],
	);
	push(@rows, {%wireshark});
	#last if ($. == 5000);

}
close(PCAP);

#question4();
question5();

sub question5 {
	my %mng_frm;
	foreach my $row (@rows) {
		next if (!exists $row->{managementFrame});
		if ($row->{managementFrame} eq "Yes"){
			if (exists $mng_frm{$row->{frameType}}) {
				$mng_frm{$row->{frameType}}++;
			} else {
				$mng_frm{$row->{frameType}} = 1;
			}
		}
	}
	print Dumper \%mng_frm;
	#foreach my $key (%mng_frm) {
		#print $key . " ". $mng_frm{$key}. "\n";
	#}
}

sub question4 {
	my %mac;
	foreach my $row (@rows) {
		if ($row->{Destination} eq "00:24:6c:5e:03:30" || $row->{Destination} eq "ArubaNet_5e:03:30") {
			$mac{$row->{Source}} = 1; 
		}
	}
	foreach my $macs (keys %mac){
		say $macs;
	}
}

#print Dumper @rows;
sub dump {
	
}
