#!/usr/bin/perl -w
use strict;
use feature 'say';
use Text::CSV_PP;
use  Data::Dumper;
my $parser = Text::CSV_PP->new();


my @rows = ();
open (PCAP, "< test.wireshark");
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
		dataRate => $columns[10],
		dropped => $columns[11],
		ssid => $columns[12],
	);
	push(@rows, {%wireshark});
	#last if ($. == 5000);

}
close(PCAP);

#question1();
#question4();
question5();
#question6();
#question7();
#question8();
#question9();


sub question9 {
	my $rts = 0;
	my $total = 0;
	foreach my $row (@rows) {
		if ($row->{frameType} =~ /Clear-to-send/ || $row->{frameType} =~ /Request-to-send/) {
			$rts++;
		}
		$total++;
	}
	say "Request/Clear to Sends: ". $rts/$total;
}

sub question8 {
	my $bad = 0;
	my $total = 0;
	foreach my $row (@rows) {
		if ($row->{dropped} =~ /Error/){
			$bad++;
		}
		$total++;
	}
	say "Percent Bad Packets: ". $bad/$total; 
}

sub question7 {
	foreach my $row (@rows){
		next if ($row->{managementFrame} ne "Yes");
		if ($row->{Source} eq "00:24:6c:5e:03:30" || $row->{Source} eq "ArubaNet_5e:03:30") {
			say $row->{dataRate};
		}
	}
}

sub question6 {
	my $max =0;
	foreach my $row (@rows){
		if ($row->{dataRate} > $max) {
			$max = $row->{dataRate};
		}
	}
	say "Max Data Rate: $max";
}

sub question5 {
	my %mng_frm;
	foreach my $row (@rows) {
		#next if (!exists $row->{managementFrame});
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

sub question1 {
	my %essid;
	foreach my $row (@rows) {
		if ($row->{frameType} eq "Beacon frame") {
			$row->{beaconInt} =~ s/\s\[Seconds\]//i;
			if (exists $essid{$row->{ssid}}){
				 $essid{$row->{ssid}}[0] += $row->{beaconInt};
				 $essid{$row->{ssid}}[1]++;
			} else {
				 $essid{$row->{ssid}} = [$row->{beaconInt}, 1];
			}
		}
	}
	foreach my $id (keys %essid){
		say $id . " ". $essid{$id}[0]/$essid{$id}[1];
	}
}
