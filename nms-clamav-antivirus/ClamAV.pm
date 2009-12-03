#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright (C) 2006-2009 Nexenta Systems, Inc.
# All rights reserved.
#

#TODO: add config file for all services
# I hope file->onchange = service->restart(reload)
#############################################################################
package NZA::SmfClamfreshServiceObject;
#############################################################################

use NZA::Common;
use NZA::SmfService;
use NZA::Utils;
use strict;

use base qw(NZA::SmfNetworkServiceObject);

require 'nms-clamav-antivirus/Consts.pm';

sub new {
	my ($class, $parent) = @_;
	my $self = $class->SUPER::new( $NZA::ClamAV::FMRI_FRESHCLAM ,
		'clamfresh', {}, {}, {}, {}, $parent);

	bless $self, $class;

	return $self;
}

#############################################################################
package NZA::SmfCicapServiceObject;
#############################################################################

use NZA::Common;
use NZA::SmfService;
use NZA::Utils;
use strict;

use base qw(NZA::SmfNetworkServiceObject);

require 'nms-clamav-antivirus/Consts.pm';

sub new {
	my ($class, $parent) = @_;
	my $self = $class->SUPER::new($NZA::ClamAV::FMRI_CICAP,
		'cicap', {}, {}, {}, {}, $parent);

	bless $self, $class;

	return $self;
}

#############################################################################
package NZA::SmfVscanServiceObject;
#############################################################################

use NZA::Common;
use NZA::SmfService;
use NZA::Utils;
use strict;

use base qw(NZA::SmfNetworkServiceObject);

require 'nms-clamav-antivirus/Consts.pm';

sub new {
	my ($class, $parent) = @_;
	my $self = $class->SUPER::new($NZA::ClamAV::FMRI_VSCAN,
		'vscan', {}, {}, {}, {}, $parent);

	bless $self, $class;

	return $self;
}

#############################################################################
package NZA::VscanConfig;
#############################################################################

use NZA::Exception;
use NZA::Common;
use NZA::Utils;

use strict;

sub new {
	my ($class) = @_;
	my $self = {};

	bless $self, ref($class) || $class;

	return $self;
}

# clone NZA::ApacheStyleConfig
# proto => "[], [['array', ['dict', 'string', 'string']]]",
sub list_options {
	my ($self, $where) = @_;
	my @lines = ();
	my @options = ();
	my $nvp_re = qr/^\s*(((?:.)*?\S)\s*=\s*(.*\S))\s*$/o;

	if ( nza_exec( "$NZA::ClamAV::CMD_VSCANADM show", \@lines ) != 0 ) {
		die new NZA::Exception($Exception::SystemCallError,
			"Error: vscan list_options\n@lines");
	}

	foreach my $line ( @lines ) {
		next if $line =~ m/^\s*$/;
		push @options,  {name=>$2, value=>$3} if $line =~ m/$nvp_re/;

	}

	return \@options;
}

# $self->{config}->option_exists({'name' => 'test'})
# $self->{config}->set_option({'name' => 'test', 'value' => 'best'})
# $self->{config}->add_option({'name' => 'test', 'value' => 'best'}})

sub option_exists {
	my ($self, $option, $where) = @_;

	foreach my $op ( @{ $self->list_options() } ) {
		return 1 if ( $op->{'name'} eq $option->{'name'} );
	}

	return 0;
}

sub add_option {
	my ($self, $option, $where) = @_;
	return $self->set_option( $option, $where );
}

sub set_option {
	my ($self, $option, $where) = @_;
	my @lines = ();

	#
	# avscan:hostname=localhost
	# max-size = 10m
	#
	if ( $option->{name} =~ m/^\s*$NZA::ClamAV::ENGINE_NAME:(.*\S)\s*$/ ) {

		if ( nza_exec( "$NZA::ClamAV::CMD_VSCANADM set-engine -p $1=$option->{value} $NZA::ClamAV::ENGINE_NAME", \@lines ) != 0 ) {
			die new NZA::Exception($Exception::SystemCallError,
				"Error: vscan set_option $1=$option->{value} engine:$NZA::ClamAV::ENGINE_NAME\nReason: @lines");
		}

	} else {
		if ( nza_exec( "$NZA::ClamAV::CMD_VSCANADM set -p $option->{name}=$option->{value}", \@lines ) != 0 ) {
			die new NZA::Exception($Exception::SystemCallError,
				"Error: vscan set_option $option->{name}=$option->{value}\nReason: @lines");
		}
	}
}

sub get_option {
	my ($self, $option, $where) = @_;

	foreach my $op ( @{ $self->list_options() } ) {
		return $op->{'value'} if ( $op->{'name'} eq $option->{'name'} );
	}

	return undef;
}

#############################################################################
package NZA::ClamAVObject;
#############################################################################

use NZA::Exception;
use NZA::Common;
use NZA::Config;
use NZA::Utils;

use strict;

use base qw(NZA::Object);

require 'nms-clamav-antivirus/Consts.pm';

#FIXME
use Data::Dumper;

sub new {
	my ($class) = @_;

	my $self = $class->SUPER::new('ClamAV');

	my $netsvc_cont = $NZA::server_obj->get_impl_object('smf', 'networkservice');

	my $clamfresh_obj = new NZA::SmfClamfreshServiceObject( $netsvc_cont );
	my $cicap_obj = new NZA::SmfCicapServiceObject( $netsvc_cont );
	my $vscan_obj = new NZA::SmfVscanServiceObject( $netsvc_cont );

	$netsvc_cont->attach( $clamfresh_obj, 1 );
	$netsvc_cont->attach( $cicap_obj, 1 );
	$netsvc_cont->attach( $vscan_obj, 1 );

	bless $self, $class;

	$self->{configuration}->{$NZA::ClamAV::CONF_FRESHCLAM_NAME} = new NZA::ApacheStyleConfig($NZA::ClamAV::CONF_FRESHCLAM);
	$self->{configuration}->{$NZA::ClamAV::CONF_CICAP_NAME} = new NZA::ApacheStyleConfig($NZA::ClamAV::CONF_CICAP);
	$self->{configuration}->{$NZA::ClamAV::CONF_VSCAN_NAME} = new NZA::VscanConfig();

	return $self;
}

sub install_engine {
	my ($self) = @_;
	my @lines = ();

	# &NZA::smf->reread_config($NZA::ClamAV::FMRI_VSCAN);
	# &NZA::smf->enable($NZA::ClamAV::FMRI_VSCAN);

	if ( nza_exec( "$NZA::ClamAV::CMD_VSCANADM add-engine $NZA::ClamAV::ENGINE_NAME", \@lines ) != 0) {
		TRACE("ClamAV: add-engine $NZA::ClamAV::ENGINE_NAME: @lines");
		# die new NZA::Exception($Exception::SystemCallError,
			# "Error: engine $NZA::ClamAV::ENGINE_NAME is off");
		return 1;
	}

	if ( nza_exec( "$NZA::ClamAV::CMD_VSCANADM set-engine -p host=$NZA::ClamAV::ENGINE_HOST $NZA::ClamAV::ENGINE_NAME", \@lines ) != 0) {
		TRACE("ClamAV: set-engine host=$NZA::ClamAV::ENGINE_HOST $NZA::ClamAV::ENGINE_NAME: @lines");
		# die new NZA::Exception($Exception::SystemCallError,
			# "Error: engine $NZA::ClamAV::ENGINE_NAME is off");
		return 1;
	}

	return 0;
}

sub check_engine {
	my ($self) = @_;
	my @lines = ();

	if ( nza_exec( "$NZA::ClamAV::CMD_VSCANADM get-engine $NZA::ClamAV::ENGINE_NAME", \@lines ) != 0) {
		TRACE("ClamAV: get-engine $NZA::ClamAV::ENGINE_NAME error: @lines");
		# die new NZA::Exception($Exception::SystemCallError,
			# "Error: engine $NZA::ClamAV::ENGINE_NAME is off");
		return 1;
	}
	TRACE("ClamAV: get-engine $NZA::ClamAV::ENGINE_NAME ok");

	return 0;
}

sub get_params_desc {
	my ($self, $section) = @_;
	return $self->_get_params( $section, 1, 1);
}

sub get_params {
	my ($self, $section) = @_;
	return $self->_get_params( $section, 1);
}

sub get_all_params {
	my ($self, $section) = @_;
	return $self->_get_params( $section );
}

sub _get_params {
	my ($self, $section, $valid, $desc) = @_;
	my %props;

	foreach my $_section ( keys %NZA::ClamAV::CONF_ALL_PROPS ) {

		next if ( exists $NZA::ClamAV::CONF_ALL_PROPS{$section} && $section ne $_section );

		foreach my $param ( @{ $self->{configuration}->{$_section}->list_options() } ) {
			# &Data::Dumper::Dumpp([$param]);
			# FIXME: param: 'DatabaseMirror' can be multiply with same name

			next if ( $valid &&
				not exists $NZA::ClamAV::CONF_ALL_PROPS{$_section}->{ $param->{'name'} } );

			$props{ $param->{'name'} } = ( $desc ) ?
				$NZA::ClamAV::CONF_ALL_PROPS{$_section}->{ $param->{'name'} } :
				$param->{'value'};
		}
	}

	return \%props;
}

sub set_params {
	my ($self, $params) = @_;

	die new NZA::Exception($Exception::WrongArguments, "Parameters must be specified.")
		if (!defined($params) ||  ref($params) ne 'HASH');

	foreach my $_section ( keys %NZA::ClamAV::CONF_ALL_PROPS ) {
		foreach my $param ( @{ $self->{configuration}->{$_section}->list_options() } ) {

			next if not exists $NZA::ClamAV::CONF_ALL_PROPS{$_section}->{ $param->{'name'} };
			
			next if $param->{'name'} ne $params->{'name'};

			$self->{configuration}->{$_section}->set_option( $params );
		}
	}
}

sub stats {
	my ($self, $zero) = @_;
	my @lines = ();
	$zero = ( $zero ) ? "-z" : "";
	nza_exec("$NZA::ClamAV::CMD_VSCANADM stats $zero", \@lines);

	@lines = map { chomp($_); "$_\n" } @lines;
	return \@lines;
}

sub icap {
	my ($self, $checktest, $testfile) = @_;
	my @lines = ();

	#
	# ICAP/1.0 200 OK
	#
	if ( nza_exec("$NZA::ClamAV::CMD_ICAP_CLIENT", \@lines) != 0 ) {
		die new NZA::Exception($Exception::SystemCallError,
			"Error: icap connect\n@lines");
	}

	#
	# FOUND!
	#
	if ( $checktest ) {
		$testfile = $NZA::ClamAV::TEST_FILE unless $testfile;
		@lines = ();
		if ( nza_exec("$NZA::ClamAV::CMD_ICAP_CLIENT -f $testfile -s $NZA::ClamAV::ENGINE_NAME", \@lines) != 0 ) {
			die new NZA::Exception($Exception::SystemCallError,
				"Error: icap testfile:$testfile engine:$NZA::ClamAV::ENGINE_NAME\n@lines");
		}
	}
	
	@lines = map { chomp($_); "$_\n" } @lines;
	return \@lines;
}

sub freshclam {
	my ($self) = @_;
	my @lines = ();
	my $retval;

	#NOTE: freshclam return always >0
	$retval = nza_exec($NZA::ClamAV::CMD_FRESHCLAM, \@lines);

	@lines = map { chomp($_); "$_\n" } @lines;
	return \@lines;
}

sub clamscan {
	my ($self, $vol, $folder, $recursive, $delete, $quarantine) = @_;
	my $zname = "$vol/$folder";
	my $mp; # mountpoint

	if ( $zname =~ m|^/| ) {
		#
		# clamscan('','/export/home/')
		# clamscan('','vol1/a2')
		#
		$mp = ( $folder =~ m|^/| ) ? $folder : "${NZA::VOLROOT}/${folder}";
	} else {
		#
		# clamscan('tank', 'users/mike')
		#
		my $fc = $NZA::server_obj->get_impl_object('folder');
		my $fol = $fc->get_object($zname);
		$mp = $fol->mountpoint();
	}

	#
	# check $mp for exists or raise error
	#
	die new NZA::Exception($Exception::ObjectNotFound, "Directory or file ${mp} not found") unless ( -d $mp || -f $mp || -l $mp );
	#
	# check $quarantine for exists or raise error
	#
	die new NZA::Exception($Exception::ObjectNotFound, "Quarantine directory ${quarantine} not found") if $quarantine && ! ( -d $quarantine );

	my $params = '';

	$params .= " -r"		 if $recursive;
	$params .= " --remove=yes"	 if $delete;
	$params .= " --move=$quarantine" if $quarantine;

	my @lines = ();
	my @viruses = ();
	my $retval = nza_exec("$NZA::ClamAV::CMD_CLAMSCAN $params $mp", \@lines);

	if ( $retval == 256 ) {

		# TODO: parse output and report fault
		for my $line (@lines) {
			# ( $pathname, $virusname ) = ($line =~ /^(.+):\s+(\S+)\s+FOUND$/);
			push @viruses, $1 if $line =~ /^(.+)\s+FOUND$/;
			# push @viruses, $1 if $line =~ /^(WARNING.*)$/; # XXX ???
		}
		# TRACE("ClamAV: Viruses Found");
		# map { TRACE("ClamAV: ${_}"); $_ } @viruses if scalar @viruses;

		#
		# log it
		#
		$NZA::server_obj->append_log( "ClamAV: Viruses Found", \@viruses );

		#
		# broadcast it
		#
		my $timestamp = localtime();
		my %evt_broadcast_props = (
			type => 'clamav-scan',
			name => 'ClamAV: Viruses Found',
			'time' => $timestamp,
			description  => join( "\n", @viruses ),
		);
		$NZA::server_obj->event_broadcast(\%evt_broadcast_props);

	} elsif ( $retval != 0 ) {

		# retval:512 quarantine folder not exists
		# retval:14336 if WARNING: Can't access file No such file or directory
		die new NZA::Exception($Exception::SystemCallError, "Error run $NZA::ClamAV::CMD_CLAMSCAN $params $mp retval:$retval output: @lines");
	}

	@lines = map { chomp($_); "$_\n" } @lines;

	return \@lines;
}

sub _get_zfs_object {
	my ($self, $vol, $folder) = @_;
	my $fol;

	if ( $vol ne '' && $folder ne '' ) {
		my $zname = "$vol/$folder";
		my $fc = $NZA::server_obj->get_impl_object('folder');

		$fol = $fc->get_object($zname);

	} elsif ( $vol ne '' ) {
		my $vc = $NZA::server_obj->get_impl_object('volume');

		$fol = $vc->get_object($vol);
	}

	return $fol;
}

sub set_vscan_value {
	my ($self, $vol, $folder, $value) = @_;
	my $fol = $self->_get_zfs_object($vol, $folder);

	TRACE($NZA::TRACE_LEVEL_VVV, "ClamAV: $value vscan at " . $fol->_get_type_str() .
		" $vol/$folder, old:" . $fol->_get_child_prop('vscan'));

	return unless $fol;

	if ( $value eq 'disable' ) {

		$fol->_set_child_prop('vscan', 'off');

	} elsif ( $value eq 'enable' ) {

		$fol->_set_child_prop('vscan', 'on');

	} elsif ( $value eq 'reset' ) {

		#
		# if object is volume the nza think default is "on" but "zfs -
		#
		$fol->_set_child_prop('vscan', 'off') if $fol->isa('NZA::Volume');
		$fol->inherit_prop('vscan');
		#
		# inherit_prop don't dirty (refresh) like set_child_prop
		#
		$fol->_dirty_recurs();
		#
		# and _dirty_recurs don't dirty self (root)
		#
		$fol->dirty(1); # set flag, then other run the $fol->refresh();
	}
}

sub get_vscan_props {
	my ($self, $vol, $folder, $pattern) = @_;
	my $fol = $self->_get_zfs_object($vol, $folder);
	my %out = ();
	
	if ( defined $fol ) {

		$out{$fol->{name}} = $fol->_get_child_prop('vscan');

	} else {
		#
		# if vol='' folder=''
		#
		$fol = $NZA::server_obj->get_impl_object('folder') unless $fol;

		my $list_on = $fol->get_names_by_prop( 'vscan', 'on', '' );
		my $list_off = $fol->get_names_by_prop( 'vscan', 'off', '' );

		if (defined $pattern && length($pattern) > 0) {
			$list_off = () if $pattern =~ /on/;
			$list_on = () if $pattern =~ /off/;
		}

		foreach my $zname ( @$list_on ) {
			$out{$zname} = "on";
		}

		foreach my $zname ( @$list_off ) {
			$out{$zname} = "off";
		}

		# # same way
		# # from get_names
		# my $h = $fol->{objects};

		# for my $name (keys %$h) {
			# my $obj = $h->{$name};

			# next if ($NZA::EXCLUDE_SYSPOOL && $obj->isa('NZA::Volume') && $name eq $NZA::SYSPOOL);
			# next if ($NZA::EXCLUDE_SYSPOOL && $obj->isa('NZA::Folder') && $name =~ /^$NZA::SYSPOOL\//);
			# next if ($NZA::EXCLUDE_SYSPOOL && $obj->isa('NZA::Snapshot') && $name =~ /^$NZA::SYSPOOL\//);

			# if ($obj->dirty()) {
				# TRACE("ClamAV: get_vscan_props: refresh $name");
				# $obj->refresh();
			# }

			# if (defined $pattern && length($pattern) > 0) {
				# next if ($obj->{vscan} !~ /$pattern/);
			# }

			# $out{$name} = $obj->{vscan};
		# }
	}

	return \%out;
}

sub is_vscan_enabled {
	my ($self, $vol, $folder) = @_;
	my $fol = $self->_get_zfs_object($vol, $folder);
	my $prop = $fol->_get_child_prop('vscan');

	TRACE($NZA::TRACE_LEVEL_VVV, "ClamAV: at " . $fol->_get_type_str() .
		" $vol/$folder, vscan:" . $prop);

	return 1 if ($prop eq 'on');

	return 0;
}

#
# wrapper for '/Root/Runner/ClamRunner
#
sub schedule_create {
	my ($self, $pathname, $params, $tunables) = @_;
	$NZA::server_obj->{runner}->{clamav_runner}->create($pathname, $params, $tunables);
}

sub schedule_destroy {
	my ($self, $pathname) = @_;
	$NZA::server_obj->{runner}->{clamav_runner}->destroy($pathname);
}


#############################################################################
package NZA::ClamAVIPC;
#############################################################################

use strict;
use base qw(NZA::ObjectIPC);
use Net::DBus::Exporter qw(com.nexenta.nms.ClamAV);
#use ClamRunner;
require 'nms-clamav-antivirus/ClamRunner.pm';

my %props = (
	#
	# TODO: add here vscan prop and other if it needed
	# try play with it
	#
);

my %methods = (
	#
	# wrapper for '/Root/Runner/ClamRunner
	#
	schedule_create	=> {
		# pathname, params, tunables
		proto => "['string', ['dict', 'string', 'string'], ['dict', 'string', 'string']], []",
		access => $NZA::API_WRITE.$NZA::API_DELEGATE_IMPL,
	},

	schedule_destroy => {
		# pathname
		proto => "['string'], []",
		access => $NZA::API_WRITE.$NZA::API_DELEGATE_IMPL,
	},

	#
	# TODO: vscan prop, need to be moved to Volume.pm & Folder.pm
	#
	set_vscan_value => {

		proto => "['string', 'string', 'string'], []",
		access => $NZA::API_WRITE.$NZA::API_DELEGATE_IMPL,
	},

	get_vscan_props => {

		proto => "['string', 'string', 'string'], [['dict', 'string', 'string']]",
		access => $NZA::API_DELEGATE_IMPL,
	},

	is_vscan_enabled => {

		proto => "['string', 'string'], ['bool']",
		access => $NZA::API_DELEGATE_IMPL,
	},

	#
	# Engine
	#
	install_engine => {

		proto => "[], ['bool']",
		access => $NZA::API_DELEGATE_IMPL,
	},

	check_engine => {

		proto => "[], ['bool']",
		access => $NZA::API_DELEGATE_IMPL,
	},

	#
	# 
	#
	clamscan => {

		proto => "['string', 'string', 'bool', 'bool', 'string'], [['array', 'string']]",
		access => $NZA::API_DELEGATE_IMPL,
	},

	freshclam => {

		proto => "[], [['array', 'string']]",
		access => $NZA::API_DELEGATE_IMPL,
	},

	icap => {

		proto => "['bool', 'string'], [['array', 'string']]",
		access => $NZA::API_DELEGATE_IMPL,
	},

	stats => {

		proto => "['bool'], [['array', 'string']]",
		access => $NZA::API_DELEGATE_IMPL,
	},

	get_all_params => {

		proto => "['string'], [['dict', 'string', 'string']]",
		access => $NZA::API_DELEGATE_IMPL,
	},

	get_params_desc => {

		proto => "['string'], [['dict', 'string', ['array', 'string']]]",
		access => $NZA::API_DELEGATE_IMPL,
	},

	get_params => {

		proto => "['string'], [['dict', 'string', 'string']]",
		access => $NZA::API_DELEGATE_IMPL,
	},

	set_params => {

		proto => "[['dict', 'string', 'string']], []",
		access => $NZA::API_DELEGATE_IMPL,
	},
);

#/Root/ClamAV
sub new {
	my ($class, $parent) = @_;

	my $object = new NZA::ClamAVObject( $parent );
	my $self = $class->SUPER::new( 'ClamAV', $parent, $object,
		\%props, \%methods );

	#
	# /Root/Runner/ClamRunner
	#
	my $runner = $NZA::server_obj->{runner};
	my $runner_container = $NZA::server_obj->get_impl_object('runner');
	$runner->{clamav_runner} = new NZA::ClamRunnerIPC( $runner, $runner_container );

	bless $self, $class;

	eval $self->_gen_api();

	return $self;
}

1;
# vim:set sts=0 ts=8 sw=8 noet:
