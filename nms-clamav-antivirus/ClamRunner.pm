#
# Copyright (C) 2006-2009 Nexenta Systems, Inc.
# All rights reserved.
#

#############################################################################
package NZA::ClamRunnerObject;
#############################################################################

use NZA::Exception;
use NZA::Common;
use NZA::Utils;
use NZA::Runner;
use strict;
use base qw(NZA::RunnerObject);

my $CLAMAV_RUNNER_SCRIPT	= 'clamav-scan';

sub new {
	my ($class, $name, $parent) = @_;

	# 
	# the very first time pass is_new = 1 - the 2nd argument
	#
        my $exec = "$NZA::LIBROOT/$CLAMAV_RUNNER_SCRIPT '$name'";
	my $self = $class->SUPER::new($exec, $NZA::RFLAG_NONE, $name, $parent);

	bless $self, $class;

	return $self;
}

sub get_init_params {
	my ($self) = @_;
	return $self->{params};
}

sub get_init_tunables {
	my ($self) = @_;
	return $self->{tunables};
}


#############################################################################
package NZA::ClamRunnerIPC;
#############################################################################

use strict;
use base qw(NZA::ContainerIPC);
use NZA::Common;
use NZA::Utils;
use Net::DBus::Exporter qw(com.nexenta.nms.ClamRunner);

my $CLAMAV_RUNNER_TYPE		= 'clamav-scan';

#FIXME
use Data::Dumper;

my %script_props = (
);

my %script_methods = (
	'create'	  => { proto => "['string', ['dict', 'string', 'string'], ['dict', 'string', 'string']], []",
			       access => $NZA::API_WRITE.$NZA::API_EXECUTE },

	'destroy'	  => { proto => "['string'], []",
			       access => $NZA::API_WRITE.$NZA::API_EXECUTE },

	get_init_params	  => { proto => "['string'], [['dict', 'string', 'string']]",
			       access => $NZA::API_READ.$NZA::API_DELEGATE_CHILD },

	get_init_tunables => { proto => "['string'], [['dict', 'string', 'string']]",
			       access => $NZA::API_READ.$NZA::API_DELEGATE_CHILD },
);

sub new {
	my ($class, $ipc_parent, $runner_container) = @_;

	my $self = $class->SUPER::new('ClamRunner', $ipc_parent, $runner_container,
				      NZA::RunnerIPC::common_props(),
				      NZA::RunnerIPC::common_methods());
	bless $self, $class;

	$self->add_props_and_methods(\%script_props, \%script_methods);
	eval $self->_gen_api();

	$self->_construct_all();

	return $self;
}

sub _construct_all {
	my $self = shift;
	my $container = $self->impl_object();

	#
	# recovery old state of runners by our type
	#  
	my $all_scripts = $container->{dbh}->selectall_arrayref("SELECT name FROM runners WHERE type = ?",
								undef, $CLAMAV_RUNNER_TYPE);

	for my $script_name_ref (@$all_scripts) {
		my $script_name = $script_name_ref->[0];
		my $rec = $container->get_runner($script_name);
		my $obj = new NZA::ClamRunnerObject($script_name, $container);

		for my $k (keys %$rec) {
			next if ($k eq 'name');
			next if ($k =~ /^tunables/);
			$obj->{$k} = $rec->{$k};
		};

		$obj->{tunables} = $container->__get_tunables($rec, '');

		TRACE($NZA::TRACE_LEVEL_VVV, "ClamRunner: attach ${script_name}");

		$container->attach($obj, 1);
	}
}

sub create {
	my ($self, $pathname, $params, $tunables) = @_;
	my $container = $self->impl_object();

	my $obj = new NZA::ClamRunnerObject($pathname, $container);

	$obj->{type} = $params->{type};
	$obj->{params} = $params;
	$obj->{tunables} = $tunables;
	
	$container->attach($obj, 1);
}

sub destroy {
	my ($self, $pathname) = @_;
	my $container = $self->impl_object();

	$container->unregister($pathname);
}

1;
