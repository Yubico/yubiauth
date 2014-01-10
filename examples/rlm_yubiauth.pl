# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
# This is a working example of how to configure FreeRADIUS to use YubiAuth
# to authenticate users.
#
# To use, configure the rlm_perl module in FreeRadius to use this script, and
# add the Perl module to the authorize and authenticate sections of your site
# configuration.
#
# You will also need to add the accompanying dictionary file to be included in
# /etc/freeradius/dictionary
# 
# YubiKey OTPs are expected to be appended to either the username or password.
#

use strict;
use warnings;
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK);
use LWP::UserAgent;

our $id_len = 12;
our $yubiauth_url = "http://localhost/yubiauth/client/authenticate";

my $otp_len = 32 + $id_len;

########################
# FreeRADIUS functions #
########################

use constant    RLM_MODULE_REJECT=>    0;#  /* immediately reject the request */
use constant	RLM_MODULE_FAIL=>      1;#  /* module failed, don't reply */
use constant	RLM_MODULE_OK=>	2;#  /* the module is OK, continue */
use constant	RLM_MODULE_HANDLED=>   3;#  /* the module handled the request, so stop. */
use constant	RLM_MODULE_INVALID=>   4;#  /* the module considers the request invalid. */
use constant	RLM_MODULE_USERLOCK=>  5;#  /* reject the request (user is locked out) */
use constant	RLM_MODULE_NOTFOUND=>  6;#  /* user not found */
use constant	RLM_MODULE_NOOP=>      7;#  /* module succeeded without doing anything */
use constant	RLM_MODULE_UPDATED=>   8;#  /* OK (pairs modified) */
use constant	RLM_MODULE_NUMCODES=>  9;#  /* How many return codes there are */


# Extract the OTP appended to the username or password.
sub authorize {
	# Extract OTP, if available
	my $otp = '';
	if($RAD_REQUEST{'User-Name'} =~ /[cbdefghijklnrtuv]{$otp_len}$/) {
		my $username_len = length($RAD_REQUEST{'User-Name'}) - $otp_len;
		$RAD_REQUEST{'Yubikey-OTP'} = substr $RAD_REQUEST{'User-Name'}, $username_len;
		$RAD_REQUEST{'User-Name'} = substr $RAD_REQUEST{'User-Name'}, 0, $username_len;
	} elsif($RAD_REQUEST{'User-Password'} =~ /[cbdefghijklnrtuv]{$otp_len}$/) {
		my $password_len = length($RAD_REQUEST{'User-Password'}) - $otp_len;
		$RAD_REQUEST{'Yubikey-OTP'} = substr $RAD_REQUEST{'User-Password'}, $password_len;
		$RAD_REQUEST{'User-Password'} = substr $RAD_REQUEST{'User-Password'}, 0, $password_len;
	}

	$RAD_CHECK{'Auth-Type'} = "Perl";
	return RLM_MODULE_UPDATED;
}

sub authenticate {
	my %data = ();
	if($RAD_REQUEST{'User-Name'} ne '') {
		$data{'username'} = $RAD_REQUEST{'User-Name'};
	}
	if($RAD_REQUEST{'User-Password'} ne '') {
		$data{'password'} = $RAD_REQUEST{'User-Password'};
	}
	if($RAD_REQUEST{'Yubikey-OTP'} ne '') {
		$data{'otp'} = $RAD_REQUEST{'Yubikey-OTP'};
	}

	my $ua = LWP::UserAgent->new();
	my $response = $ua->post($yubiauth_url, [%data]);
	my $content  = $response->decoded_content();

	if($content eq "true") {
		return RLM_MODULE_OK;
	} else {
		$RAD_REPLY{'Reply-Message'} = $content;
		return RLM_MODULE_REJECT;
	}
}
