lappend auto_path [file dirname [info script]]
package require ossltest

namespace eval is_openssl_bug {
	proc asn1_item_verify_with_provider {} {
		global OPENSSL_APP

		set is_affected_version 0

		set openssl_ver [exec $OPENSSL_APP version]
		if {[regexp {^OpenSSL 4\.0\.0} $openssl_ver]} {
			set is_affected_version 1
		} elseif {[regexp {^OpenSSL 3\..*} $openssl_ver]} {
			if {![info exists ::env(TLS13_PATCHED_OPENSSL)] || $::env(TLS13_PATCHED_OPENSSL) != 1} {
				set is_affected_version 1
			}
		}

		return $is_affected_version
	}

	namespace export asn1_item_verify_with_provider
}

package provide is_openssl_bug 0.1