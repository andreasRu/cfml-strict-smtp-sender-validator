# cfml-strict-smtp-sender-validator

A CFML component to verify if an IPv4 address is allowed to send on behalf of an email address or email domain. This component performs various, also non-SPF-Compliant (strict even with ~all flag) verifications, similar to various email providers who dictate SPF, PTR, etc. IPv6 and DMARC is not supported, this works only on Lucee and this is all alpha!
