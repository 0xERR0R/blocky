package dnssec

// This file contains the high-level denial of existence dispatcher
// that routes to NSEC or NSEC3 validation based on response contents.

import (
	"context"

	"github.com/miekg/dns"
)

// validateDenialOfExistence validates NSEC/NSEC3 records for authenticated denial of existence
// Per RFC 4035 §5.4 and RFC 5155
func (v *Validator) validateDenialOfExistence(
	ctx context.Context,
	response *dns.Msg,
	question dns.Question,
) ValidationResult {
	// Check if we have NSEC3 records (RFC 5155)
	hasNSEC3 := false
	hasNSEC := false

	for _, rr := range response.Ns {
		switch rr.(type) {
		case *dns.NSEC3:
			hasNSEC3 = true
		case *dns.NSEC:
			hasNSEC = true
		}
	}

	// Validate the authority section RRsets first (must have valid signatures)
	result := v.validateRRsets(ctx, response.Ns, question.Name, response.Ns, question.Name)
	if result != ValidationResultSecure {
		v.logger.Warnf("Authority section validation failed for denial of existence: %s", question.Name)

		return result
	}

	// Now validate the denial of existence proof
	if hasNSEC3 {
		return v.validateNSEC3DenialOfExistence(response, question)
	} else if hasNSEC {
		return v.validateNSECDenialOfExistence(response, question)
	}

	// No NSEC or NSEC3 records found - cannot validate denial of existence
	v.logger.Warnf("No NSEC/NSEC3 records found for denial of existence: %s", question.Name)

	return ValidationResultInsecure
}
