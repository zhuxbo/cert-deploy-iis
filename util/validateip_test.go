package util

import "testing"

// TestValidateIP IPv4/IPv6 与通配地址通过，非法输入拒绝
func TestValidateIP(t *testing.T) {
	valid := []string{"0.0.0.0", "::", "1.2.3.4", "255.255.255.255", "::1", "2001:db8::1", "fe80::1"}
	for _, ip := range valid {
		if err := ValidateIP(ip); err != nil {
			t.Errorf("ValidateIP(%q) 应通过, got %v", ip, err)
		}
	}
	invalid := []string{"", "not-an-ip", "1.2.3", "1.2.3.4.5", "example.com", "999.999.999.999"}
	for _, ip := range invalid {
		if err := ValidateIP(ip); err == nil {
			t.Errorf("ValidateIP(%q) 应拒绝", ip)
		}
	}
}
