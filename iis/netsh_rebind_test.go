package iis

import (
	"reflect"
	"testing"
)

// TestBuildRebindArgs_MinimalCapture full=false 仅三字段回绑（与改造前行为一致，降级不劣于现状）
func TestBuildRebindArgs_MinimalCapture(t *testing.T) {
	b := &capturedBinding{CertHash: "abcd", AppID: "{11111111-1111-1111-1111-111111111111}", CertStoreName: "MY"}
	got := buildRebindArgs("hostnameport", "www.example.com:443", b)
	want := []string{
		"hostnameport=www.example.com:443",
		"certhash=abcd",
		"appid={11111111-1111-1111-1111-111111111111}",
		"certstorename=MY",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("minimal 回绑参数\n got=%v\nwant=%v", got, want)
	}
}

// TestBuildRebindArgs_DefaultsFallback AppID/store 为空回退默认
func TestBuildRebindArgs_DefaultsFallback(t *testing.T) {
	b := &capturedBinding{CertHash: "ff"}
	got := buildRebindArgs("ipport", "0.0.0.0:443", b)
	want := []string{
		"ipport=0.0.0.0:443",
		"certhash=ff",
		"appid=" + defaultAppID,
		"certstorename=MY",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("默认回退\n got=%v\nwant=%v", got, want)
	}
}

// TestBuildRebindArgs_FullAllParams full=true 附加全部高级参数
func TestBuildRebindArgs_FullAllParams(t *testing.T) {
	b := &capturedBinding{
		CertHash:                "aa",
		AppID:                   "{22222222-2222-2222-2222-222222222222}",
		CertStoreName:           "WebHosting",
		full:                    true,
		certCheckMode:           certCheckModeNoVerifyRevocation | certCheckModeCachedRevocationOnly | certCheckModeNoUsageCheck,
		revocationFreshnessTime: 3600,
		urlRetrievalTimeout:     15000,
		sslCtlIdentifier:        "myctl",
		sslCtlStoreName:         "CA",
		defaultFlags:            sslFlagUseDSMapper | sslFlagNegotiateClientCert,
	}
	got := buildRebindArgs("ipport", "1.2.3.4:443", b)
	want := []string{
		"ipport=1.2.3.4:443",
		"certhash=aa",
		"appid={22222222-2222-2222-2222-222222222222}",
		"certstorename=WebHosting",
		"verifyclientcertrevocation=disable",
		"verifyrevocationwithcachedclientcertonly=enable",
		"usagecheck=disable",
		"revocationfreshnesstime=3600",
		"urlretrievaltimeout=15000",
		"sslctlidentifier=myctl",
		"sslctlstorename=CA",
		"dsmapperusage=enable",
		"clientcertnegotiation=enable",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("full 全参数\n got=%v\nwant=%v", got, want)
	}
}

// TestSSLParamNetshArgs_FlagBitCombos 位组合 → netsh 参数（仅回写非默认）
func TestSSLParamNetshArgs_FlagBitCombos(t *testing.T) {
	cases := []struct {
		name          string
		certCheckMode uint32
		flags         uint32
		want          []string
	}{
		{"全默认无参数", 0, 0, nil},
		{"仅不验证吊销", certCheckModeNoVerifyRevocation, 0, []string{"verifyclientcertrevocation=disable"}},
		{"仅协商客户端证书", 0, sslFlagNegotiateClientCert, []string{"clientcertnegotiation=enable"}},
		{"仅DS映射", 0, sslFlagUseDSMapper, []string{"dsmapperusage=enable"}},
		{
			"吊销位组合",
			certCheckModeNoVerifyRevocation | certCheckModeCachedRevocationOnly,
			0,
			[]string{"verifyclientcertrevocation=disable", "verifyrevocationwithcachedclientcertonly=enable"},
		},
		{
			"flags双位",
			0,
			sslFlagUseDSMapper | sslFlagNegotiateClientCert,
			[]string{"dsmapperusage=enable", "clientcertnegotiation=enable"},
		},
		{"未知位忽略", 0x00100000, 0x80000000, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &capturedBinding{certCheckMode: c.certCheckMode, defaultFlags: c.flags}
			got := sslParamNetshArgs(b)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("%s\n got=%v\nwant=%v", c.name, got, c.want)
			}
		})
	}
}

// TestSSLParamNetshArgs_NumericAndStringOnlyWhenSet 数值 0/字符串空不回写
func TestSSLParamNetshArgs_NumericAndStringOnlyWhenSet(t *testing.T) {
	b := &capturedBinding{revocationFreshnessTime: 0, urlRetrievalTimeout: 500, sslCtlIdentifier: "", sslCtlStoreName: "CA"}
	got := sslParamNetshArgs(b)
	want := []string{"urlretrievaltimeout=500", "sslctlstorename=CA"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("数值/字符串条件回写\n got=%v\nwant=%v", got, want)
	}
}

// TestAppIDStoreDefault 默认回退辅助
func TestAppIDStoreDefault(t *testing.T) {
	if appIDOrDefault("") != defaultAppID {
		t.Error("空 AppID 应回退默认")
	}
	if appIDOrDefault("{x}") != "{x}" {
		t.Error("非空 AppID 应原样返回")
	}
	if storeOrDefault("") != "MY" {
		t.Error("空 store 应回退 MY")
	}
	if storeOrDefault("CA") != "CA" {
		t.Error("非空 store 应原样返回")
	}
}
