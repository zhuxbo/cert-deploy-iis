package deploy

import (
	"testing"

	"sslctlw/api"
	"sslctlw/config"
)

// TestUpdateRenewBeforeDays_Cap 服务端返回值超过上限 30 时拒绝并保留本地配置（deploy-spec 2.9）
func TestUpdateRenewBeforeDays_Cap(t *testing.T) {
	cfg := &config.Config{Schedule: config.Schedule{RenewBeforeDays: config.DefaultRenewBeforeDays}}
	client := &api.Client{}

	client.LastRenewBeforeDays = config.MaxRenewBeforeDays + 1
	updateRenewBeforeDays(cfg, client)
	if cfg.Schedule.RenewBeforeDays != config.DefaultRenewBeforeDays {
		t.Fatalf("超上限应保留本地配置，got %d", cfg.Schedule.RenewBeforeDays)
	}

	client.LastRenewBeforeDays = config.MaxRenewBeforeDays
	updateRenewBeforeDays(cfg, client)
	if cfg.Schedule.RenewBeforeDays != config.MaxRenewBeforeDays {
		t.Fatalf("上限值应更新，got %d", cfg.Schedule.RenewBeforeDays)
	}

	client.LastRenewBeforeDays = 0
	cfg.Schedule.RenewBeforeDays = config.DefaultRenewBeforeDays
	updateRenewBeforeDays(cfg, client)
	if cfg.Schedule.RenewBeforeDays != config.DefaultRenewBeforeDays {
		t.Fatalf("零值不应更新，got %d", cfg.Schedule.RenewBeforeDays)
	}
}
