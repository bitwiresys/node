package xray

import (
	"context"
	"errors"
	"log"
	"slices"

	"github.com/pasarguard/node/common"
)

// pushWireguardPeers applies WG peers via Xray HandlerService (no process restart).
// Initial JSON should keep settings.peers empty; panel passes users on Start.
func (x *Xray) pushWireguardPeers(ctx context.Context, users []*common.User) error {
	handler := x.handler
	if handler == nil {
		return errors.New("xray handler not ready")
	}

	var errMessage string
	applied := 0

	for _, user := range users {
		proxySetting, err := setupUserAccount(user)
		if err != nil || proxySetting.Wireguard == nil {
			continue
		}

		userInbounds := user.GetInbounds()
		for _, inbound := range x.config.InboundConfigs {
			if inbound.exclude || inbound.Protocol != Wireguard {
				continue
			}
			if !slices.Contains(userInbounds, inbound.Tag) {
				continue
			}

			account := proxySetting.Wireguard
			_ = handler.RemoveInboundUser(ctx, inbound.Tag, account.GetEmail())
			inbound.updateUser(account)
			if err := handler.AddInboundUser(ctx, inbound.Tag, accountForAPI(inbound, account)); err != nil {
				log.Printf("wireguard add peer %s on %s: %v", account.GetEmail(), inbound.Tag, err)
				errMessage += "\n" + err.Error()
				continue
			}
			applied++
		}
	}

	if applied > 0 {
		log.Printf("wireguard: applied %d peer(s) via API", applied)
	}

	if errMessage != "" {
		return errors.New("failed to push wireguard peers:" + errMessage)
	}
	return nil
}
