// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package upgrades

import (
	"context"
	"fmt"

	"go.mau.fi/util/dbutil"
)

func upgradeMobileDevice(ctx context.Context, db *dbutil.Database) error {
	// Both branches shipped v17: one created only the pending table, the other
	// also added device metadata. Add only missing columns, preserving sessions.
	for _, column := range []struct{ name, definition string }{
		{"mobile", "BOOLEAN NOT NULL DEFAULT FALSE"},
		{"mobile_version", "TEXT NOT NULL DEFAULT ''"},
		{"mobile_phone_id", "TEXT NOT NULL DEFAULT ''"},
		{"mobile_os_version", "TEXT NOT NULL DEFAULT ''"},
		{"mobile_model", "TEXT NOT NULL DEFAULT ''"},
		{"mobile_manufacturer", "TEXT NOT NULL DEFAULT ''"},
	} {
		exists, err := db.ColumnExists(ctx, "whatsmeow_device", column.name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err = db.Exec(ctx, fmt.Sprintf("ALTER TABLE whatsmeow_device ADD COLUMN %s %s", column.name, column.definition)); err != nil {
				return err
			}
		}
	}
	// The earlier remote implementation supported only iOS and did not store this.
	_, err := db.Exec(ctx, "UPDATE whatsmeow_device SET mobile_manufacturer='Apple' WHERE mobile=true AND mobile_manufacturer=''")
	return err
}
