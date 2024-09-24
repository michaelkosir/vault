// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/shamir"
)

// VerifyQuorumQuorumConfig holds the configuration for a verify command.
type VerifyQuorumConfig struct {
	Nonce string
}

// VerifyQuorumResult holds the result of a verify update command
type VerifyQuorumResult struct {
	Progress int
	Required int
}

// VerifyQuorumProgress is used to return the verify progress (num shares)
func (c *Core) VerifyQuorumProgress() (int, error) {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() && !c.recoveryMode {
		return 0, consts.ErrSealed
	}
	if c.standby && !c.recoveryMode {
		return 0, consts.ErrStandby
	}

	c.verifyQuorumLock.Lock()
	defer c.verifyQuorumLock.Unlock()

	return len(c.verifyQuorumProgress), nil
}

// VerifyQuorumQuorumConfiguration is used to read the verify configuration
func (c *Core) VerifyQuorumConfiguration() (*VerifyQuorumConfig, error) {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() && !c.recoveryMode {
		return nil, consts.ErrSealed
	}
	if c.standby && !c.recoveryMode {
		return nil, consts.ErrStandby
	}

	c.verifyQuorumLock.Lock()
	defer c.verifyQuorumLock.Unlock()

	return c.verifyQuorumConfig, nil
}

// VerifyQuorumInit is used to initialize the root generation settings
func (c *Core) VerifyQuorumInit() error {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() && !c.recoveryMode {
		return consts.ErrSealed
	}
	barrierSealed, err := c.barrier.Sealed()
	if err != nil {
		return errors.New("unable to check barrier seal status")
	}
	if !barrierSealed && c.recoveryMode {
		return errors.New("attempt to verify when already unsealed")
	}
	if c.standby && !c.recoveryMode {
		return consts.ErrStandby
	}

	c.verifyQuorumLock.Lock()
	defer c.verifyQuorumLock.Unlock()

	// Prevent multiple concurrent verifications
	if c.verifyQuorumConfig != nil {
		return fmt.Errorf("verify already in progress")
	}

	// Copy the configuration
	generationNonce, err := uuid.GenerateUUID()
	if err != nil {
		return err
	}

	c.verifyQuorumConfig = &VerifyQuorumConfig{
		Nonce: generationNonce,
	}

	c.logger.Info("verify initialized", "nonce", c.verifyQuorumConfig.Nonce)

	return nil
}

// VerifyQuorumUpdate is used to provide a new key part
func (c *Core) VerifyQuorumUpdate(ctx context.Context, key []byte, nonce string) (*VerifyQuorumResult, error) {
	// Verify the key length
	min, max := c.barrier.KeyLength()
	max += shamir.ShareOverhead
	if len(key) < min {
		return nil, &ErrInvalidKey{fmt.Sprintf("key is shorter than minimum %d bytes", min)}
	}
	if len(key) > max {
		return nil, &ErrInvalidKey{fmt.Sprintf("key is longer than maximum %d bytes", max)}
	}

	// Get the seal configuration
	var config *SealConfig
	var err error
	if c.seal.RecoveryKeySupported() {
		config, err = c.seal.RecoveryConfig(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		config, err = c.seal.BarrierConfig(ctx)
		if err != nil {
			return nil, err
		}
	}

	// Ensure the barrier is initialized
	if config == nil {
		return nil, ErrNotInit
	}

	// Ensure we are already unsealed
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() && !c.recoveryMode {
		return nil, consts.ErrSealed
	}

	barrierSealed, err := c.barrier.Sealed()
	if err != nil {
		return nil, errors.New("unable to check barrier seal status")
	}
	if !barrierSealed && c.recoveryMode {
		return nil, errors.New("attempt to verify when already unsealed")
	}

	if c.standby && !c.recoveryMode {
		return nil, consts.ErrStandby
	}

	c.verifyQuorumLock.Lock()
	defer c.verifyQuorumLock.Unlock()

	// Ensure a verification is in progress
	if c.verifyQuorumConfig == nil {
		return nil, fmt.Errorf("no root generation in progress")
	}

	if nonce != c.verifyQuorumConfig.Nonce {
		return nil, fmt.Errorf("incorrect nonce supplied; nonce for this verify operation is %q", c.verifyQuorumConfig.Nonce)
	}

	// Check if we already have this piece
	for _, existing := range c.verifyQuorumProgress {
		if bytes.Equal(existing, key) {
			return nil, fmt.Errorf("given key has already been provided during this generation operation")
		}
	}

	// Store this key
	c.verifyQuorumProgress = append(c.verifyQuorumProgress, key)
	progress := len(c.verifyQuorumProgress)

	// Check if we don't have enough keys to unlock
	if len(c.verifyQuorumProgress) < config.SecretThreshold {
		if c.logger.IsDebug() {
			c.logger.Debug("cannot verify, not enough keys", "keys", progress, "threshold", config.SecretThreshold)
		}
		return &VerifyQuorumResult{
			Progress: progress,
			Required: config.SecretThreshold,
		}, nil
	}

	// Combine the key parts
	var combinedKey []byte
	if config.SecretThreshold == 1 {
		combinedKey = c.verifyQuorumProgress[0]
		c.verifyQuorumProgress = nil
	} else {
		combinedKey, err = shamir.Combine(c.verifyQuorumProgress)
		c.verifyQuorumProgress = nil
		if err != nil {
			return nil, fmt.Errorf("failed to compute root key: %w", err)
		}
	}

	// Auth and verify
	root, err := c.unsealKeyToRootKeyPostUnseal(ctx, combinedKey)
	if err != nil {
		c.logger.Error("verify quorum aborted", "error", err.Error())
		return nil, fmt.Errorf("unable to authenticate: %w", err)
	}
	if err := c.barrier.VerifyRoot(root); err != nil {
		c.logger.Error("verify quorum aborted", "error", err.Error())
		return nil, fmt.Errorf("root key verification failed: %w", err)
	}

	memzero(root)

	results := &VerifyQuorumResult{
		Progress: progress,
		Required: config.SecretThreshold,
	}

	c.logger.Info("verify finished", "nonce", c.verifyQuorumConfig.Nonce)

	c.verifyQuorumProgress = nil
	c.verifyQuorumConfig = nil
	return results, nil
}

// VerifyQuorumCancel is used to cancel an in-progress verification
func (c *Core) VerifyQuorumCancel() error {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() && !c.recoveryMode {
		return consts.ErrSealed
	}
	if c.standby && !c.recoveryMode {
		return consts.ErrStandby
	}

	c.verifyQuorumLock.Lock()
	defer c.verifyQuorumLock.Unlock()

	// Clear any progress or config
	c.verifyQuorumConfig = nil
	c.verifyQuorumProgress = nil
	return nil
}
