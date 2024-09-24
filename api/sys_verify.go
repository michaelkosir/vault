// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
)

func (c *Sys) VerifyQuorumStatus() (*VerifyQuorumStatusResponse, error) {
	return c.VerifyQuorumStatusWithContext(context.Background())
}

func (c *Sys) VerifyQuorumStatusWithContext(ctx context.Context) (*VerifyQuorumStatusResponse, error) {
	return c.VerifyQuorumStatusCommonWithContext(ctx)
}

func (c *Sys) VerifyQuorumStatusCommonWithContext(ctx context.Context) (*VerifyQuorumStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/verify/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result VerifyQuorumStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

func (c *Sys) VerifyQuorumInit() (*VerifyQuorumStatusResponse, error) {
	return c.VerifyQuorumInitWithContext(context.Background())
}

func (c *Sys) VerifyQuorumInitWithContext(ctx context.Context) (*VerifyQuorumStatusResponse, error) {
	return c.VerifyQuorumInitCommonWithContext(ctx)
}

func (c *Sys) VerifyQuorumInitCommonWithContext(ctx context.Context) (*VerifyQuorumStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{}

	r := c.c.NewRequest(http.MethodPut, "/v1/sys/verify/init")
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result VerifyQuorumStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

func (c *Sys) VerifyQuorumCancel() error {
	return c.VerifyQuorumCancelWithContext(context.Background())
}

func (c *Sys) VerifyQuorumCancelWithContext(ctx context.Context) error {
	return c.VerifyQuorumCancelCommonWithContext(ctx)
}

func (c *Sys) VerifyQuorumCancelCommonWithContext(ctx context.Context) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, "/v1/sys/verify/init")

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err == nil {
		defer resp.Body.Close()
	}
	return err
}

func (c *Sys) VerifyQuorumUpdate(shard, nonce string) (*VerifyQuorumStatusResponse, error) {
	return c.VerifyQuorumUpdateWithContext(context.Background(), shard, nonce)
}

func (c *Sys) VerifyQuorumUpdateWithContext(ctx context.Context, shard, nonce string) (*VerifyQuorumStatusResponse, error) {
	return c.VerifyQuorumUpdateCommonWithContext(ctx, shard, nonce)
}

func (c *Sys) VerifyQuorumUpdateCommonWithContext(ctx context.Context, shard, nonce string) (*VerifyQuorumStatusResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := map[string]interface{}{
		"key":   shard,
		"nonce": nonce,
	}

	r := c.c.NewRequest(http.MethodPut, "/v1/sys/verify/update")
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result VerifyQuorumStatusResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

type VerifyQuorumStatusResponse struct {
	Nonce    string `json:"nonce"`
	Started  bool   `json:"started"`
	Progress int    `json:"progress"`
	Required int    `json:"required"`
	Complete bool   `json:"complete"`
}
