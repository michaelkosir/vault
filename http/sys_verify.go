// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package http

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/vault/vault"
)

func handleSysVerifyQuorumInit(core *vault.Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			handleSysVerifyQuorumInitGet(core, w, r)
		case "POST", "PUT":
			handleSysVerifyQuorumInitPut(core, w, r)
		case "DELETE":
			handleSysVerifyQuorumInitDelete(core, w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, nil)
		}
	})
}

func handleSysVerifyQuorumInitGet(core *vault.Core, w http.ResponseWriter, r *http.Request) {
	ctx, cancel := core.GetContext()
	defer cancel()

	// Get the current seal configuration
	barrierConfig, err := core.SealAccess().BarrierConfig(ctx)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	if barrierConfig == nil {
		respondError(w, http.StatusBadRequest, fmt.Errorf("server is not yet initialized"))
		return
	}

	sealConfig := barrierConfig
	if core.SealAccess().RecoveryKeySupported() {
		sealConfig, err = core.SealAccess().RecoveryConfig(ctx)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
	}

	// Get the verification configuration
	verifyQuorumConfig, err := core.VerifyQuorumConfiguration()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}

	// Get the progress
	progress, err := core.VerifyQuorumProgress()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}

	// Format the status
	status := &VerifyQuorumStatusResponse{
		Started:  false,
		Progress: progress,
		Required: sealConfig.SecretThreshold,
		Complete: false,
	}
	if verifyQuorumConfig != nil {
		status.Nonce = verifyQuorumConfig.Nonce
		status.Started = true
	}

	respondOk(w, status)
}

func handleSysVerifyQuorumInitPut(core *vault.Core, w http.ResponseWriter, r *http.Request) {
	// Parse the request
	var req VerifyQuorumInitRequest
	if _, err := parseJSONRequest(core.PerfStandby(), r, w, &req); err != nil && err != io.EOF {
		respondError(w, http.StatusBadRequest, err)
		return
	}

	// Initialize the verification
	if err := core.VerifyQuorumInit(); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}

	handleSysVerifyQuorumInitGet(core, w, r)
}

func handleSysVerifyQuorumInitDelete(core *vault.Core, w http.ResponseWriter, r *http.Request) {
	err := core.VerifyQuorumCancel()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondOk(w, nil)
}

func handleSysVerifyQuorumUpdate(core *vault.Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the request
		var req VerifyQuorumUpdateRequest
		if _, err := parseJSONRequest(core.PerfStandby(), r, w, &req); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		if req.Key == "" {
			respondError(
				w, http.StatusBadRequest,
				errors.New("'key' must be specified in request body as JSON"))
			return
		}

		// Decode the key, which is base64 or hex encoded
		min, max := core.BarrierKeyLength()
		key, err := hex.DecodeString(req.Key)
		// We check min and max here to ensure that a string that is base64
		// encoded but also valid hex will not be valid and we instead base64
		// decode it
		if err != nil || len(key) < min || len(key) > max {
			key, err = base64.StdEncoding.DecodeString(req.Key)
			if err != nil {
				respondError(
					w, http.StatusBadRequest,
					errors.New("'key' must be a valid hex or base64 string"))
				return
			}
		}

		ctx, cancel := core.GetContext()
		defer cancel()

		// Use the key to make progress on the verification
		result, err := core.VerifyQuorumUpdate(ctx, key, req.Nonce)
		if err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}

		resp := &VerifyQuorumStatusResponse{
			Complete: result.Progress == result.Required,
			Nonce:    req.Nonce,
			Progress: result.Progress,
			Required: result.Required,
			Started:  true,
		}

		respondOk(w, resp)
	})
}

type VerifyQuorumInitRequest struct{}

type VerifyQuorumStatusResponse struct {
	Nonce    string `json:"nonce"`
	Started  bool   `json:"started"`
	Progress int    `json:"progress"`
	Required int    `json:"required"`
	Complete bool   `json:"complete"`
}

type VerifyQuorumUpdateRequest struct {
	Nonce string
	Key   string
}
