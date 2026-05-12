// Copyright (c) 2026 Riptides Labs, Inc.
// SPDX-License-Identifier: MIT

package rfc7523

import (
	"context"

	"github.com/go-logr/logr"

	"go.riptides.io/tokenex/pkg/option"
	"go.riptides.io/tokenex/pkg/token"
)

const anthropicTokenEndpoint = "https://api.anthropic.com/v1/oauth/token"

// AnthropicWIFConfig holds the Anthropic-specific fields required for Workload Identity Federation.
// See https://platform.claude.com/docs/en/manage-claude/workload-identity-federation
type AnthropicWIFConfig struct {
	FederationRuleID string
	OrganizationID   string
	ServiceAccountID string
	WorkspaceID      string
}

// GetAnthropicCredentials is a convenience wrapper around GetCredentials for the Anthropic WIF endpoint.
// It sets BodyFormatJSON and injects the required Anthropic fields, accepting any additional options.
func GetAnthropicCredentials(
	ctx context.Context,
	logger logr.Logger,
	tokenProvider token.IdentityTokenProvider,
	wif AnthropicWIFConfig,
	opts ...option.Option,
) (<-chan Credential, error) {
	p, err := NewCredentialsProvider(ctx, logger)
	if err != nil {
		return nil, err
	}

	anthropicOpts := []option.Option{
		WithBodyFormat(BodyFormatJSON),
		WithAdditionalFields(map[string]string{
			"federation_rule_id": wif.FederationRuleID,
			"organization_id":    wif.OrganizationID,
			"service_account_id": wif.ServiceAccountID,
			"workspace_id":       wif.WorkspaceID,
		}),
	}

	return p.GetCredentials(ctx, anthropicTokenEndpoint, tokenProvider, append(anthropicOpts, opts...)...)
}
