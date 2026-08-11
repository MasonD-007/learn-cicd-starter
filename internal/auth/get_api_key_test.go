package auth_test

import (
	"errors"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAPIKey(t *testing.T) {

	tests := []struct {
		name    string
		headers map[string][]string
		want    string
		wantErr error
	}{
		{
			name: "returns API key when authorization header is valid",
			headers: map[string][]string{
				"Authorization": {"ApiKey my-api-key"},
			},
			want:    "my-api-key",
			wantErr: nil,
		},
		{
			name:    "returns error when authorization header is missing",
			headers: map[string][]string{},
			want:    "",
			wantErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name: "returns error when authorization header is malformed",
			headers: map[string][]string{
				"Authorization": {"Bearer my-api-key"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(map[string][]string)
			for k, v := range tt.headers {
				headers[k] = v
			}

			got, err := auth.GetAPIKey(headers)

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr.Error(), err.Error())
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
